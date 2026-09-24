// SPDX-License-Identifier: Apache-2.0

#![allow(
    clippy::doc_markdown,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

//! Pi's durable-session adapter.
//!
//! Pi stores durable sessions below an account-configured session root. The
//! normal source is an append-only JSONL session file; the adapter also admits
//! a narrowly recognized immutable session-object form. Discovery reads only
//! a bounded header, retains unknown files as unsupported sources, and never
//! writes to a source.
//!
//! JSONL capture composes the SDK file-core cursor and generation tracker: a
//! torn final record is measured but not captured, while replacement,
//! truncation, rewind, and rewrite open a new generation. Immutable files use
//! a digest probe with the same generation history, so every digest change is
//! a new generation even when the replacement happens to look append-only.
//!
//! Explicit ephemeral and no-session roots are reported as coverage gaps.
//! Environment construction honors PI_CODING_AGENT_SESSION_DIR,
//! PI_CODING_AGENT_DIR, and the HOME fallback.

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
use archivist_adapter_sdk::fingerprint::{
    FingerprintAllowlist, SourceFingerprint, UnsupportedFingerprint,
};
use archivist_adapter_sdk::lifecycle::{AdapterLifecycle, LifecycleState};
use archivist_adapter_sdk::status::{AccountLabel, ScanClassification};
use archivist_adapter_sdk::{AdapterId, VersionToken};

/// The adapter identity published in descriptors and discovery reports.
pub const ADAPTER_ID: &str = "pi";

/// The projection version stamped on captured Pi artifacts.
pub const PROJECTION_VERSION: &str = "1.0.0";

/// The default relative durable-session root beneath the Pi agent directory.
pub const DEFAULT_SESSION_ROOT: &str = ".pi/agent/sessions";

/// The maximum header prefix read while identifying a source.
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

/// The supported append-only Pi JSONL fingerprints.
pub const JSONL_FINGERPRINTS: [&str; 3] = ["pi-jsonl-v1", "pi-jsonl-v2", "pi-jsonl-v3"];

/// The supported immutable Pi session-object fingerprint.
pub const IMMUTABLE_FINGERPRINT: &str = "pi-immutable-v1";

const UNKNOWN_JSONL_FINGERPRINT: &str = "pi-jsonl-unknown";
const UNKNOWN_IMMUTABLE_FINGERPRINT: &str = "pi-immutable-unknown";
const UNKNOWN_FILE_FINGERPRINT: &str = "pi-unknown-format";

/// How a configured Pi root obtains durable sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionMode {
    /// Pi writes resumable session files below the configured root.
    Durable,
    /// Pi was explicitly run without persistence.
    Ephemeral,
    /// No session was configured for this run.
    NoSession,
}

impl SessionMode {
    /// Whether this mode provides a durable source to capture.
    #[must_use]
    pub const fn is_durable(self) -> bool {
        matches!(self, Self::Durable)
    }

    /// The classification used for a non-durable mode.
    #[must_use]
    pub const fn classification(self) -> ScanClassification {
        match self {
            Self::Durable => ScanClassification::Ok,
            Self::Ephemeral | Self::NoSession => ScanClassification::RootAbsent,
        }
    }
}

/// A configured Pi account and its durable-session root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredRoot {
    account: AccountLabel,
    path: PathBuf,
    mode: SessionMode,
}

impl ConfiguredRoot {
    /// Configure a durable account root.
    #[must_use]
    pub fn durable(account: AccountLabel, path: impl Into<PathBuf>) -> Self {
        Self {
            account,
            path: path.into(),
            mode: SessionMode::Durable,
        }
    }

    /// Configure a root whose Pi run is explicitly ephemeral.
    #[must_use]
    pub fn ephemeral(account: AccountLabel, path: impl Into<PathBuf>) -> Self {
        Self {
            account,
            path: path.into(),
            mode: SessionMode::Ephemeral,
        }
    }

    /// Configure a root for a Pi run with no session.
    #[must_use]
    pub fn no_session(account: AccountLabel, path: impl Into<PathBuf>) -> Self {
        Self {
            account,
            path: path.into(),
            mode: SessionMode::NoSession,
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

    /// The persistence mode for this root.
    #[must_use]
    pub const fn mode(&self) -> SessionMode {
        self.mode
    }
}

/// Alias for callers that name a configured root a Pi root.
pub type PiRoot = ConfiguredRoot;

/// Alias for callers that name persistence state a Pi mode.
pub type PiMode = SessionMode;

/// The source format recognized by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PiFormat {
    /// An append-only Pi session JSONL file and its header version.
    Jsonl {
        /// The Pi session header version.
        version: u8,
    },
    /// A complete immutable session object.
    Immutable {
        /// The immutable object format version.
        version: u8,
    },
    /// A file discovered under a configured root but not admitted.
    Unknown,
}

impl PiFormat {
    /// Whether the format is admitted by this adapter.
    #[must_use]
    pub const fn is_supported(self) -> bool {
        matches!(
            self,
            Self::Jsonl { version: 1..=3 } | Self::Immutable { version: 1 }
        )
    }

    /// The content-free fingerprint used in discovery and admission.
    #[must_use]
    pub fn fingerprint(self) -> SourceFingerprint {
        let token = match self {
            Self::Jsonl { version: 1 } => "pi-jsonl-v1",
            Self::Jsonl { version: 2 } => "pi-jsonl-v2",
            Self::Jsonl { version: 3 } => "pi-jsonl-v3",
            Self::Jsonl { .. } => UNKNOWN_JSONL_FINGERPRINT,
            Self::Immutable { version: 1 } => IMMUTABLE_FINGERPRINT,
            Self::Immutable { .. } => UNKNOWN_IMMUTABLE_FINGERPRINT,
            Self::Unknown => UNKNOWN_FILE_FINGERPRINT,
        };
        SourceFingerprint::parse(token).expect("Pi fingerprints are constants")
    }

    /// Whether this format uses append-only complete-record capture.
    #[must_use]
    pub const fn is_jsonl(self) -> bool {
        matches!(self, Self::Jsonl { .. })
    }

    /// Whether this format is one complete immutable object per file.
    #[must_use]
    pub const fn is_immutable(self) -> bool {
        matches!(self, Self::Immutable { .. })
    }
}

/// One file discovered below a configured durable root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiSource {
    account: AccountLabel,
    path: PathBuf,
    format: PiFormat,
    fingerprint: SourceFingerprint,
}

impl PiSource {
    fn new(account: &AccountLabel, path: PathBuf, format: PiFormat) -> Self {
        Self {
            account: account.clone(),
            path,
            format,
            fingerprint: format.fingerprint(),
        }
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

    /// The detected source format.
    #[must_use]
    pub const fn format(&self) -> PiFormat {
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
        self.format.is_supported()
    }
}

/// A detected coverage gap for a configured Pi root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageGap {
    /// The configured run was ephemeral and left no durable file.
    Ephemeral,
    /// The configured run had no session persistence.
    NoSession,
    /// The configured durable root did not exist or contained no sessions.
    RootAbsent,
}

impl CoverageGap {
    /// The source classification represented by this gap.
    #[must_use]
    pub const fn classification(self) -> ScanClassification {
        ScanClassification::RootAbsent
    }

    /// A stable content-free token for diagnostics and tests.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Ephemeral => "ephemeral",
            Self::NoSession => "no-session",
            Self::RootAbsent => "root-absent",
        }
    }
}

/// The result of one Pi inventory pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiInventory {
    /// The bounded SDK discovery report.
    pub report: DiscoveryReport,
    /// Every file found, including unsupported formats.
    pub sources: Vec<PiSource>,
    /// Non-durable or absent-root coverage gaps seen during the pass.
    pub gaps: Vec<CoverageGap>,
}

impl PiInventory {
    /// The supported sources in discovery order.
    pub fn supported(&self) -> impl Iterator<Item = &PiSource> {
        self.sources.iter().filter(|source| source.is_supported())
    }

    /// The unsupported sources in discovery order.
    pub fn unsupported(&self) -> impl Iterator<Item = &PiSource> {
        self.sources.iter().filter(|source| !source.is_supported())
    }

    /// Whether the pass observed at least one explicit coverage gap.
    #[must_use]
    pub fn has_coverage_gap(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// Convert distinct observed fingerprints into the SDK routing list.
    pub fn discovered_sources(&self) -> Result<DiscoveredSources, DiscoveryError> {
        let mut seen = BTreeSet::new();
        let entries = self
            .sources
            .iter()
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
pub enum PiConfigError {
    /// The adapter must have at least one configured account root.
    EmptyRoots,
    /// More than one root used the same account label.
    DuplicateAccount,
}

impl fmt::Display for PiConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyRoots => "pi_empty_roots",
            Self::DuplicateAccount => "pi_duplicate_account",
        })
    }
}

impl std::error::Error for PiConfigError {}

/// Errors returned while reading or admitting a Pi source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PiCaptureError {
    /// The source fingerprint is not on the adapter's allowlist.
    Unsupported(UnsupportedFingerprint),
    /// The source disappeared or its root was absent.
    RootAbsent,
    /// The source exists but could not be read.
    PermissionDenied,
    /// The source could not be read for another filesystem reason.
    ReadError,
    /// The file became a different, unsupported format between passes.
    FormatChanged(UnsupportedFingerprint),
    /// The file-core cursor observed an impossible shrink.
    CursorSourceShrank,
}

impl PiCaptureError {
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

impl fmt::Display for PiCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported(_) => "pi_unsupported_fingerprint",
            Self::RootAbsent => "pi_root_absent",
            Self::PermissionDenied => "pi_permission_denied",
            Self::ReadError => "pi_read_error",
            Self::FormatChanged(_) => "pi_format_changed",
            Self::CursorSourceShrank => "pi_capture_source_shrank",
        })
    }
}

impl std::error::Error for PiCaptureError {}

/// The kind of captured Pi artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PiArtifactKind {
    /// A complete-record slice from an append-only session JSONL file.
    Jsonl,
    /// One complete immutable session object.
    Immutable,
}

/// A digest of canonical uncompressed captured bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PiDigest([u8; 32]);

impl PiDigest {
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

impl fmt::Display for PiDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&hex(self.0))
    }
}

/// One capture emitted by Pi.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PiCapturedChunk {
    /// Whether this chunk is a JSONL slice or an immutable object.
    pub artifact: PiArtifactKind,
    /// The generation that owns the bytes.
    pub generation: SourceGeneration,
    /// Complete canonical bytes. JSONL chunks include terminating newlines.
    pub bytes: Vec<u8>,
    /// SHA-256 over bytes.
    pub digest: PiDigest,
    /// Inclusive byte range within this generation's source stream.
    pub range_start: u64,
    /// Inclusive byte range within this generation's source stream.
    pub range_end: u64,
    /// Zero-based chunk order within the generation.
    pub sequence: u64,
    /// The admitted source fingerprint.
    pub fingerprint: SourceFingerprint,
}

impl PiCapturedChunk {
    /// Whether this chunk is an immutable whole-file object.
    #[must_use]
    pub const fn is_immutable(&self) -> bool {
        matches!(self.artifact, PiArtifactKind::Immutable)
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

/// The filesystem-backed Pi source adapter.
#[derive(Clone, Debug)]
pub struct PiAdapter {
    descriptor: AdapterDescriptor,
    roots: Vec<ConfiguredRoot>,
    state: LifecycleState,
}

impl PiAdapter {
    /// Build an adapter from one or more account roots.
    pub fn new<I>(roots: I) -> Result<Self, PiConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        let roots: Vec<_> = roots.into_iter().collect();
        if roots.is_empty() {
            return Err(PiConfigError::EmptyRoots);
        }
        let mut accounts = BTreeSet::new();
        if roots
            .iter()
            .any(|root| !accounts.insert(root.account().clone()))
        {
            return Err(PiConfigError::DuplicateAccount);
        }
        Ok(Self {
            descriptor: descriptor(),
            roots,
            state: LifecycleState::Constructed,
        })
    }

    /// Compatibility constructor named after mounting an adapter.
    pub fn mount<I>(roots: I) -> Result<Self, PiConfigError>
    where
        I: IntoIterator<Item = ConfiguredRoot>,
    {
        Self::new(roots)
    }

    /// Construct an adapter from Pi's environment-selected durable root.
    pub fn from_environment(account: AccountLabel) -> Result<Self, PiConfigError> {
        let mode = if env_truthy("PI_NO_SESSION") {
            SessionMode::Ephemeral
        } else {
            SessionMode::Durable
        };
        Self::new([ConfiguredRoot {
            account,
            path: configured_session_root(),
            mode,
        }])
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
    pub fn inventory(&self, account: &AccountLabel) -> PiInventory {
        let roots: Vec<_> = self
            .roots
            .iter()
            .filter(|root| root.account() == account)
            .collect();
        if roots.is_empty() {
            return empty_inventory(&self.descriptor, account, ScanClassification::NotObserved);
        }

        let mut sources = Vec::new();
        let mut gaps = Vec::new();
        let mut saw_read_error = false;
        for root in roots {
            if !root.mode().is_durable() {
                gaps.push(match root.mode() {
                    SessionMode::Ephemeral => CoverageGap::Ephemeral,
                    SessionMode::NoSession => CoverageGap::NoSession,
                    SessionMode::Durable => CoverageGap::RootAbsent,
                });
                continue;
            }
            match inventory_root(root, &mut sources) {
                RootInventoryResult::Ok { files_seen: 0 } => {
                    gaps.push(CoverageGap::RootAbsent);
                }
                RootInventoryResult::RootAbsent => gaps.push(CoverageGap::RootAbsent),
                RootInventoryResult::ReadError => saw_read_error = true,
                RootInventoryResult::Ok { .. } => {}
            }
        }
        let supported = sources
            .iter()
            .filter(|source| source.is_supported())
            .count();
        let unsupported = sources.len().saturating_sub(supported);
        let classification = if saw_read_error {
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
            u64::try_from(sources.len()).unwrap_or(u64::MAX),
            u64::try_from(supported).unwrap_or(u64::MAX),
            u64::try_from(unsupported).unwrap_or(u64::MAX),
        )
        .expect("inventory counts are derived from one source list");
        PiInventory {
            report,
            sources,
            gaps,
        }
    }

    /// Open one source after exact fingerprint admission.
    pub fn open(&self, source: &PiSource) -> Result<PiCapture, PiCaptureError> {
        self.descriptor
            .fingerprints
            .admit(source.fingerprint())
            .map_err(PiCaptureError::Unsupported)?;
        match source.format() {
            PiFormat::Jsonl { .. } => Ok(PiCapture::Jsonl(JsonlCapture::new(source.clone()))),
            PiFormat::Immutable { .. } => {
                Ok(PiCapture::Immutable(ImmutableCapture::new(source.clone())))
            }
            PiFormat::Unknown => Err(PiCaptureError::Unsupported(UnsupportedFingerprint {
                fingerprint: source.fingerprint().clone(),
            })),
        }
    }

    /// Alias for open used by callers that call a capture a stream.
    pub fn capture(&self, source: &PiSource) -> Result<PiCapture, PiCaptureError> {
        self.open(source)
    }
}

impl AdapterLifecycle for PiAdapter {
    fn state(&self) -> LifecycleState {
        self.state
    }

    fn close(&mut self) {
        self.state = LifecycleState::Closed;
    }
}

impl SourceDiscovery for PiAdapter {
    fn discover(&self, account: &AccountLabel) -> DiscoveryReport {
        self.inventory(account).report
    }
}

/// A live capture stream for a supported Pi source.
#[derive(Clone, Debug)]
pub enum PiCapture {
    /// Append-only JSONL complete-record capture.
    Jsonl(JsonlCapture),
    /// Digest-sensitive immutable whole-file capture.
    Immutable(ImmutableCapture),
}

impl PiCapture {
    /// Pull one capture unit. None means no newly complete bytes exist.
    pub fn next_chunk(&mut self) -> Result<Option<PiCapturedChunk>, PiCaptureError> {
        match self {
            Self::Jsonl(capture) => capture.next_chunk(),
            Self::Immutable(capture) => capture.next_chunk(),
        }
    }

    /// Alias for next_chunk.
    pub fn capture_pass(&mut self) -> Result<Option<PiCapturedChunk>, PiCaptureError> {
        self.next_chunk()
    }

    /// The currently open generation.
    #[must_use]
    pub fn generation(&self) -> &SourceGeneration {
        match self {
            Self::Jsonl(capture) => capture.generation(),
            Self::Immutable(capture) => capture.generation(),
        }
    }

    /// Generations closed by replacement, truncation, or digest change.
    #[must_use]
    pub fn history(&self) -> &[SourceGeneration] {
        match self {
            Self::Jsonl(capture) => capture.history(),
            Self::Immutable(capture) => capture.history(),
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &PiSource {
        match self {
            Self::Jsonl(capture) => capture.source(),
            Self::Immutable(capture) => capture.source(),
        }
    }
}

/// JSONL capture state using the SDK file-core cursor.
#[derive(Clone, Debug)]
pub struct JsonlCapture {
    source: PiSource,
    tracker: Option<FileGenerationTracker>,
    cursor: CaptureCursor,
    sequence: u64,
}

impl JsonlCapture {
    /// Start an unopened JSONL stream.
    #[must_use]
    pub fn new(source: PiSource) -> Self {
        Self {
            source,
            tracker: None,
            cursor: CaptureCursor::new(),
            sequence: 0,
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &PiSource {
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
    pub fn next_chunk(&mut self) -> Result<Option<PiCapturedChunk>, PiCaptureError> {
        let identity = file_identity(&self.source.path)?;
        let prefix = read_prefix(&self.source.path)?;
        let detected = detect_format(&self.source.path, &prefix);
        if detected != self.source.format {
            return Err(PiCaptureError::FormatChanged(UnsupportedFingerprint {
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
            CaptureCursorError::SourceShrank => PiCaptureError::CursorSourceShrank,
        })?;
        if outcome.captured.is_empty() {
            return Ok(None);
        }
        let captured = outcome.captured.to_vec();
        let end = start
            .checked_add(u64::try_from(captured.len()).unwrap_or(u64::MAX))
            .and_then(|value| value.checked_sub(1))
            .unwrap_or(u64::MAX);
        let chunk = PiCapturedChunk {
            artifact: PiArtifactKind::Jsonl,
            generation: self.generation().clone(),
            digest: PiDigest::from_raw(sha256(&captured)),
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

/// Immutable capture state. The generation tracker observes a fixed-size
/// digest probe with the real filesystem identity, so every digest change is
/// a generation boundary.
#[derive(Clone, Debug)]
pub struct ImmutableCapture {
    source: PiSource,
    tracker: Option<FileGenerationTracker>,
    last_digest: Option<PiDigest>,
    sequence: u64,
}

impl ImmutableCapture {
    /// Start an unopened immutable stream.
    #[must_use]
    pub fn new(source: PiSource) -> Self {
        Self {
            source,
            tracker: None,
            last_digest: None,
            sequence: 0,
        }
    }

    /// The source this stream reads.
    #[must_use]
    pub fn source(&self) -> &PiSource {
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

    /// Pull the whole immutable object once per digest-sensitive generation.
    pub fn next_chunk(&mut self) -> Result<Option<PiCapturedChunk>, PiCaptureError> {
        let identity = file_identity(&self.source.path)?;
        let prefix = read_prefix(&self.source.path)?;
        let detected = detect_format(&self.source.path, &prefix);
        if detected != self.source.format {
            return Err(PiCaptureError::FormatChanged(UnsupportedFingerprint {
                fingerprint: detected.fingerprint(),
            }));
        }
        let bytes = read_all(&self.source.path)?;
        let digest = PiDigest::from_raw(sha256(&bytes));
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
        if !rotated && !changed {
            return Ok(None);
        }
        if bytes.is_empty() {
            return Ok(None);
        }
        let end = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_sub(1);
        let chunk = PiCapturedChunk {
            artifact: PiArtifactKind::Immutable,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootInventoryResult {
    Ok { files_seen: usize },
    RootAbsent,
    ReadError,
}

fn descriptor() -> AdapterDescriptor {
    let capabilities = CapabilitySet::parse([
        AdapterCapability::FileSliceCapture.token(),
        AdapterCapability::CompleteRecordBoundaries.token(),
        AdapterCapability::GenerationDetection.token(),
        AdapterCapability::CoverageGapReporting.token(),
    ])
    .expect("Pi capabilities are constants");
    let fingerprints = FingerprintAllowlist::parse(
        JSONL_FINGERPRINTS
            .into_iter()
            .chain([IMMUTABLE_FINGERPRINT]),
    )
    .expect("Pi fingerprints are constants");
    AdapterDescriptor::publish(
        AdapterId::parse(ADAPTER_ID).expect("Pi adapter id is canonical"),
        VersionToken::parse(PROJECTION_VERSION).expect("Pi projection is canonical"),
        capabilities,
        fingerprints,
    )
    .expect("Pi declares capture capabilities")
}

fn empty_inventory(
    descriptor: &AdapterDescriptor,
    account: &AccountLabel,
    classification: ScanClassification,
) -> PiInventory {
    PiInventory {
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
        gaps: Vec::new(),
    }
}

fn inventory_root(root: &ConfiguredRoot, output: &mut Vec<PiSource>) -> RootInventoryResult {
    let metadata = match fs::metadata(root.path()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RootInventoryResult::RootAbsent;
        }
        Err(_) => return RootInventoryResult::ReadError,
    };
    let mut files_seen = 0;
    if metadata.is_file() {
        output.push(inspect_source(root.account(), root.path().to_path_buf()));
        files_seen = 1;
        return RootInventoryResult::Ok { files_seen };
    }
    let mut stack = vec![match fs::read_dir(root.path()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return RootInventoryResult::RootAbsent;
        }
        Err(_) => return RootInventoryResult::ReadError,
    }];
    while let Some(entries) = stack.pop() {
        for entry in entries {
            let Ok(entry) = entry else {
                return RootInventoryResult::ReadError;
            };
            let path = entry.path();
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return RootInventoryResult::ReadError,
            };
            if metadata.is_dir() {
                match fs::read_dir(path) {
                    Ok(nested) => stack.push(nested),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(_) => return RootInventoryResult::ReadError,
                }
            } else if metadata.is_file() {
                output.push(inspect_source(root.account(), path));
                files_seen += 1;
            }
        }
    }
    output.sort_by(|left, right| left.path().cmp(right.path()));
    RootInventoryResult::Ok { files_seen }
}

fn inspect_source(account: &AccountLabel, path: PathBuf) -> PiSource {
    let Ok(prefix) = read_prefix(&path) else {
        return PiSource::new(account, path, PiFormat::Unknown);
    };
    PiSource::new(account, path.clone(), detect_format(&path, &prefix))
}

fn detect_format(path: &Path, prefix: &[u8]) -> PiFormat {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("jsonl") => detect_jsonl(prefix),
        Some(extension) if extension.eq_ignore_ascii_case("json") => detect_immutable(prefix),
        _ => PiFormat::Unknown,
    }
}

fn detect_jsonl(prefix: &[u8]) -> PiFormat {
    let line = prefix
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    if !looks_like_json_object(line)
        || json_string_member(line, "type").as_deref() != Some("session")
    {
        return PiFormat::Jsonl { version: 0 };
    }
    let version = json_number_member(line, "version").unwrap_or(1);
    PiFormat::Jsonl {
        version: u8::try_from(version).unwrap_or(0),
    }
}

fn detect_immutable(prefix: &[u8]) -> PiFormat {
    let trimmed = trim_ascii_space(prefix);
    if trimmed.first() != Some(&b'{')
        || json_string_member(trimmed, "type").as_deref() != Some("session")
    {
        return PiFormat::Immutable { version: 0 };
    }
    PiFormat::Immutable { version: 1 }
}

fn looks_like_json_object(bytes: &[u8]) -> bool {
    let bytes = trim_ascii_space(bytes);
    bytes.first() == Some(&b'{') && bytes.last() == Some(&b'}')
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
    let needle = format!("\"{key}\"");
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())?;
    let rest = &bytes[start + needle.len()..];
    let colon = rest.iter().position(|byte| *byte == b':')?;
    let value = trim_ascii_space(&rest[colon + 1..]);
    if value.first() != Some(&b'"') {
        return None;
    }
    let end = value[1..].iter().position(|byte| *byte == b'"')? + 1;
    std::str::from_utf8(&value[1..end]).ok().map(str::to_owned)
}

fn json_number_member(bytes: &[u8], key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let start = bytes
        .windows(needle.len())
        .position(|window| window == needle.as_bytes())?;
    let rest = &bytes[start + needle.len()..];
    let colon = rest.iter().position(|byte| *byte == b':')?;
    let value = trim_ascii_space(&rest[colon + 1..]);
    if value.first() == Some(&b'"') {
        let end = value[1..].iter().position(|byte| *byte == b'"')? + 1;
        return std::str::from_utf8(&value[1..end]).ok()?.parse().ok();
    }
    let end = value
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(value.len());
    std::str::from_utf8(&value[..end]).ok()?.parse().ok()
}

fn configured_session_root() -> PathBuf {
    if let Some(path) = env::var_os("PI_CODING_AGENT_SESSION_DIR") {
        return PathBuf::from(path);
    }
    if let Some(agent_dir) = env::var_os("PI_CODING_AGENT_DIR") {
        return PathBuf::from(agent_dir).join("sessions");
    }
    if let Some(home) = env::var_os("HOME") {
        return PathBuf::from(home).join(DEFAULT_SESSION_ROOT);
    }
    PathBuf::from(DEFAULT_SESSION_ROOT)
}

fn env_truthy(name: &str) -> bool {
    env::var(name).is_ok_and(|value| {
        matches!(
            value.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn file_identity(path: &Path) -> Result<FileIdentity, PiCaptureError> {
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

fn read_prefix(path: &Path) -> Result<Vec<u8>, PiCaptureError> {
    let file = File::open(path).map_err(|error| map_io_error(&error))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(MAX_HEADER_BYTES).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| map_io_error(&error))?;
    Ok(bytes)
}

fn read_all(path: &Path) -> Result<Vec<u8>, PiCaptureError> {
    fs::read(path).map_err(|error| map_io_error(&error))
}

fn map_io_error(error: &io::Error) -> PiCaptureError {
    match error.kind() {
        io::ErrorKind::NotFound => PiCaptureError::RootAbsent,
        io::ErrorKind::PermissionDenied => PiCaptureError::PermissionDenied,
        _ => PiCaptureError::ReadError,
    }
}

fn digest_probe(digest: PiDigest) -> Vec<u8> {
    let mut probe = Vec::with_capacity(33);
    probe.extend_from_slice(&digest.0);
    probe.push(b'\n');
    probe
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
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .saturating_mul(8);
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn account() -> AccountLabel {
        AccountLabel::parse("test-account").expect("valid account")
    }

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        env::temp_dir().join(format!("archivist-pi-{label}-{nanos}"))
    }

    fn write(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture root");
        }
        fs::write(path, bytes).expect("write fixture");
    }

    fn adapter(root: &Path) -> PiAdapter {
        PiAdapter::new([ConfiguredRoot::durable(account(), root)]).expect("adapter")
    }

    #[test]
    fn descriptor_publishes_supported_formats_and_gap_capability() {
        let descriptor = descriptor();
        assert_eq!(descriptor.adapter.as_str(), ADAPTER_ID);
        assert!(
            descriptor
                .fingerprints
                .contains(&PiFormat::Jsonl { version: 1 }.fingerprint())
        );
        assert!(
            descriptor
                .fingerprints
                .contains(&PiFormat::Jsonl { version: 3 }.fingerprint())
        );
        assert!(
            descriptor
                .fingerprints
                .contains(&PiFormat::Immutable { version: 1 }.fingerprint())
        );
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::CoverageGapReporting)
        );
    }

    #[test]
    fn discovery_finds_nested_sessions_and_keeps_unknown_files_visible() {
        let root = temp_root("discovery");
        write(
            &root.join("--project--/session.jsonl"),
            br#"{"type":"session","version":3}
{"type":"message"}
"#,
        );
        write(
            &root.join("--project--/mystery.jsonl"),
            br#"{"type":"future"}
"#,
        );
        write(
            &root.join("settings.json"),
            br#"{"settings":true}
"#,
        );
        let inventory = adapter(&root).inventory(&account());
        assert_eq!(inventory.report.sources, 3);
        assert_eq!(inventory.report.supported, 1);
        assert_eq!(inventory.report.unsupported, 2);
        assert_eq!(inventory.report.classification, ScanClassification::Ok);
        assert_eq!(inventory.supported().count(), 1);
        assert_eq!(inventory.unsupported().count(), 2);
        assert_eq!(
            inventory.discovered_sources().expect("routing list").len(),
            3
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn missing_root_and_non_durable_modes_are_coverage_gaps() {
        let missing = temp_root("missing");
        let inventory = adapter(&missing).inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::RootAbsent
        );
        assert!(inventory.has_coverage_gap());

        let ephemeral_root = temp_root("ephemeral");
        let adapter = PiAdapter::new([ConfiguredRoot::ephemeral(account(), ephemeral_root)])
            .expect("adapter");
        let inventory = adapter.inventory(&account());
        assert_eq!(
            inventory.report.classification,
            ScanClassification::RootAbsent
        );
        assert_eq!(inventory.gaps, [CoverageGap::Ephemeral]);
    }

    #[test]
    fn jsonl_growth_captures_only_complete_records_and_preserves_generation() {
        let root = temp_root("growth");
        let path = root.join("session.jsonl");
        write(
            &path,
            br#"{"type":"session","version":3}
{"type":"message""#,
        );
        let configured = adapter(&root);
        let source = configured
            .inventory(&account())
            .supported()
            .next()
            .cloned()
            .expect("source");
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("header");
        assert_eq!(
            first.bytes,
            br#"{"type":"session","version":3}
"#
        );
        let generation = first.generation.clone();
        assert_eq!(capture.next_chunk().expect("unchanged pass"), None);
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open append")
            .write_all(b"}\n{\"type\":\"message\"}\n")
            .expect("append completion");
        let second = capture.next_chunk().expect("growth pass").expect("growth");
        assert_eq!(
            second.bytes,
            b"{\"type\":\"message\"}\n{\"type\":\"message\"}\n"
        );
        assert_eq!(second.generation, generation);
        assert_eq!(second.range_start, first.bytes.len() as u64);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn immutable_files_are_idempotent_but_digest_rewrites_open_generations() {
        let root = temp_root("immutable");
        let path = root.join("session.json");
        write(&path, br#"{"type":"session","version":1,"id":"one"}"#);
        let configured = adapter(&root);
        let source = configured
            .inventory(&account())
            .supported()
            .next()
            .cloned()
            .expect("source");
        let mut capture = configured.open(&source).expect("open");
        let first = capture.next_chunk().expect("first pass").expect("object");
        assert!(first.is_immutable());
        assert_eq!(capture.next_chunk().expect("idempotent pass"), None);
        let generation = first.generation.generation.clone();
        write(&path, br#"{"type":"session","version":1,"id":"two"}"#);
        let second = capture.next_chunk().expect("rewrite pass").expect("object");
        assert_ne!(second.generation.generation, generation);
        assert_eq!(capture.history().len(), 1);
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn unknown_fingerprints_are_rejected_before_body_capture() {
        let root = temp_root("unknown");
        let path = root.join("future.jsonl");
        write(
            &path,
            br#"{"type":"session","version":99}
{"secret":"must-not-be-captured"}
"#,
        );
        let configured = adapter(&root);
        let source = configured
            .inventory(&account())
            .unsupported()
            .next()
            .cloned()
            .expect("source");
        let error = configured
            .open(&source)
            .expect_err("unknown source rejected");
        assert_eq!(
            error.classification(),
            ScanClassification::FingerprintUnsupported
        );
        assert_eq!(
            fs::read(&path).expect("source unchanged"),
            br#"{"type":"session","version":99}
{"secret":"must-not-be-captured"}
"#
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn sha256_matches_the_standard_empty_vector() {
        assert_eq!(
            PiDigest::from_raw(sha256(b"")).to_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
