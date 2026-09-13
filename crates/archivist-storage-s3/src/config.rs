// SPDX-License-Identifier: Apache-2.0

//! The portable S3 configuration surface: endpoint, region, path style,
//! transport security, at-rest encryption policy, buckets, and per-identity
//! credential references, validated fail-closed before any store is built.
//!
//! Every setting here is a registered configuration key owned by this crate
//! (`tools/config-keys.toml`, "Storage backend" section); the registry is
//! the deployment surface, and this module is the typed shape an assembled
//! configuration must validate into. A required registry key that never
//! arrived, a value outside its closed grammar, and a cross-field
//! contradiction are all *construction* failures of [`S3StorageConfig`]:
//! there is no half-valid configuration, and no default silently
//! substitutes for a required one.
//!
//! # Storage identities (plan Section 5)
//!
//! The configuration maps four storage roles to four *distinct* credential
//! identities, even when every role addresses the same endpoint and bucket:
//!
//! - the **raw writer** (required) — create, multipart-write, and abort on
//!   the tenant raw prefix, and nothing else;
//! - the **control reader** (required) — read-only access to the signed
//!   control-record families;
//! - the **raw reader** (optional) — the STO-007 preflight optimization,
//!   "never required by the portable ingest path";
//! - the **offline restore** identity (optional on this surface) — the
//!   offline credential backup and restore use.
//!
//! Validation rejects any configuration where two roles share one
//! credential reference: the authority split is the point of the mapping,
//! so collapsing two roles onto one credential is the exact failure the
//! split exists to prevent. Ingest replicas are configured with the two
//! required roles; the optional roles exist for deployments that
//! deliberately grant them ([`StorageRole::RawReader`] preflight, offline
//! restore tooling).
//!
//! # Transport security
//!
//! The endpoint scheme and the [`Tls`] setting must agree: an `https://`
//! endpoint requires [`Tls::Enabled`], and a plaintext `http://` endpoint
//! is accepted only with an explicit [`Tls::Disabled`] — plaintext is
//! never reached by omission (SEC-001). Deployment configuration assembled
//! from the registry has no key that disables TLS, so a registry-loaded
//! configuration is TLS-only by construction; [`Tls::Disabled`] exists for
//! the local reference backend the compatibility suite exercises.
//!
//! # Secrets by reference
//!
//! Credentials enter as [`CredentialReference`] values (`file:`/`env:`,
//! CFG-029), never as values. The type renders the kind alone in `Debug`
//! and `Display`: a reference pointer is operator configuration, not
//! output (CFG-027, CFG-030), and the resolved secret never crosses this
//! crate.

use std::fmt;

use archivist_protocol::vocabulary::GrammarError;

/// Why a configuration failed validation: a closed class of failure
/// carrying the decision the operator must make next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum S3ConfigErrorKind {
    /// A required setting never arrived in any tier.
    MissingSetting,
    /// A setting arrived but is outside its closed grammar or bounds.
    MalformedSetting,
    /// The endpoint scheme and the TLS setting disagree.
    TransportMismatch,
    /// Two storage roles were mapped to the same credential reference.
    DuplicateIdentity,
}

impl S3ConfigErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::MissingSetting,
            Self::MalformedSetting,
            Self::TransportMismatch,
            Self::DuplicateIdentity,
        ]
    }

    /// The content-free default detail shipped with this kind. Callers
    /// that have nothing more specific to say use these verbatim; the
    /// literals are pinned by a unit test to stay inside the project's
    /// safe-message grammar.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::MissingSetting => "required setting is absent from every tier",
            Self::MalformedSetting => "setting is outside its closed grammar",
            Self::TransportMismatch => "endpoint scheme and tls setting disagree",
            Self::DuplicateIdentity => "two storage roles share one credential reference",
        }
    }
}

impl fmt::Display for S3ConfigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::MissingSetting => "missing-setting",
            Self::MalformedSetting => "malformed-setting",
            Self::TransportMismatch => "transport-mismatch",
            Self::DuplicateIdentity => "duplicate-identity",
        };
        f.write_str(text)
    }
}

/// Which setting an error is about. The per-setting detail literals live
/// here so every operator-facing sentence is a static, pinned string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Setting {
    EndpointUrl,
    Region,
    Encryption,
    RawBucket,
    ControlBucket,
    Credentials,
}

impl Setting {
    /// Every setting, in declaration order (test evidence for the pinned
    /// detail literals).
    #[cfg(test)]
    fn all() -> &'static [Self] {
        &[
            Self::EndpointUrl,
            Self::Region,
            Self::Encryption,
            Self::RawBucket,
            Self::ControlBucket,
            Self::Credentials,
        ]
    }

    /// The detail for a required-but-absent setting.
    const fn missing_detail(self) -> &'static str {
        match self {
            Self::EndpointUrl => "endpoint url is required",
            Self::Region => "region is required",
            Self::Encryption => "encryption policy is required",
            Self::RawBucket => "raw bucket is required",
            Self::ControlBucket => "control bucket is required",
            Self::Credentials => "raw-write and control-read credentials are required",
        }
    }

    /// The detail for a present-but-malformed setting.
    const fn malformed_detail(self) -> &'static str {
        match self {
            Self::EndpointUrl => "endpoint url is outside the closed grammar",
            Self::Region => "region is outside the bounded string grammar",
            Self::Encryption => "encryption policy token is not canonical",
            Self::RawBucket => "raw bucket is outside the bounded string grammar",
            Self::ControlBucket => "control bucket is outside the bounded string grammar",
            Self::Credentials => "credential reference is outside the closed grammar",
        }
    }
}

/// Why a configuration failed validation: a closed class plus one
/// content-safe detail naming the setting class, never the offending
/// value.
///
/// The detail is a static literal by construction — the type cannot carry
/// runtime text such as endpoints, bucket names, or reference targets —
/// so a configuration error can never echo a credential pointer or a
/// secret (CFG-013, CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct S3ConfigError {
    kind: S3ConfigErrorKind,
    detail: &'static str,
}

impl S3ConfigError {
    /// Build an error from a kind and a static, content-safe detail.
    #[must_use]
    pub const fn new(kind: S3ConfigErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: S3ConfigErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> S3ConfigErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for S3ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s3 config {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for S3ConfigError {}

/// The kind of a [`CredentialReference`] target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CredentialKind {
    /// The credential lives in a mode-restricted file on this host.
    File,
    /// The credential lives in an environment variable on this host.
    Env,
}

impl fmt::Display for CredentialKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::File => "file",
            Self::Env => "env",
        })
    }
}

/// A parsed, validated credential reference: `file:` with an absolute
/// path or `env:` with an environment-variable name (CFG-029).
///
/// The type holds only the *reference* — the pointer — never the
/// credential value it names. Its [`Debug`](std::fmt::Debug) and
/// [`Display`](std::fmt::Display) implementations render the kind alone:
/// a reference string is operator configuration, and no diagnostic echoes
/// it (CFG-027).
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum CredentialReference {
    /// `file:` — a mode-restricted regular file on this host (CFG-030)
    /// holding the credential value.
    File {
        /// The absolute target path. Never rendered by this type.
        path: Box<std::path::Path>,
    },
    /// `env:` — an environment variable on this host holding the
    /// credential value.
    Env {
        /// The variable name, matching the pinned grammar.
        name: Box<str>,
    },
}

impl CredentialReference {
    /// Parse a reference string, failing closed on anything outside the
    /// pinned grammar (CFG-029):
    ///
    /// - `file:` plus an absolute path of at least one segment whose
    ///   characters are only `[A-Za-z0-9._+-]`, with no `.` or `..`
    ///   segment and no tilde;
    /// - `env:` plus a name matching `[A-Z][A-Z0-9_]{0,63}` that does not
    ///   start with the reserved `ARCHIVIST_` configuration prefix.
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MalformedSetting`] for anything else. The
    /// malformed input is not echoed.
    pub fn parse(text: &str) -> Result<Self, S3ConfigError> {
        if let Some(target) = text.strip_prefix("file:") {
            return Self::parse_file(target);
        }
        if let Some(target) = text.strip_prefix("env:") {
            return Self::parse_env(target);
        }
        Err(malformed_credentials())
    }

    fn parse_file(target: &str) -> Result<Self, S3ConfigError> {
        if target.len() <= 1 || target.len() > REF_TARGET_MAX || !target.starts_with('/') {
            return Err(malformed_credentials());
        }
        // The leading `/` yields the one permitted empty segment; every
        // other empty segment (`//`, a trailing `/`) is refused, not
        // normalized away.
        let mut parts = target.split('/');
        if !parts.next().is_some_and(str::is_empty) {
            return Err(malformed_credentials());
        }
        for segment in parts {
            if segment.is_empty() || segment == "." || segment == ".." {
                return Err(malformed_credentials());
            }
            if !segment
                .bytes()
                .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-'))
            {
                return Err(malformed_credentials());
            }
        }
        Ok(Self::File {
            path: std::path::PathBuf::from(target).into_boxed_path(),
        })
    }

    fn parse_env(target: &str) -> Result<Self, S3ConfigError> {
        let mut bytes = target.bytes();
        let well_formed = match bytes.next() {
            Some(first) if first.is_ascii_uppercase() => {
                bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            }
            _ => false,
        };
        if !well_formed || target.len() > ENV_NAME_MAX || target.starts_with(RESERVED_ENV_PREFIX) {
            return Err(malformed_credentials());
        }
        Ok(Self::Env {
            name: Box::from(target),
        })
    }

    /// The kind of target this reference names.
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        match self {
            Self::File { .. } => CredentialKind::File,
            Self::Env { .. } => CredentialKind::Env,
        }
    }
}

impl fmt::Debug for CredentialReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialReference({})", self.kind())
    }
}

impl fmt::Display for CredentialReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The kind alone: the target is operator configuration, and no
        // diagnostic echoes a reference string (CFG-027).
        write!(f, "credential-reference({})", self.kind())
    }
}

/// The detail for every credential-reference grammar failure: one static
/// sentence, no echo of the offending text.
fn malformed_credentials() -> S3ConfigError {
    S3ConfigError::new(
        S3ConfigErrorKind::MalformedSetting,
        Setting::Credentials.malformed_detail(),
    )
}

/// The reserved configuration-tier prefix an `env:` credential target
/// must not use (CFG-029): a secret's channel can never be confused with
/// a configuration key.
const RESERVED_ENV_PREFIX: &str = "ARCHIVIST_";

/// Longest accepted `env:` variable name (CFG-029).
const ENV_NAME_MAX: usize = 64;

/// Longest accepted `file:` target path.
const REF_TARGET_MAX: usize = 4096;

/// The registry string bound (CFG-016): printable ASCII, no braces.
const STRING_MAX: usize = 128;

/// Whether transport to the endpoint is TLS.
///
/// The default is [`Tls::Enabled`]; plaintext requires the explicit,
/// affirmative [`Tls::Disabled`] in the configuration that requests it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Tls {
    /// Transport is TLS (`https://`).
    #[default]
    Enabled,
    /// Transport is plaintext (`http://`); accepted only when stated
    /// explicitly, for the local reference backend the compatibility
    /// suite exercises.
    Disabled,
}

/// How the bucket is addressed against the endpoint.
///
/// The default is [`PathStyle::Path`], matching the `MinIO` reference
/// profile the registry default pins; virtual-hosted addressing is the
/// registry's `virtual_hosted` value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum PathStyle {
    /// The bucket is addressed in the request path:
    /// `https://endpoint/bucket/key`. The registry default and the
    /// `MinIO` reference profile.
    #[default]
    Path,
    /// The bucket is addressed as a subdomain: `https://bucket/key`.
    VirtualHosted,
}

impl PathStyle {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["path", "virtual_hosted"]
    }

    /// The model token — the same string the registry declares.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::VirtualHosted => "virtual_hosted",
        }
    }

    /// Parse one registry token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "path" => Ok(Self::Path),
            "virtual_hosted" => Ok(Self::VirtualHosted),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// The at-rest encryption mechanism this deployment requires (SEC-002).
///
/// Configuration validation refuses to build a store configuration
/// without one: raw archive content is personal provenance, and a
/// deployment that cannot name its encryption mechanism is not a
/// deployment this adapter serves. The tokens are the registry's
/// `storage.encryption` values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncryptionPolicy {
    /// S3 server-side encryption on every write; the adapter asserts the
    /// SSE headers and verifies the reported capability.
    S3Sse,
    /// ARMOR's S3/encryption path (ARCH-006).
    Armor,
    /// Client-side envelope encryption before any byte leaves the
    /// process.
    ClientEnvelope,
}

impl EncryptionPolicy {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["s3_sse", "armor", "client_envelope"]
    }

    /// The model token — the same string the registry declares.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::S3Sse => "s3_sse",
            Self::Armor => "armor",
            Self::ClientEnvelope => "client_envelope",
        }
    }

    /// Parse one registry token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "s3_sse" => Ok(Self::S3Sse),
            "armor" => Ok(Self::Armor),
            "client_envelope" => Ok(Self::ClientEnvelope),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// The validated endpoint URL: `http` or `https`, a host, an optional
/// port, and an optional path — and nothing else.
///
/// The grammar is closed on purpose: a lowercase `http://`/`https://`
/// scheme; a host (DNS name, IPv4 literal, or bracketed IPv6 literal); an
/// optional port in 1..=65535; and an optional path of non-empty
/// `[A-Za-z0-9._+-~]` segments. Userinfo, query strings, fragments,
/// braces, backslashes, and whitespace are refused — an endpoint is
/// infrastructure configuration, credentials never ride the URL, and
/// nothing here is a place to smuggle text through. The whole URL is
/// bounded by the registry string length (CFG-016).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct EndpointUrl {
    text: Box<str>,
    secure: bool,
}

impl EndpointUrl {
    /// Parse and validate an endpoint URL.
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MalformedSetting`] for anything outside the
    /// closed grammar. The offending text is not echoed.
    pub fn parse(text: &str) -> Result<Self, S3ConfigError> {
        let malformed = || {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::EndpointUrl.malformed_detail(),
            )
        };
        if text.is_empty() || text.len() > STRING_MAX {
            return Err(malformed());
        }
        let (secure, rest) = if let Some(rest) = text.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = text.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(malformed());
        };
        if rest.is_empty()
            || rest
                .bytes()
                .any(|byte| matches!(byte, b'@' | b'?' | b'#' | b'{' | b'}' | b'\\' | b' '))
        {
            return Err(malformed());
        }
        let (authority, path) = match rest.find('/') {
            Some(index) => (&rest[..index], Some(&rest[index..])),
            None => (rest, None),
        };
        Self::parse_authority(authority)?;
        if let Some(path) = path {
            Self::check_path(path)?;
        }
        Ok(Self {
            text: Box::from(text),
            secure,
        })
    }

    fn parse_authority(authority: &str) -> Result<(), S3ConfigError> {
        let malformed = || {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::EndpointUrl.malformed_detail(),
            )
        };
        if let Some(bracketed) = authority.strip_prefix('[') {
            // Bracketed IPv6 literal: `[hex:…:hex]`, optionally followed
            // by `:port`.
            let Some(close) = bracketed.find(']') else {
                return Err(malformed());
            };
            let (host, after) = (&bracketed[..close], &bracketed[close + 1..]);
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F' | b':'))
            {
                return Err(malformed());
            }
            return match after.strip_prefix(':') {
                Some(port) => check_port(port),
                None if after.is_empty() => Ok(()),
                None => Err(malformed()),
            };
        }
        let (host, port) = match authority.rfind(':') {
            Some(index) => (&authority[..index], Some(&authority[index + 1..])),
            None => (authority, None),
        };
        if host.is_empty()
            || !host.bytes().all(
                |byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'),
            )
        {
            return Err(malformed());
        }
        // The host charset above rejects `:`, so an IPv6 literal must
        // arrive bracketed — that refusal is the point of the split.
        if let Some(port) = port {
            check_port(port)?;
        }
        Ok(())
    }

    fn check_path(path: &str) -> Result<(), S3ConfigError> {
        let malformed = || {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::EndpointUrl.malformed_detail(),
            )
        };
        let body = path.strip_prefix('/').unwrap_or(path);
        if body.is_empty() {
            return Ok(()); // a lone trailing slash
        }
        // No empty segments beyond that lone slash: `//double` and a
        // trailing `seg/` are refused, not normalized.
        for segment in body.split('/') {
            if segment.is_empty()
                || !segment
                    .bytes()
                    .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'+' | b'-' | b'~'))
            {
                return Err(malformed());
            }
        }
        Ok(())
    }

    /// The endpoint text as configured.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Whether the endpoint scheme is `https`.
    #[must_use]
    pub const fn is_secure(&self) -> bool {
        self.secure
    }

    /// The transport the scheme implies: `https://` is [`Tls::Enabled`],
    /// `http://` is [`Tls::Disabled`].
    #[must_use]
    pub const fn tls(&self) -> Tls {
        if self.secure {
            Tls::Enabled
        } else {
            Tls::Disabled
        }
    }
}

impl fmt::Display for EndpointUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn check_port(port: &str) -> Result<(), S3ConfigError> {
    let malformed = || {
        S3ConfigError::new(
            S3ConfigErrorKind::MalformedSetting,
            Setting::EndpointUrl.malformed_detail(),
        )
    };
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(malformed());
    }
    match port.parse::<u16>() {
        Ok(value) if value != 0 => Ok(()),
        _ => Err(malformed()),
    }
}

/// A bounded plain string: printable ASCII, no braces, at most
/// [`STRING_MAX`] characters (CFG-016).
fn check_bounded_string(text: &str, malformed: S3ConfigError) -> Result<(), S3ConfigError> {
    if text.is_empty()
        || text.len() > STRING_MAX
        || !text.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        || text.contains(['{', '}'])
    {
        return Err(malformed);
    }
    Ok(())
}

/// A storage role: one of the four deliberately disjoint credential
/// identities the configuration maps (plan Section 5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageRole {
    /// Create, multipart-write, and abort on the tenant raw prefix — and
    /// nothing else.
    RawWriter,
    /// Read-only access to the signed control-record families.
    ControlReader,
    /// The optional STO-007 preflight reader; never required by the
    /// portable ingest path.
    RawReader,
    /// The offline identity backup and restore use.
    OfflineRestore,
}

impl StorageRole {
    /// Every role, in plan order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::RawWriter,
            Self::ControlReader,
            Self::RawReader,
            Self::OfflineRestore,
        ]
    }

    /// The role's token, for content-free diagnostics.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::RawWriter => "raw-writer",
            Self::ControlReader => "control-reader",
            Self::RawReader => "raw-reader",
            Self::OfflineRestore => "offline-restore",
        }
    }
}

impl fmt::Display for StorageRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

/// The validated role-to-credential mapping: each role its own credential
/// reference, pairwise distinct once held by an [`S3StorageConfig`].
///
/// The raw writer and the control reader are always present — the two
/// identities every ingest replica is configured with. The raw reader and
/// the offline restore identity are present only when a deployment
/// deliberately granted them.
#[derive(Clone, Debug)]
pub struct StorageIdentities {
    raw_write: CredentialReference,
    control_read: CredentialReference,
    raw_read: Option<CredentialReference>,
    offline_restore: Option<CredentialReference>,
}

impl StorageIdentities {
    /// The raw-writer credential.
    #[must_use]
    pub const fn raw_write(&self) -> &CredentialReference {
        &self.raw_write
    }

    /// The control-reader credential.
    #[must_use]
    pub const fn control_read(&self) -> &CredentialReference {
        &self.control_read
    }

    /// The optional raw-reader credential (STO-007 preflight).
    #[must_use]
    pub fn raw_read(&self) -> Option<&CredentialReference> {
        self.raw_read.as_ref()
    }

    /// The optional offline restore credential.
    #[must_use]
    pub fn offline_restore(&self) -> Option<&CredentialReference> {
        self.offline_restore.as_ref()
    }

    /// The credential mapped to `role`, or [`None`] for an optional role
    /// the deployment did not grant.
    #[must_use]
    pub fn role(&self, role: StorageRole) -> Option<&CredentialReference> {
        match role {
            StorageRole::RawWriter => Some(&self.raw_write),
            StorageRole::ControlReader => Some(&self.control_read),
            StorageRole::RawReader => self.raw_read.as_ref(),
            StorageRole::OfflineRestore => self.offline_restore.as_ref(),
        }
    }
}

/// The validated portable S3 configuration. Construct only through
/// [`S3StorageConfig::builder`] — every field below has passed the
/// fail-closed validation this crate pins.
#[derive(Clone, Debug)]
pub struct S3StorageConfig {
    endpoint: EndpointUrl,
    tls: Tls,
    region: Box<str>,
    path_style: PathStyle,
    encryption: EncryptionPolicy,
    raw_bucket: Box<str>,
    control_bucket: Box<str>,
    identities: StorageIdentities,
}

impl S3StorageConfig {
    /// Start assembling a configuration from its tier values.
    #[must_use]
    pub fn builder() -> S3StorageConfigBuilder {
        S3StorageConfigBuilder::default()
    }

    /// The validated endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.endpoint
    }

    /// The configured transport security.
    #[must_use]
    pub const fn tls(&self) -> Tls {
        self.tls
    }

    /// The region string the endpoint expects.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The bucket addressing style.
    #[must_use]
    pub const fn path_style(&self) -> PathStyle {
        self.path_style
    }

    /// The required at-rest encryption policy (SEC-002).
    #[must_use]
    pub const fn encryption(&self) -> EncryptionPolicy {
        self.encryption
    }

    /// The raw bucket: content-addressed blobs, occurrences, and
    /// attestations with server-derived keys.
    #[must_use]
    pub fn raw_bucket(&self) -> &str {
        &self.raw_bucket
    }

    /// The control bucket: signed control-plane records.
    #[must_use]
    pub fn control_bucket(&self) -> &str {
        &self.control_bucket
    }

    /// The validated role-to-credential identity mapping.
    #[must_use]
    pub const fn identities(&self) -> &StorageIdentities {
        &self.identities
    }
}

/// The unvalidated configuration under assembly: every registry-backed
/// setting enters as its tier string, exactly as a loader would carry it,
/// and [`S3StorageConfigBuilder::build`] is the single fail-closed gate.
#[derive(Clone, Debug, Default)]
pub struct S3StorageConfigBuilder {
    endpoint_url: Option<String>,
    tls: Option<Tls>,
    region: Option<String>,
    path_style: Option<PathStyle>,
    encryption: Option<EncryptionPolicy>,
    raw_bucket: Option<String>,
    control_bucket: Option<String>,
    raw_write: Option<String>,
    control_read: Option<String>,
    raw_read: Option<String>,
    offline_restore: Option<String>,
}

impl S3StorageConfigBuilder {
    /// Set the S3-compatible endpoint URL (`storage.endpoint_url`).
    #[must_use]
    pub fn endpoint_url(mut self, value: impl Into<String>) -> Self {
        self.endpoint_url = Some(value.into());
        self
    }

    /// Set the transport security. Defaults to [`Tls::Enabled`]; a
    /// plaintext endpoint is valid only with an explicit
    /// [`Tls::Disabled`].
    #[must_use]
    pub fn tls(mut self, value: Tls) -> Self {
        self.tls = Some(value);
        self
    }

    /// Set the region string (`storage.region`).
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = Some(value.into());
        self
    }

    /// Set the bucket addressing style (`storage.path_style`). Defaults
    /// to [`PathStyle::Path`], the registry default.
    #[must_use]
    pub fn path_style(mut self, value: PathStyle) -> Self {
        self.path_style = Some(value);
        self
    }

    /// Set the at-rest encryption policy (`storage.encryption`).
    /// Required: validation refuses to build without one (SEC-002).
    #[must_use]
    pub fn encryption(mut self, value: EncryptionPolicy) -> Self {
        self.encryption = Some(value);
        self
    }

    /// Set the raw bucket (`storage.raw_bucket`).
    #[must_use]
    pub fn raw_bucket(mut self, value: impl Into<String>) -> Self {
        self.raw_bucket = Some(value.into());
        self
    }

    /// Set the control bucket (`storage.control_bucket`).
    #[must_use]
    pub fn control_bucket(mut self, value: impl Into<String>) -> Self {
        self.control_bucket = Some(value.into());
        self
    }

    /// Set the raw-writer credential reference
    /// (`storage.raw_write_credentials_ref`). Required.
    #[must_use]
    pub fn raw_write_credentials(mut self, value: impl Into<String>) -> Self {
        self.raw_write = Some(value.into());
        self
    }

    /// Set the control-reader credential reference
    /// (`storage.control_read_credentials_ref`). Required.
    #[must_use]
    pub fn control_read_credentials(mut self, value: impl Into<String>) -> Self {
        self.control_read = Some(value.into());
        self
    }

    /// Set the optional raw-reader credential reference (STO-007
    /// preflight; the portable ingest path never requires it).
    #[must_use]
    pub fn raw_read_credentials(mut self, value: impl Into<String>) -> Self {
        self.raw_read = Some(value.into());
        self
    }

    /// Set the optional offline restore credential reference.
    #[must_use]
    pub fn offline_restore_credentials(mut self, value: impl Into<String>) -> Self {
        self.offline_restore = Some(value.into());
        self
    }

    /// Validate everything assembled so far into an [`S3StorageConfig`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] when a required setting
    /// never arrived — including the encryption policy validation
    /// requires; [`S3ConfigErrorKind::MalformedSetting`] when a setting
    /// is outside its closed grammar; [`S3ConfigErrorKind::
    /// TransportMismatch`] when the endpoint scheme and the TLS setting
    /// disagree; and [`S3ConfigErrorKind::DuplicateIdentity`] when two
    /// roles share one credential reference. No error echoes the
    /// offending value.
    pub fn build(self) -> Result<S3StorageConfig, S3ConfigError> {
        let endpoint_text = required_string(self.endpoint_url, Setting::EndpointUrl)?;
        let endpoint = EndpointUrl::parse(&endpoint_text)?;

        let tls = self.tls.unwrap_or_default();
        // The scheme and the TLS setting are one decision stated twice;
        // contradicting statements are a configuration error, and
        // plaintext is only ever reached affirmatively (SEC-001).
        if endpoint.tls() != tls {
            let detail = match (endpoint.is_secure(), tls) {
                (true, Tls::Disabled) => "https endpoint requires tls enabled",
                _ => "plaintext endpoint requires explicit tls disabled",
            };
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::TransportMismatch,
                detail,
            ));
        }

        let region_text = required_string(self.region, Setting::Region)?;
        check_bounded_string(
            &region_text,
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::Region.malformed_detail(),
            ),
        )?;

        let encryption = self.encryption.ok_or(S3ConfigError::new(
            S3ConfigErrorKind::MissingSetting,
            Setting::Encryption.missing_detail(),
        ))?;

        let raw_bucket = bucket_string(self.raw_bucket, Setting::RawBucket)?;
        let control_bucket = bucket_string(self.control_bucket, Setting::ControlBucket)?;

        let raw_write_text = required_string(self.raw_write, Setting::Credentials)?;
        let control_read_text = required_string(self.control_read, Setting::Credentials)?;
        let raw_write = CredentialReference::parse(&raw_write_text)?;
        let control_read = CredentialReference::parse(&control_read_text)?;
        let raw_read = optional_reference(self.raw_read)?;
        let offline_restore = optional_reference(self.offline_restore)?;

        // The authority split is the point of the identity mapping: two
        // roles on one credential collapse the split, so every present
        // reference must be pairwise distinct — even when every role
        // addresses the same endpoint and bucket (plan Section 5).
        let mut mapped = vec![
            (StorageRole::RawWriter, &raw_write),
            (StorageRole::ControlReader, &control_read),
        ];
        if let Some(reference) = raw_read.as_ref() {
            mapped.push((StorageRole::RawReader, reference));
        }
        if let Some(reference) = offline_restore.as_ref() {
            mapped.push((StorageRole::OfflineRestore, reference));
        }
        for (index, (_, reference)) in mapped.iter().enumerate() {
            for (_, other) in mapped.iter().skip(index + 1) {
                if reference == other {
                    return Err(S3ConfigError::new(
                        S3ConfigErrorKind::DuplicateIdentity,
                        "two storage roles map to one credential reference",
                    ));
                }
            }
        }

        Ok(S3StorageConfig {
            endpoint,
            tls,
            region: Box::from(region_text),
            path_style: self.path_style.unwrap_or_default(),
            encryption,
            raw_bucket: Box::from(raw_bucket),
            control_bucket: Box::from(control_bucket),
            identities: StorageIdentities {
                raw_write,
                control_read,
                raw_read,
                offline_restore,
            },
        })
    }
}

fn required_string(value: Option<String>, setting: Setting) -> Result<String, S3ConfigError> {
    value.ok_or(S3ConfigError::new(
        S3ConfigErrorKind::MissingSetting,
        setting.missing_detail(),
    ))
}

fn bucket_string(value: Option<String>, setting: Setting) -> Result<String, S3ConfigError> {
    let text = required_string(value, setting)?;
    check_bounded_string(
        &text,
        S3ConfigError::new(
            S3ConfigErrorKind::MalformedSetting,
            setting.malformed_detail(),
        ),
    )?;
    Ok(text)
}

fn optional_reference(value: Option<String>) -> Result<Option<CredentialReference>, S3ConfigError> {
    value
        .map(|text| CredentialReference::parse(&text))
        .transpose()
}

#[cfg(test)]
mod tests {
    use archivist_protocol::vocabulary::{GrammarError, SafeMessage};

    use super::{
        CredentialKind, CredentialReference, EncryptionPolicy, EndpointUrl, PathStyle,
        S3ConfigError, S3ConfigErrorKind, S3StorageConfig, S3StorageConfigBuilder, STRING_MAX,
        StorageRole, Tls,
    };

    const ENDPOINT: &str = "https://s3.example.invalid";
    const REGION: &str = "us-east-1";
    const RAW_BUCKET: &str = "archivist-raw-example";
    const CONTROL_BUCKET: &str = "archivist-control-example";
    const RAW_WRITE_REF: &str = "file:/etc/archivist/storage/raw-write-credentials";
    const CONTROL_READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";
    const RAW_READ_REF: &str = "file:/etc/archivist/storage/raw-read-credentials";
    const RESTORE_REF: &str = "env:RESTORE_CREDENTIALS_TARGET";

    fn valid_builder() -> S3StorageConfigBuilder {
        S3StorageConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .encryption(EncryptionPolicy::S3Sse)
            .raw_bucket(RAW_BUCKET)
            .control_bucket(CONTROL_BUCKET)
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
    }

    fn full_builder() -> S3StorageConfigBuilder {
        valid_builder()
            .raw_read_credentials(RAW_READ_REF)
            .offline_restore_credentials(RESTORE_REF)
    }

    fn without_encryption() -> S3StorageConfigBuilder {
        S3StorageConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .raw_bucket(RAW_BUCKET)
            .control_bucket(CONTROL_BUCKET)
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
    }

    fn error_of(builder: S3StorageConfigBuilder) -> S3ConfigError {
        builder
            .build()
            .expect_err("this builder must fail validation")
    }

    #[test]
    fn minimal_ingest_config_builds_with_defaults() {
        let config = valid_builder().build().expect("valid");
        assert_eq!(config.endpoint().as_str(), ENDPOINT);
        assert_eq!(config.region(), REGION);
        assert_eq!(config.path_style(), PathStyle::Path, "registry default");
        assert_eq!(config.tls(), Tls::Enabled, "tls defaults to enabled");
        assert_eq!(config.encryption(), EncryptionPolicy::S3Sse);
        assert_eq!(config.raw_bucket(), RAW_BUCKET);
        assert_eq!(config.control_bucket(), CONTROL_BUCKET);
        assert_eq!(config.identities().raw_write().kind(), CredentialKind::File);
        // The portable ingest path: exactly the two required identities.
        assert!(config.identities().raw_read().is_none());
        assert!(config.identities().offline_restore().is_none());
    }

    #[test]
    fn all_four_roles_map_to_distinct_credentials() {
        let config = full_builder().build().expect("valid");
        let identities = config.identities();
        for role in StorageRole::all() {
            let reference = identities
                .role(*role)
                .unwrap_or_else(|| panic!("role {role} must be mapped"));
            for other in StorageRole::all() {
                if role != other {
                    assert_ne!(
                        Some(reference),
                        identities.role(*other),
                        "{role} and {other} share a credential"
                    );
                }
            }
        }
        assert_eq!(
            identities.role(StorageRole::RawWriter).unwrap().kind(),
            CredentialKind::File
        );
        assert_eq!(
            identities.role(StorageRole::OfflineRestore).unwrap().kind(),
            CredentialKind::Env
        );
    }

    #[test]
    fn encryption_policy_is_required_by_validation() {
        let error = error_of(without_encryption());
        assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
        assert_eq!(error.detail(), "encryption policy is required");
        assert_eq!(
            error.to_string(),
            "s3 config missing-setting: encryption policy is required"
        );
    }

    #[test]
    fn every_required_setting_is_demanded() {
        let cases: [(S3StorageConfigBuilder, &str); 6] = [
            (S3StorageConfig::builder(), "endpoint url is required"),
            (
                S3StorageConfig::builder().endpoint_url(ENDPOINT),
                "region is required",
            ),
            (
                S3StorageConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .encryption(EncryptionPolicy::S3Sse),
                "raw bucket is required",
            ),
            (
                S3StorageConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .encryption(EncryptionPolicy::S3Sse)
                    .raw_bucket(RAW_BUCKET),
                "control bucket is required",
            ),
            (
                S3StorageConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .encryption(EncryptionPolicy::S3Sse)
                    .raw_bucket(RAW_BUCKET)
                    .control_bucket(CONTROL_BUCKET)
                    .control_read_credentials(CONTROL_READ_REF),
                "raw-write and control-read credentials are required",
            ),
            (
                S3StorageConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .encryption(EncryptionPolicy::S3Sse)
                    .raw_bucket(RAW_BUCKET)
                    .control_bucket(CONTROL_BUCKET)
                    .raw_write_credentials(RAW_WRITE_REF),
                "raw-write and control-read credentials are required",
            ),
        ];
        for (builder, detail) in cases {
            let error = error_of(builder);
            assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
            assert_eq!(error.detail(), detail);
        }
    }

    #[test]
    fn empty_values_are_malformed_not_missing() {
        // A tier supplied *something*; it just is not valid. Absence and
        // emptiness fail in different classes.
        for builder in [
            valid_builder().region(""),
            valid_builder().raw_bucket(""),
            valid_builder().control_bucket(""),
            valid_builder().raw_write_credentials(""),
            valid_builder().control_read_credentials(""),
        ] {
            let error = error_of(builder);
            assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
        }
    }

    #[test]
    fn transport_mismatch_is_rejected_in_both_directions() {
        let error = error_of(valid_builder().tls(Tls::Disabled));
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
        assert_eq!(error.detail(), "https endpoint requires tls enabled");

        let error = error_of(valid_builder().endpoint_url("http://minio.local:9000"));
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
        assert_eq!(
            error.detail(),
            "plaintext endpoint requires explicit tls disabled"
        );
    }

    #[test]
    fn plaintext_reference_profile_needs_explicit_opt_out() {
        let config = S3StorageConfig::builder()
            .endpoint_url("http://minio.local:9000")
            .tls(Tls::Disabled)
            .region(REGION)
            .encryption(EncryptionPolicy::ClientEnvelope)
            .raw_bucket(RAW_BUCKET)
            .control_bucket(CONTROL_BUCKET)
            .raw_write_credentials(RAW_WRITE_REF)
            .control_read_credentials(CONTROL_READ_REF)
            .build()
            .expect("explicit plaintext is a valid reference profile");
        assert_eq!(config.tls(), Tls::Disabled);
        assert!(!config.endpoint().is_secure());
        assert_eq!(config.endpoint().tls(), Tls::Disabled);
        assert_eq!(config.encryption(), EncryptionPolicy::ClientEnvelope);
    }

    #[test]
    fn duplicate_identities_are_rejected() {
        let error = error_of(valid_builder().control_read_credentials(RAW_WRITE_REF));
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);

        let error = error_of(full_builder().raw_read_credentials(RAW_WRITE_REF));
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);

        let error = error_of(full_builder().offline_restore_credentials(CONTROL_READ_REF));
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);

        let error = error_of(full_builder().raw_read_credentials(RESTORE_REF));
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
    }

    #[test]
    fn endpoint_grammar_is_closed() {
        for accepted in [
            "https://s3.example.invalid",
            "http://minio:9000",
            "http://minio_service:9000",
            "https://10.0.0.8:9000",
            "https://[::1]:9000",
            "https://[2001:db8::1]",
            "https://s3.example.invalid/tenant-prefix",
            "https://s3.example.invalid/",
        ] {
            assert!(
                EndpointUrl::parse(accepted).is_ok(),
                "{accepted} must parse"
            );
        }
        for rejected in [
            "",
            "s3.example.invalid",
            "ftp://s3.example.invalid",
            "HTTPS://s3.example.invalid",
            "https://",
            "https:///",
            "https://user:pass@s3.example.invalid",
            "https://s3.example.invalid?bucket=x",
            "https://s3.example.invalid#frag",
            "https://s3.example.invalid//double",
            "https://s3.example.invalid/seg{bad}",
            "https://[::1",
            "https://[::1]:junk",
            "https://host:notaport",
            "https://host:0",
            "https://host:99999",
            "https://host:65536",
            "https://ho st",
            "https://s3.example.invalid/pa th",
            "https://s3.example.invalid/back\\slash",
        ] {
            assert!(
                EndpointUrl::parse(rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
        let long = format!("https://{}.invalid", "a".repeat(STRING_MAX));
        assert!(long.len() > STRING_MAX);
        assert!(EndpointUrl::parse(&long).is_err());
    }

    #[test]
    fn bounded_strings_reject_braces_and_oversize() {
        for rejected in ["has {brace}", "has}brace", "tab\tvalue", "caf\u{e9}", ""] {
            let error = error_of(valid_builder().region(rejected));
            assert_eq!(
                error.kind(),
                S3ConfigErrorKind::MalformedSetting,
                "{rejected}"
            );
        }
        let error = error_of(valid_builder().region("r".repeat(STRING_MAX + 1)));
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
        let error = error_of(valid_builder().raw_bucket("b".repeat(STRING_MAX + 1)));
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
        let error = error_of(valid_builder().control_bucket("c".repeat(STRING_MAX + 1)));
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
    }

    #[test]
    fn credential_reference_grammar_is_closed() {
        for accepted in [
            RAW_WRITE_REF,
            "file:/run/secrets/cred",
            "env:S3_ACCESS_KEY_FILE",
            RESTORE_REF,
        ] {
            assert!(
                CredentialReference::parse(accepted).is_ok(),
                "{accepted} must parse"
            );
        }
        for rejected in [
            "",
            "file:/",
            "file:relative/path",
            "file:/has/tilde~",
            "file:/a//double",
            "file:/trailing/",
            "file:/has/../escape",
            "file:/has/./dot",
            "file:/bad{brace}",
            "file:/sp ace",
            "env:",
            "env:lowercase",
            "env:1LEADING_DIGIT",
            "env:ARCHIVIST_ENDPOINT_URL",
            "env:WITH-DASH",
            "gpg:/keyring",
            "/etc/passwd",
        ] {
            assert!(
                CredentialReference::parse(rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
    }

    #[test]
    fn reference_rendering_stays_redacted() {
        let config = full_builder().build().expect("valid");
        let rendered = format!("{config:?}");
        for never_rendered in [
            RAW_WRITE_REF,
            CONTROL_READ_REF,
            RAW_READ_REF,
            RESTORE_REF,
            "/etc/archivist",
            "RESTORE_CREDENTIALS_TARGET",
        ] {
            assert!(
                !rendered.contains(never_rendered),
                "debug rendering leaked a reference target"
            );
        }
        let file_reference = CredentialReference::parse(RAW_WRITE_REF).unwrap();
        assert_eq!(file_reference.to_string(), "credential-reference(file)");
        assert_eq!(format!("{file_reference:?}"), "CredentialReference(file)");
        let env_reference = CredentialReference::parse(RESTORE_REF).unwrap();
        assert_eq!(env_reference.to_string(), "credential-reference(env)");
        assert_eq!(format!("{env_reference:?}"), "CredentialReference(env)");
    }

    #[test]
    fn token_models_round_trip_and_fail_closed() {
        fn check<E: Copy>(
            tokens: &[&str],
            token_of: impl Fn(E) -> &'static str,
            parse_of: impl Fn(&str) -> Result<E, GrammarError>,
        ) {
            for token in tokens {
                assert_eq!(token_of(parse_of(token).unwrap()), *token);
            }
            for rejected in ["", "Path", "gzip"] {
                assert!(parse_of(rejected).is_err(), "{rejected} must be rejected");
            }
        }
        check(PathStyle::tokens(), PathStyle::token, PathStyle::parse);
        check(
            EncryptionPolicy::tokens(),
            EncryptionPolicy::token,
            EncryptionPolicy::parse,
        );
    }

    #[test]
    fn tokens_agree_with_the_registry() {
        // The registry (tools/config-keys.toml) is the source of these
        // closed sets; this pin makes drift a test failure here too.
        assert_eq!(
            PathStyle::tokens(),
            &["path", "virtual_hosted"],
            "storage.path_style values"
        );
        assert_eq!(
            EncryptionPolicy::tokens(),
            &["s3_sse", "armor", "client_envelope"],
            "storage.encryption values"
        );
    }

    #[test]
    fn errors_are_safe_messages_with_distinct_kinds() {
        let all = S3ConfigErrorKind::all();
        assert_eq!(all.len(), 4);
        let displays: Vec<_> = all.iter().map(std::string::ToString::to_string).collect();
        let mut sorted = displays.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(displays.len(), sorted.len(), "display strings collide");
        for kind in all {
            let detail = kind.default_detail();
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("default detail of {kind} is not safe"))
                    .as_str(),
                detail
            );
        }
        for setting in super::Setting::all() {
            for detail in [setting.missing_detail(), setting.malformed_detail()] {
                assert_eq!(
                    SafeMessage::parse(detail)
                        .unwrap_or_else(|_| panic!("setting detail is not safe: {detail}"))
                        .as_str(),
                    detail
                );
            }
        }
        // The TransportMismatch literals are call sites, not kind
        // defaults; pin them here too.
        for detail in [
            "https endpoint requires tls enabled",
            "plaintext endpoint requires explicit tls disabled",
            "two storage roles map to one credential reference",
        ] {
            assert_eq!(
                SafeMessage::parse(detail)
                    .unwrap_or_else(|_| panic!("call-site detail is not safe: {detail}"))
                    .as_str(),
                detail
            );
        }
    }

    #[test]
    fn roles_render_as_content_free_tokens() {
        let tokens: Vec<_> = StorageRole::all()
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        assert_eq!(
            tokens,
            vec![
                "raw-writer",
                "control-reader",
                "raw-reader",
                "offline-restore"
            ]
        );
    }
}
