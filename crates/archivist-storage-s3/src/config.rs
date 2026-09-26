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
//! # The control-administration surface
//!
//! [`ControlAdminConfig`] is deliberately *not* an ingest configuration.
//! It is the separate, offline surface the administrator CLI assembles —
//! its own endpoint and bucket settings, its own dedicated credential
//! reference, and the one tenant whose control prefix that credential
//! provisions. "Ingest replicas never receive this credential" (plan
//! Section 5) holds three ways: the ingest builder has no setter and
//! [`StorageRole`] no role for the administration credential;
//! [`S3StorageConfig::reject_administration_credential`] refuses a
//! deployment that maps any ingest role onto the administration reference
//! anyway — the one composition mistake the type split alone cannot see;
//! and [`ControlAdminConfig::permits_key`] models the reference's
//! provisioned scope, admitting only the five control layouts under the
//! pinned tenant's control prefix. The surface is registry-backed as the
//! `admin.*` section: `admin.endpoint_url`, `admin.region`,
//! `admin.path_style`, `admin.control_bucket`, and `admin.tenant` assemble
//! this configuration, and the dedicated credential reference is
//! `admin.credentials_ref` (a secret reference, CFG-028 through CFG-031).
//! The section is disjoint from `storage.*` by construction, so an ingest
//! replica's configuration file never carries administration material even
//! by accident; the tenant-authority signing seed the administration
//! commands also consume is registered beside these as
//! `admin.authority_seed_ref`, owned by `archivist-auth`.
//!
//! # The Phase 10 scoped-writer surface
//!
//! [`ScopedWritersConfig`] is the pair surface the process hosting the
//! Phase 10 pipelines assembles — the catalog-writer and derived-writer
//! identities (plan Section 7.5; the ARMOR provisioning's two `put+list`
//! grants below one tenant's catalog and derived prefixes), the way
//! [`ControlAdminConfig`] is the offline administration surface. The two
//! writers share the deployment's endpoint, region, addressing style, and
//! tenant bucket and differ only in the namespace each credential
//! provisions. Each half validates by its own standalone surface in
//! [`crate::scoped_write`] — the same fail-closed gates the stores compose
//! from — and never becomes a field of [`S3StorageConfig`] or a
//! [`StorageRole`]: the writer credentials are not ingest identities, and
//! the joint refusals that keep them disjoint from every ingest role, the
//! administration credential, and each other stay on the writer surfaces
//! themselves. This surface adds the one check the two halves cannot see
//! on their own — the pair never maps both namespaces onto one credential
//! — and hands back the two validated writer configurations.
//!
//! The credentials enter as registry references
//! (`storage.catalog_write_credentials_ref`,
//! `storage.derived_write_credentials_ref` — optional secret references,
//! CFG-019 and CFG-028: a replica that hosts none of the Phase 10
//! pipelines never carries them) and validate by the CFG-029 grammar, so
//! a literal value assigned to either setting is a construction failure,
//! never a store (CFG-032). The scoping settings ride the deployment's
//! `storage.endpoint_url` and `storage.region` values and the tenant
//! bucket the two identities provision.
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

use archivist_protocol::vocabulary::{GrammarError, TenantId};

use crate::control_admin::ControlObjectKey;
use crate::scoped_write::{CatalogWriterConfig, DerivedWriterConfig};

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
    /// Two storage roles were mapped to the same credential reference —
    /// or one ingest identity is the offline control-administration
    /// credential.
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
    Tenant,
    AdminCredentials,
    ReadCredentials,
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
            Self::Tenant,
            Self::AdminCredentials,
            Self::ReadCredentials,
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
            Self::Tenant => "tenant is required",
            Self::AdminCredentials => "control-administration credential is required",
            Self::ReadCredentials => "control-read credential is required",
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
            Self::Tenant => "tenant is outside the canonical uuid grammar",
            Self::AdminCredentials => {
                "control-administration credential is outside the closed grammar"
            }
            Self::ReadCredentials => "control-read credential is outside the closed grammar",
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

    /// Resolve the referenced S3 credential document at composition time.
    ///
    /// The document contains exactly `ACCESS_KEY=...` and
    /// `SECRET_KEY=...` lines. The returned pair is crate-private so the
    /// resolved values cannot become part of the public configuration API;
    /// request composition immediately hands them to the redacting auth
    /// signer. A file reference is accepted only for a regular owner-only
    /// file, and neither failure class carries the path, variable name, or
    /// secret value.
    pub(crate) fn resolve_s3_credentials(
        &self,
    ) -> Result<(String, String), CredentialResolutionError> {
        let document = match self {
            Self::File { path } => {
                let metadata =
                    std::fs::metadata(path).map_err(|_| CredentialResolutionError::Unavailable)?;
                if !metadata.is_file() {
                    return Err(CredentialResolutionError::Malformed);
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if metadata.permissions().mode() & 0o077 != 0 {
                        return Err(CredentialResolutionError::Malformed);
                    }
                }
                std::fs::read_to_string(path).map_err(|_| CredentialResolutionError::Unavailable)?
            }
            Self::Env { name } => {
                std::env::var(name.as_ref()).map_err(|_| CredentialResolutionError::Unavailable)?
            }
        };
        parse_s3_credential_document(&document)
    }
}

/// The two content-free failure classes for composition-time credential
/// resolution. This is crate-private deliberately: callers receive a
/// constructor error, never a path or secret-bearing diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialResolutionError {
    /// The reference target could not be read.
    Unavailable,
    /// The target was readable but was not a valid credential document.
    Malformed,
}

/// Parse one bounded `ACCESS_KEY`/`SECRET_KEY` credential document.
fn parse_s3_credential_document(
    document: &str,
) -> Result<(String, String), CredentialResolutionError> {
    const MAX_DOCUMENT_BYTES: usize = 4096;
    const MAX_FIELD_BYTES: usize = 1024;
    if document.is_empty() || document.len() > MAX_DOCUMENT_BYTES {
        return Err(CredentialResolutionError::Malformed);
    }
    let mut access = None;
    let mut secret = None;
    for line in document.lines() {
        let Some((name, value)) = line.split_once('=') else {
            return Err(CredentialResolutionError::Malformed);
        };
        if value.is_empty()
            || value.len() > MAX_FIELD_BYTES
            || !value.bytes().all(|byte| (b'!'..=b'~').contains(&byte))
        {
            return Err(CredentialResolutionError::Malformed);
        }
        match name {
            "ACCESS_KEY" if access.is_none() => access = Some(value.to_owned()),
            "SECRET_KEY" if secret.is_none() => secret = Some(value.to_owned()),
            _ => return Err(CredentialResolutionError::Malformed),
        }
    }
    match (access, secret) {
        (Some(access), Some(secret)) => Ok((access, secret)),
        _ => Err(CredentialResolutionError::Malformed),
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

    /// Refuse the one composition mistake the type split cannot prevent on
    /// its own: an ingest role mapped onto the offline
    /// control-administration credential (plan Section 5: "Ingest replicas
    /// never receive this credential").
    ///
    /// The ingest surface cannot *express* the administration credential —
    /// no builder setter and no [`StorageRole`] names it — so an ingest
    /// configuration that carries it can only mean a deployment reused the
    /// same reference string on both surfaces. That collapses the
    /// authority split this crate exists to keep, so validation reports it
    /// as the duplicate-identity failure it is. The check is joint by
    /// necessity: each configuration is valid on its own, and only the
    /// pair states the violation.
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::DuplicateIdentity`] when any mapped ingest
    /// role — present or optional — holds the administration credential
    /// reference. The offending reference is not echoed.
    pub fn reject_administration_credential(
        &self,
        admin: &ControlAdminConfig,
    ) -> Result<(), S3ConfigError> {
        for role in StorageRole::all() {
            if self.identities.role(*role) == Some(admin.control_admin_credentials()) {
                return Err(S3ConfigError::new(
                    S3ConfigErrorKind::DuplicateIdentity,
                    "an ingest identity is the control-administration credential",
                ));
            }
        }
        Ok(())
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
        let (endpoint, tls) = agreed_transport(&endpoint_text, self.tls)?;

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

/// The validated configuration of the offline control-administration
/// identity (plan Section 5): the dedicated, protected credential that can
/// put only validated, tenant-authority-signed control records below one
/// tenant's control prefix — and nothing else.
///
/// This is a separate surface from [`S3StorageConfig`] by design. The
/// ingest configuration maps read/write roles for the replica; this one
/// configures the single-writer authority the administrator CLI composes
/// into [`crate::control_admin::S3ControlAdminStore`]. It carries no raw
/// bucket, no encryption policy, and no role mapping, because the
/// administration identity has exactly one capability and no optional
/// companions.
#[derive(Clone, Debug)]
pub struct ControlAdminConfig {
    endpoint: EndpointUrl,
    tls: Tls,
    region: Box<str>,
    path_style: PathStyle,
    control_bucket: Box<str>,
    tenant: TenantId,
    admin_credentials: CredentialReference,
}

impl ControlAdminConfig {
    /// Start assembling an administration configuration from its tier
    /// values.
    #[must_use]
    pub fn builder() -> ControlAdminConfigBuilder {
        ControlAdminConfigBuilder::default()
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

    /// The control bucket: signed control-plane records.
    #[must_use]
    pub fn control_bucket(&self) -> &str {
        &self.control_bucket
    }

    /// The one tenant whose control prefix this credential provisions.
    /// Every record the store accepts must belong to this tenant, and
    /// every key it derives lives under this tenant's prefix.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The dedicated administration credential reference. Distinct by
    /// construction from every ingest credential:
    /// [`S3StorageConfig::reject_administration_credential`] refuses a
    /// deployment that maps an ingest role onto it.
    #[must_use]
    pub const fn control_admin_credentials(&self) -> &CredentialReference {
        &self.admin_credentials
    }

    /// Whether a raw object key is inside this credential's provisioned
    /// scope: one of the five canonical control layouts under this
    /// tenant's control prefix (plan Section 7.5), and nothing else.
    ///
    /// This is the Rust-side model of the deployment's backend policy for
    /// the administration credential — read-write below
    /// `tenants/<tenant>/v1/control/`, deny every other prefix. Raw blobs,
    /// occurrences, attestations, catalog checkpoints, derived objects,
    /// tombstones, legal holds, and every other tenant's prefix (control
    /// included) are denied; a control-layout key with a non-canonical
    /// identifier or epoch segment is denied rather than normalized. The
    /// compatibility-suite profiles prove the live policy agrees.
    #[must_use]
    pub fn permits_key(&self, key: &str) -> bool {
        ControlObjectKey::parse(key).is_ok_and(|derived| derived.tenant() == &self.tenant)
    }
}

/// The unvalidated administration configuration under assembly;
/// [`ControlAdminConfigBuilder::build`] is its single fail-closed gate,
/// with the same endpoint/TLS agreement rule the ingest surface pins.
#[derive(Clone, Debug, Default)]
pub struct ControlAdminConfigBuilder {
    endpoint_url: Option<String>,
    tls: Option<Tls>,
    region: Option<String>,
    path_style: Option<PathStyle>,
    control_bucket: Option<String>,
    tenant: Option<String>,
    admin_credentials: Option<String>,
}

impl ControlAdminConfigBuilder {
    /// Set the S3-compatible endpoint URL of the control bucket.
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

    /// Set the region string.
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = Some(value.into());
        self
    }

    /// Set the bucket addressing style. Defaults to [`PathStyle::Path`].
    #[must_use]
    pub fn path_style(mut self, value: PathStyle) -> Self {
        self.path_style = Some(value);
        self
    }

    /// Set the control bucket.
    #[must_use]
    pub fn control_bucket(mut self, value: impl Into<String>) -> Self {
        self.control_bucket = Some(value.into());
        self
    }

    /// Set the tenant whose control prefix this credential provisions.
    /// Required: the administration identity is single-tenant by design.
    #[must_use]
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.tenant = Some(value.into());
        self
    }

    /// Set the dedicated administration credential reference (CFG-029
    /// grammar). Required.
    #[must_use]
    pub fn control_admin_credentials(mut self, value: impl Into<String>) -> Self {
        self.admin_credentials = Some(value.into());
        self
    }

    /// Validate everything assembled so far into a
    /// [`ControlAdminConfig`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] when a required setting never
    /// arrived; [`S3ConfigErrorKind::MalformedSetting`] when a setting is
    /// outside its grammar; [`S3ConfigErrorKind::TransportMismatch`] when
    /// the endpoint scheme and the TLS setting disagree. No error echoes
    /// the offending value.
    pub fn build(self) -> Result<ControlAdminConfig, S3ConfigError> {
        let endpoint_text = required_string(self.endpoint_url, Setting::EndpointUrl)?;
        let (endpoint, tls) = agreed_transport(&endpoint_text, self.tls)?;

        let region_text = required_string(self.region, Setting::Region)?;
        check_bounded_string(
            &region_text,
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::Region.malformed_detail(),
            ),
        )?;

        let control_bucket = bucket_string(self.control_bucket, Setting::ControlBucket)?;

        let tenant_text = required_string(self.tenant, Setting::Tenant)?;
        let tenant = TenantId::parse(&tenant_text).map_err(|_| {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::Tenant.malformed_detail(),
            )
        })?;

        let admin_text = required_string(self.admin_credentials, Setting::AdminCredentials)?;
        let admin_credentials = CredentialReference::parse(&admin_text).map_err(|_| {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::AdminCredentials.malformed_detail(),
            )
        })?;

        Ok(ControlAdminConfig {
            endpoint,
            tls,
            region: Box::from(region_text),
            path_style: self.path_style.unwrap_or_default(),
            control_bucket: Box::from(control_bucket),
            tenant,

            admin_credentials,
        })
    }
}

/// The validated configuration of an ingest replica's control-READ
/// identity (plan Section 5): the credential that may read
/// tenant-authority-signed control records and hold no other authority.
///
/// This is a separate surface from [`ControlAdminConfig`] by necessity,
/// not convenience. The administration identity writes the control prefix
/// and is never configured on a replica; this one reads it and can neither
/// publish nor retract a record. Keeping them as distinct types means a
/// deployment cannot quietly hand an ingest replica write authority by
/// reusing one configuration in both places, and
/// [`ControlReadConfig::reject_administration_credential`] refuses the
/// remaining way to collapse them.
///
/// It carries no raw bucket and no role mapping: this identity has exactly
/// one capability over exactly one prefix.
#[derive(Clone, Debug)]
pub struct ControlReadConfig {
    endpoint: EndpointUrl,
    tls: Tls,
    region: Box<str>,
    path_style: PathStyle,
    control_bucket: Box<str>,
    tenant: TenantId,
    read_credentials: CredentialReference,
}

impl ControlReadConfig {
    /// Start assembling a control-read configuration from its tier values.
    #[must_use]
    pub fn builder() -> ControlReadConfigBuilder {
        ControlReadConfigBuilder::default()
    }

    /// The validated endpoint of the control bucket.
    #[must_use]
    pub fn endpoint(&self) -> &EndpointUrl {
        &self.endpoint
    }

    /// The transport security agreed with the endpoint scheme.
    #[must_use]
    pub const fn tls(&self) -> Tls {
        self.tls
    }

    /// The configured region.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    /// The addressing style for this endpoint.
    #[must_use]
    pub const fn path_style(&self) -> PathStyle {
        self.path_style
    }

    /// The bucket holding this tenant's control prefix.
    #[must_use]
    pub fn control_bucket(&self) -> &str {
        &self.control_bucket
    }

    /// The tenant whose control prefix this identity is provisioned for.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The control-read credential reference. A reference only: no
    /// credential value is parsed, stored, or echoed on this surface.
    #[must_use]
    pub const fn control_read_credentials(&self) -> &CredentialReference {
        &self.read_credentials
    }

    /// Whether a key is inside this credential's provisioned read scope:
    /// one of the five canonical control layouts under this tenant's
    /// control prefix (plan Section 7.5), and nothing else.
    ///
    /// This is the Rust-side model of the deployment's backend policy for
    /// the read identity — read-only below `tenants/<tenant>/v1/control/`,
    /// deny every other prefix. Raw blobs, occurrences, attestations,
    /// catalog checkpoints, derived objects, tombstones, legal holds, and
    /// every other tenant's prefix (control included) are denied, and a
    /// control-layout key with a non-canonical identifier or epoch segment
    /// is denied rather than normalized.
    ///
    /// It deliberately shares [`ControlObjectKey::parse`] with the
    /// administration surface: reader and writer agreeing on what a
    /// canonical control key is, is the property that makes a record
    /// written by the administrator findable by the replica.
    #[must_use]
    pub fn permits_key(&self, key: &str) -> bool {
        ControlObjectKey::parse(key).is_ok_and(|derived| derived.tenant() == &self.tenant)
    }

    /// Refuse a deployment that maps the read identity onto the
    /// administration credential.
    ///
    /// Neither configuration can state this violation alone — each is
    /// valid on its own terms — so the check is a joint one over the pair,
    /// mirroring [`S3StorageConfig::reject_administration_credential`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::DuplicateIdentity`] when the control-read
    /// credential reference is the control-administration credential
    /// reference. The offending reference is not echoed.
    pub fn reject_administration_credential(
        &self,
        admin: &ControlAdminConfig,
    ) -> Result<(), S3ConfigError> {
        if &self.read_credentials == admin.control_admin_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                "the control-read identity is the control-administration credential",
            ));
        }
        Ok(())
    }
}

/// The unvalidated control-read configuration under assembly;
/// [`ControlReadConfigBuilder::build`] is its single fail-closed gate,
/// with the same endpoint/TLS agreement rule the other surfaces pin.
#[derive(Clone, Debug, Default)]
pub struct ControlReadConfigBuilder {
    endpoint_url: Option<String>,
    tls: Option<Tls>,
    region: Option<String>,
    path_style: Option<PathStyle>,
    control_bucket: Option<String>,
    tenant: Option<String>,
    read_credentials: Option<String>,
}

impl ControlReadConfigBuilder {
    /// Set the S3-compatible endpoint URL of the control bucket.
    #[must_use]
    pub fn endpoint_url(mut self, value: impl Into<String>) -> Self {
        self.endpoint_url = Some(value.into());
        self
    }

    /// Set the transport security. Defaults to [`Tls::Enabled`]; a
    /// plaintext endpoint is valid only with an explicit
    /// [`Tls::Disabled`].
    #[must_use]
    pub const fn tls(mut self, value: Tls) -> Self {
        self.tls = Some(value);
        self
    }

    /// Set the region.
    #[must_use]
    pub fn region(mut self, value: impl Into<String>) -> Self {
        self.region = Some(value.into());
        self
    }

    /// Set the addressing style. Defaults to the portable default.
    #[must_use]
    pub const fn path_style(mut self, value: PathStyle) -> Self {
        self.path_style = Some(value);
        self
    }

    /// Set the bucket holding the control prefix.
    #[must_use]
    pub fn control_bucket(mut self, value: impl Into<String>) -> Self {
        self.control_bucket = Some(value.into());
        self
    }

    /// Set the tenant this identity is provisioned for.
    #[must_use]
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.tenant = Some(value.into());
        self
    }

    /// Set the control-read credential reference (CFG-029). A reference,
    /// never a credential value.
    #[must_use]
    pub fn control_read_credentials(mut self, value: impl Into<String>) -> Self {
        self.read_credentials = Some(value.into());
        self
    }

    /// Validate every tier value and produce the configuration.
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] for an absent required
    /// value, [`S3ConfigErrorKind::MalformedSetting`] for one outside its
    /// grammar, and [`S3ConfigErrorKind::TransportMismatch`] when the
    /// endpoint scheme and the TLS setting disagree. No error echoes the
    /// offending value.
    pub fn build(self) -> Result<ControlReadConfig, S3ConfigError> {
        let endpoint_text = required_string(self.endpoint_url, Setting::EndpointUrl)?;
        let (endpoint, tls) = agreed_transport(&endpoint_text, self.tls)?;

        let region_text = required_string(self.region, Setting::Region)?;
        check_bounded_string(
            &region_text,
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::Region.malformed_detail(),
            ),
        )?;

        let control_bucket = bucket_string(self.control_bucket, Setting::ControlBucket)?;

        let tenant_text = required_string(self.tenant, Setting::Tenant)?;
        let tenant = TenantId::parse(&tenant_text).map_err(|_| {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::Tenant.malformed_detail(),
            )
        })?;

        let read_text = required_string(self.read_credentials, Setting::ReadCredentials)?;
        let read_credentials = CredentialReference::parse(&read_text).map_err(|_| {
            S3ConfigError::new(
                S3ConfigErrorKind::MalformedSetting,
                Setting::ReadCredentials.malformed_detail(),
            )
        })?;

        Ok(ControlReadConfig {
            endpoint,
            tls,
            region: Box::from(region_text),
            path_style: self.path_style.unwrap_or_default(),
            control_bucket: Box::from(control_bucket),
            tenant,
            read_credentials,
        })
    }
}

/// The validated configuration of the two Phase 10 scoped-writer
/// identities (plan Section 7.5): the catalog-writer and derived-writer
/// pair the process hosting the Phase 10 pipelines assembles once and
/// composes both stores from.
///
/// This is a separate surface from [`S3StorageConfig`] and from
/// [`ControlAdminConfig`] by design — and the two writers stay off the
/// ingest surface entirely: neither credential is a [`StorageRole`] nor a
/// field of [`StorageIdentities`], because a replica that hosts none of
/// the Phase 10 pipelines never carries their credentials and an ingest
/// replica is never granted them. Each half is validated by its own
/// standalone surface ([`CatalogWriterConfig`],
/// [`DerivedWriterConfig`], both in [`crate::scoped_write`]) — this type
/// carries the pair, adds the one refusal the halves cannot see on their
/// own (both namespaces on one credential), and hands the validated
/// halves back.
#[derive(Clone, Debug)]
pub struct ScopedWritersConfig {
    catalog: CatalogWriterConfig,
    derived: DerivedWriterConfig,
}

impl ScopedWritersConfig {
    /// Start assembling the scoped-writer pair from its tier values.
    #[must_use]
    pub fn builder() -> ScopedWritersConfigBuilder {
        ScopedWritersConfigBuilder::default()
    }

    /// The validated catalog-writer configuration: the half that puts
    /// and lists below one tenant's catalog namespace.
    #[must_use]
    pub const fn catalog(&self) -> &CatalogWriterConfig {
        &self.catalog
    }

    /// The validated derived-writer configuration: the half that puts
    /// and lists below one tenant's derived namespace.
    #[must_use]
    pub const fn derived(&self) -> &DerivedWriterConfig {
        &self.derived
    }
}

/// The unvalidated scoped-writer pair under assembly;
/// [`ScopedWritersConfigBuilder::build`] is its single fail-closed gate:
/// each half through its standalone surface's gate, then the pair-level
/// distinctness rule. A literal value assigned to either writer
/// credential setting is refused here, before any store exists (CFG-032).
#[derive(Clone, Debug, Default)]
pub struct ScopedWritersConfigBuilder {
    endpoint_url: Option<String>,
    tls: Option<Tls>,
    region: Option<String>,
    path_style: Option<PathStyle>,
    tenant_bucket: Option<String>,
    tenant: Option<String>,
    catalog_credentials: Option<String>,
    derived_credentials: Option<String>,
}

impl ScopedWritersConfigBuilder {
    /// Set the S3-compatible endpoint URL of the tenant bucket
    /// (`storage.endpoint_url`).
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

    /// Set the bucket addressing style. Defaults to [`PathStyle::Path`].
    #[must_use]
    pub fn path_style(mut self, value: PathStyle) -> Self {
        self.path_style = Some(value);
        self
    }

    /// Set the tenant bucket both writer identities provision.
    #[must_use]
    pub fn tenant_bucket(mut self, value: impl Into<String>) -> Self {
        self.tenant_bucket = Some(value.into());
        self
    }

    /// Set the tenant whose catalog and derived prefixes the pair
    /// provisions. Required: each writer identity is single-tenant by
    /// design.
    #[must_use]
    pub fn tenant(mut self, value: impl Into<String>) -> Self {
        self.tenant = Some(value.into());
        self
    }

    /// Set the catalog-writer credential reference
    /// (`storage.catalog_write_credentials_ref`, CFG-029 grammar).
    /// Required on this surface.
    #[must_use]
    pub fn catalog_write_credentials(mut self, value: impl Into<String>) -> Self {
        self.catalog_credentials = Some(value.into());
        self
    }

    /// Set the derived-writer credential reference
    /// (`storage.derived_write_credentials_ref`, CFG-029 grammar).
    /// Required on this surface.
    #[must_use]
    pub fn derived_write_credentials(mut self, value: impl Into<String>) -> Self {
        self.derived_credentials = Some(value.into());
        self
    }

    /// Validate everything assembled so far into a
    /// [`ScopedWritersConfig`].
    ///
    /// # Errors
    /// [`S3ConfigErrorKind::MissingSetting`] when a required setting
    /// never arrived; [`S3ConfigErrorKind::MalformedSetting`] when a
    /// setting is outside its grammar — including a literal value
    /// assigned to either writer credential reference (CFG-032);
    /// [`S3ConfigErrorKind::TransportMismatch`] when the endpoint scheme
    /// and the TLS setting disagree; and
    /// [`S3ConfigErrorKind::DuplicateIdentity`] when both writers map to
    /// one credential. No error echoes the offending value.
    pub fn build(self) -> Result<ScopedWritersConfig, S3ConfigError> {
        let Self {
            endpoint_url,
            tls,
            region,
            path_style,
            tenant_bucket,
            tenant,
            catalog_credentials,
            derived_credentials,
        } = self;

        // A setting never supplied stays never supplied: only a present
        // tier string is forwarded, so the delegated gates report a
        // missing setting as missing, never as a malformed empty one.
        let mut catalog_builder = CatalogWriterConfig::builder();
        let mut derived_builder = DerivedWriterConfig::builder();
        if let Some(value) = endpoint_url.as_deref() {
            catalog_builder = catalog_builder.endpoint_url(value);
            derived_builder = derived_builder.endpoint_url(value);
        }
        if let Some(value) = tls {
            catalog_builder = catalog_builder.tls(value);
            derived_builder = derived_builder.tls(value);
        }
        if let Some(value) = region.as_deref() {
            catalog_builder = catalog_builder.region(value);
            derived_builder = derived_builder.region(value);
        }
        if let Some(value) = path_style {
            catalog_builder = catalog_builder.path_style(value);
            derived_builder = derived_builder.path_style(value);
        }
        if let Some(value) = tenant_bucket.as_deref() {
            catalog_builder = catalog_builder.tenant_bucket(value);
            derived_builder = derived_builder.tenant_bucket(value);
        }
        if let Some(value) = tenant.as_deref() {
            catalog_builder = catalog_builder.tenant(value);
            derived_builder = derived_builder.tenant(value);
        }
        if let Some(value) = catalog_credentials.as_deref() {
            catalog_builder = catalog_builder.catalog_write_credentials(value);
        }
        if let Some(value) = derived_credentials.as_deref() {
            derived_builder = derived_builder.derived_write_credentials(value);
        }

        let catalog = catalog_builder.build()?;
        let derived = derived_builder.build()?;

        // The one refusal the two halves cannot see on their own: one
        // credential asked to serve two namespaces whose grants differ
        // collapses the authority split the pair exists to keep (plan
        // Section 7.5). The other reuse shapes — an ingest role, the
        // administration credential — stay on the writer surfaces'
        // joint checks, which see those configurations and this one
        // does not.
        if catalog.catalog_write_credentials() == derived.derived_write_credentials() {
            return Err(S3ConfigError::new(
                S3ConfigErrorKind::DuplicateIdentity,
                "the two scoped writers share one credential",
            ));
        }

        Ok(ScopedWritersConfig { catalog, derived })
    }
}

/// Parse the endpoint and settle the TLS setting, refusing contradiction
/// between the two statements of one decision: the scheme and the TLS
/// setting must agree, and plaintext is only ever reached affirmatively
/// (SEC-001).
fn agreed_transport(
    endpoint_text: &str,
    tls: Option<Tls>,
) -> Result<(EndpointUrl, Tls), S3ConfigError> {
    let endpoint = EndpointUrl::parse(endpoint_text)?;
    let tls = tls.unwrap_or_default();
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
    Ok((endpoint, tls))
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
        ControlAdminConfig, ControlAdminConfigBuilder, ControlReadConfig, ControlReadConfigBuilder,
        CredentialKind, CredentialReference, EncryptionPolicy, EndpointUrl, PathStyle,
        S3ConfigError, S3ConfigErrorKind, S3StorageConfig, S3StorageConfigBuilder, STRING_MAX,
        ScopedWritersConfig, ScopedWritersConfigBuilder, StorageRole, Tls,
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
        // The TransportMismatch and DuplicateIdentity literals are call
        // sites, not kind defaults; pin them here too.
        for detail in [
            "https endpoint requires tls enabled",
            "plaintext endpoint requires explicit tls disabled",
            "two storage roles map to one credential reference",
            "an ingest identity is the control-administration credential",
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

    const ADMIN_TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const ADMIN_REF: &str = "file:/etc/archivist/storage/control-admin-credentials";
    // The same dedicated reference through the grammar's other kind: the
    // administration credential is as likely to arrive from a secret's env
    // channel as from its file channel (CFG-029).
    const ENV_ADMIN_REF: &str = "env:CONTROL_ADMIN_CREDENTIAL_TARGET";

    fn admin_builder() -> ControlAdminConfigBuilder {
        ControlAdminConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .control_bucket(CONTROL_BUCKET)
            .tenant(ADMIN_TENANT)
            .control_admin_credentials(ADMIN_REF)
    }

    #[test]
    fn control_admin_configuration_is_its_own_surface() {
        let config = admin_builder().build().expect("valid");
        assert_eq!(config.endpoint().as_str(), ENDPOINT);
        assert_eq!(config.tls(), Tls::Enabled, "tls defaults to enabled");
        assert_eq!(config.path_style(), PathStyle::Path, "registry default");
        assert_eq!(config.region(), REGION);
        assert_eq!(config.control_bucket(), CONTROL_BUCKET);
        assert_eq!(config.tenant().as_str(), ADMIN_TENANT);
        assert_eq!(
            config.control_admin_credentials().kind(),
            CredentialKind::File
        );
        // The dedicated credential reference never renders.
        let rendered = format!("{config:?}");
        for never_rendered in [ADMIN_REF, "/etc/archivist"] {
            assert!(
                !rendered.contains(never_rendered),
                "admin debug rendering leaked a reference target"
            );
        }
    }

    #[test]
    fn control_admin_validation_is_fail_closed() {
        let missing: [(ControlAdminConfigBuilder, &str); 3] = [
            (ControlAdminConfig::builder(), "endpoint url is required"),
            (
                ControlAdminConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION),
                "control bucket is required",
            ),
            (
                ControlAdminConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .control_bucket(CONTROL_BUCKET),
                "tenant is required",
            ),
        ];
        for (builder, detail) in missing {
            let error = builder.build().expect_err("this builder must fail");
            assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
            assert_eq!(error.detail(), detail);
        }
        let error = ControlAdminConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .control_bucket(CONTROL_BUCKET)
            .tenant(ADMIN_TENANT)
            .build()
            .expect_err("credential is required");
        assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
        assert_eq!(
            error.detail(),
            "control-administration credential is required"
        );

        for (builder, detail) in [
            (
                admin_builder().tenant("not-a-uuid"),
                "tenant is outside the canonical uuid grammar",
            ),
            (
                admin_builder().tenant(""),
                "tenant is outside the canonical uuid grammar",
            ),
            (
                admin_builder().control_admin_credentials("relative-path"),
                "control-administration credential is outside the closed grammar",
            ),
            (
                admin_builder().control_admin_credentials(""),
                "control-administration credential is outside the closed grammar",
            ),
        ] {
            let error = builder.build().expect_err("this builder must fail");
            assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
            assert_eq!(error.detail(), detail);
        }

        // The transport agreement rule is the ingest surface's rule, on
        // this surface too.
        let error = admin_builder()
            .tls(Tls::Disabled)
            .build()
            .expect_err("https needs tls enabled");
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
        let error = admin_builder()
            .endpoint_url("http://minio.local:9000")
            .build()
            .expect_err("plaintext needs explicit opt-out");
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
        admin_builder()
            .endpoint_url("http://minio.local:9000")
            .tls(Tls::Disabled)
            .build()
            .expect("explicit plaintext is a valid reference profile");
    }

    #[test]
    fn ingest_configuration_refuses_the_administration_credential() {
        let admin = admin_builder().build().expect("valid");
        // Disjoint credentials compose: the ingest replica and the offline
        // administrator coexist on one deployment.
        valid_builder()
            .build()
            .expect("valid")
            .reject_administration_credential(&admin)
            .expect("disjoint credentials are fine");
        full_builder()
            .build()
            .expect("valid")
            .reject_administration_credential(&admin)
            .expect("disjoint credentials are fine");
        // Every ingest role mapped onto the administration reference is
        // refused — required or optional alike.
        for (role, builder) in [
            (
                "raw-writer",
                valid_builder().raw_write_credentials(ADMIN_REF),
            ),
            (
                "control-reader",
                valid_builder().control_read_credentials(ADMIN_REF),
            ),
            (
                "raw-reader",
                valid_builder().raw_read_credentials(ADMIN_REF),
            ),
            (
                "offline-restore",
                valid_builder().offline_restore_credentials(ADMIN_REF),
            ),
        ] {
            let config = builder.build().unwrap_or_else(|e| panic!("{role}: {e}"));
            let error = config
                .reject_administration_credential(&admin)
                .expect_err("{role} must be refused");
            assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
            assert_eq!(
                error.detail(),
                "an ingest identity is the control-administration credential"
            );
            assert!(
                !error.to_string().contains(ADMIN_REF),
                "the refusal must not echo the reference"
            );
        }
    }

    #[test]
    fn the_refusal_covers_both_credential_reference_kinds() {
        // The reference grammar has exactly two kinds, and the dedicated
        // administration reference can arrive as either. Reusing it on the
        // ingest surface is the same composition mistake through both: every
        // ingest role is refused for a file-kind and an env-kind
        // administration credential alike, with no echo of the reference in
        // either rendering.
        for admin_ref in [ADMIN_REF, ENV_ADMIN_REF] {
            let admin = admin_builder()
                .control_admin_credentials(admin_ref)
                .build()
                .expect("administration configuration validates");
            for (role, builder) in [
                (
                    "raw-writer",
                    valid_builder().raw_write_credentials(admin_ref),
                ),
                (
                    "control-reader",
                    valid_builder().control_read_credentials(admin_ref),
                ),
                (
                    "raw-reader",
                    valid_builder().raw_read_credentials(admin_ref),
                ),
                (
                    "offline-restore",
                    valid_builder().offline_restore_credentials(admin_ref),
                ),
            ] {
                let config = builder.build().unwrap_or_else(|e| panic!("{role}: {e}"));
                let error = config
                    .reject_administration_credential(&admin)
                    .expect_err("this ingest role must be refused");
                assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
                assert_eq!(
                    error.detail(),
                    "an ingest identity is the control-administration credential"
                );
                assert!(
                    !error.to_string().contains(admin_ref),
                    "the refusal must not echo the reference"
                );
                assert!(
                    !format!("{error:?}").contains(admin_ref),
                    "the refusal's debug rendering must not echo the reference"
                );
            }
        }

        // Mixed kinds compose: a file-kind administration credential over
        // env-kind ingest identities is a split deployment, not a collision —
        // the two kinds name different references by construction.
        let file_admin = admin_builder().build().expect("valid");
        let env_ingest = valid_builder()
            .raw_write_credentials("env:RAW_WRITE_CREDENTIAL_TARGET")
            .control_read_credentials("env:CONTROL_READ_CREDENTIAL_TARGET")
            .build()
            .expect("env-kind ingest identities validate");
        env_ingest
            .reject_administration_credential(&file_admin)
            .expect("disjoint kinds are disjoint references");
    }

    #[test]
    fn every_validation_failure_message_is_free_of_credential_material() {
        // Credential-shaped material pushed through every failure path the
        // two surfaces have that involves a credential: a pasted value where
        // a reference belongs, a shared reference across two ingest roles,
        // an ingest role carrying the administration reference, and a
        // missing administration credential. Whatever fails, the rendered
        // error — Display and Debug — carries none of the material, because
        // the detail is a static literal by construction.
        let shared_ref = "file:/run/secrets/SHARED_INGEST_CREDENTIAL";
        let pasted_value = "pasted-credential-value";
        let pasted_env = "env:admin_pasted_secret";
        let material = [
            pasted_value,
            pasted_env,
            shared_ref,
            ADMIN_REF,
            "/run/secrets",
            "SHARED_INGEST_CREDENTIAL",
            "admin_pasted_secret",
            "control-admin-credentials",
        ];
        let admin = admin_builder().build().expect("valid");
        let failures: [(S3ConfigErrorKind, S3ConfigError); 5] = [
            // A pasted value where the raw-writer reference belongs.
            (
                S3ConfigErrorKind::MalformedSetting,
                error_of(valid_builder().raw_write_credentials(pasted_env)),
            ),
            // A pasted value where the administration reference belongs.
            (
                S3ConfigErrorKind::MalformedSetting,
                admin_builder()
                    .control_admin_credentials(pasted_value)
                    .build()
                    .expect_err("a pasted value is not a reference"),
            ),
            // Two storage roles on one shared reference.
            (
                S3ConfigErrorKind::DuplicateIdentity,
                error_of(
                    valid_builder()
                        .raw_write_credentials(shared_ref)
                        .control_read_credentials(shared_ref),
                ),
            ),
            // An ingest role carrying the administration reference.
            (
                S3ConfigErrorKind::DuplicateIdentity,
                valid_builder()
                    .raw_write_credentials(ADMIN_REF)
                    .build()
                    .expect("structurally valid on its own")
                    .reject_administration_credential(&admin)
                    .expect_err("the joint check refuses it"),
            ),
            // No administration credential at all.
            (
                S3ConfigErrorKind::MissingSetting,
                ControlAdminConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .control_bucket(CONTROL_BUCKET)
                    .tenant(ADMIN_TENANT)
                    .build()
                    .expect_err("the credential is required"),
            ),
        ];
        for (expected_kind, error) in failures {
            assert_eq!(error.kind(), expected_kind);
            let text = error.to_string();
            let debug = format!("{error:?}");
            for fragment in material {
                assert!(
                    !text.contains(fragment),
                    "the display rendering echoed credential material: {text}"
                );
                assert!(
                    !debug.contains(fragment),
                    "the debug rendering echoed credential material"
                );
            }
        }
    }

    // ----- control-read configuration surface (aa-7f92223e) -----

    const READ_TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const READ_CLIENT: &str = "9f8e7d6c-5b4a-4938-8271-6a5b4c3d2e1f";
    const READ_REF: &str = "file:/etc/archivist/storage/control-read-credentials";

    fn read_builder() -> ControlReadConfigBuilder {
        ControlReadConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .control_bucket(CONTROL_BUCKET)
            .tenant(READ_TENANT)
            .control_read_credentials(READ_REF)
    }

    #[test]
    fn control_read_configuration_is_its_own_surface() {
        let config = read_builder().build().expect("valid");
        assert_eq!(config.endpoint().as_str(), ENDPOINT);
        assert_eq!(config.tls(), Tls::Enabled, "tls defaults to enabled");
        assert_eq!(config.path_style(), PathStyle::Path, "registry default");
        assert_eq!(config.region(), REGION);
        assert_eq!(config.control_bucket(), CONTROL_BUCKET);
        assert_eq!(config.tenant().as_str(), READ_TENANT);
        assert_eq!(
            config.control_read_credentials().kind(),
            CredentialKind::File
        );
    }

    #[test]
    fn control_read_builder_fails_closed_on_every_absent_setting() {
        let cases: [(ControlReadConfigBuilder, &str); 4] = [
            (ControlReadConfig::builder(), "endpoint url is required"),
            (
                ControlReadConfig::builder().endpoint_url(ENDPOINT),
                "region is required",
            ),
            (
                ControlReadConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .control_bucket(CONTROL_BUCKET),
                "tenant is required",
            ),
            (
                ControlReadConfig::builder()
                    .endpoint_url(ENDPOINT)
                    .region(REGION)
                    .control_bucket(CONTROL_BUCKET)
                    .tenant(READ_TENANT),
                "control-read credential is required",
            ),
        ];
        for (builder, detail) in cases {
            let error = builder.build().expect_err("must fail closed");
            assert_eq!(error.kind(), S3ConfigErrorKind::MissingSetting);
            assert_eq!(error.detail(), detail);
        }
    }

    #[test]
    fn control_read_builder_rejects_values_outside_their_grammar() {
        let tenant_error = read_builder()
            .tenant("not-a-uuid")
            .build()
            .expect_err("tenant must parse");
        assert_eq!(tenant_error.kind(), S3ConfigErrorKind::MalformedSetting);
        assert_eq!(
            tenant_error.detail(),
            "tenant is outside the canonical uuid grammar"
        );

        let credential_error = read_builder()
            .control_read_credentials("plaintext-secret-not-a-reference")
            .build()
            .expect_err("credential must be a reference");
        assert_eq!(credential_error.kind(), S3ConfigErrorKind::MalformedSetting);
        assert_eq!(
            credential_error.detail(),
            "control-read credential is outside the closed grammar"
        );
    }

    #[test]
    fn control_read_builder_rejects_a_transport_disagreement() {
        let error = read_builder()
            .tls(Tls::Disabled)
            .build()
            .expect_err("https endpoint disagrees with disabled tls");
        assert_eq!(error.kind(), S3ConfigErrorKind::TransportMismatch);
    }

    #[test]
    fn control_read_errors_never_echo_the_offending_value() {
        // A credential-shaped value is the one thing that must never reach a
        // message; assert on the value itself, not on the rule that hides it.
        let secret = "AKIAIOSFODNN7EXAMPLESECRETVALUE";
        let error = read_builder()
            .control_read_credentials(secret)
            .build()
            .expect_err("must reject");
        assert!(!error.detail().contains(secret));
        assert!(!format!("{error}").contains(secret));

        let tenant_error = read_builder()
            .tenant("tenant-with-embedded-secret-AKIAIOSFODNN7EXAMPLE")
            .build()
            .expect_err("must reject");
        assert!(!format!("{tenant_error}").contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn control_read_permits_only_this_tenants_control_layouts() {
        let config = read_builder().build().expect("valid");
        let other_tenant = "2b3c4d5e-6f7a-4b2c-8d3e-4f5a6b7c8d9e";

        assert!(
            config.permits_key(&format!(
                "tenants/{READ_TENANT}/v1/control/clients/{READ_CLIENT}.json"
            )),
            "the linked-client layout under this tenant is in scope"
        );

        for denied in [
            // every other tenant, control prefix included
            format!("tenants/{other_tenant}/v1/control/clients/{READ_CLIENT}.json"),
            // the prefixes this identity has no authority over at all
            format!("tenants/{READ_TENANT}/v1/raw/blobs/{READ_CLIENT}.zst"),
            format!("tenants/{READ_TENANT}/v1/catalog/checkpoints/{READ_CLIENT}.json"),
            format!("tenants/{READ_TENANT}/v1/derived/episodes/{READ_CLIENT}.json"),
            format!("tenants/{READ_TENANT}/v1/tombstones/{READ_CLIENT}.json"),
            format!("tenants/{READ_TENANT}/v1/legal-hold/{READ_CLIENT}.json"),
            // a control-layout key with a non-canonical identifier segment is
            // denied rather than normalized
            format!("tenants/{READ_TENANT}/v1/control/clients/not-a-uuid.json"),
        ] {
            assert!(!config.permits_key(&denied), "must deny {denied}");
        }
    }

    #[test]
    fn control_read_rejects_the_administration_credential() {
        let admin = admin_builder()
            .control_admin_credentials(READ_REF)
            .build()
            .expect("valid");
        let config = read_builder().build().expect("valid");

        let error = config
            .reject_administration_credential(&admin)
            .expect_err("the pair states the violation");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert!(
            !format!("{error}").contains(READ_REF),
            "the reference is never echoed"
        );

        // Distinct references are the ordinary, accepted case.
        let distinct = admin_builder().build().expect("valid");
        config
            .reject_administration_credential(&distinct)
            .expect("distinct identities are accepted");
    }

    // ----- scoped-writer pair surface (aa-c0fe28d3) -----
    //
    // The golden identifiers are the scoped-writer boundary suite's own
    // (scoped_write.rs tests), so the pair surface and the standalone
    // halves it hands back tell one story.
    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const TENANT_BUCKET: &str = "archivist-tenant-example";
    const CATALOG_REF: &str = "file:/etc/archivist/storage/catalog-writer-credentials";
    const DERIVED_REF: &str = "file:/etc/archivist/storage/derived-writer-credentials";

    fn scoped_writers_builder() -> ScopedWritersConfigBuilder {
        ScopedWritersConfig::builder()
            .endpoint_url(ENDPOINT)
            .region(REGION)
            .tenant_bucket(TENANT_BUCKET)
            .tenant(TENANT)
            .catalog_write_credentials(CATALOG_REF)
            .derived_write_credentials(DERIVED_REF)
    }

    #[test]
    fn scoped_writers_configuration_builds_the_two_halves() {
        let config = scoped_writers_builder().build().expect("valid");
        let (catalog, derived) = (config.catalog(), config.derived());

        // The catalog half is the validated CatalogWriterConfig of
        // scoped_write.rs: the pair surface's shared settings plus its
        // own dedicated credential reference.
        assert_eq!(catalog.endpoint().as_str(), ENDPOINT);
        assert_eq!(catalog.tls(), Tls::Enabled, "tls defaults to enabled");
        assert_eq!(catalog.path_style(), PathStyle::Path, "registry default");
        assert_eq!(catalog.region(), REGION);
        assert_eq!(catalog.tenant_bucket(), TENANT_BUCKET);
        assert_eq!(catalog.tenant().as_str(), TENANT);
        assert_eq!(
            *catalog.catalog_write_credentials(),
            CredentialReference::parse(CATALOG_REF).expect("the golden reference parses")
        );
        assert_eq!(
            catalog.catalog_write_credentials().kind(),
            CredentialKind::File
        );

        // The derived half is its mirror one namespace over.
        assert_eq!(derived.endpoint().as_str(), ENDPOINT);
        assert_eq!(derived.tls(), Tls::Enabled);
        assert_eq!(derived.path_style(), PathStyle::Path);
        assert_eq!(derived.region(), REGION);
        assert_eq!(derived.tenant_bucket(), TENANT_BUCKET);
        assert_eq!(derived.tenant().as_str(), TENANT);
        assert_eq!(
            *derived.derived_write_credentials(),
            CredentialReference::parse(DERIVED_REF).expect("the golden reference parses")
        );
        assert_eq!(
            derived.derived_write_credentials().kind(),
            CredentialKind::File
        );

        // The valid pair is the disjoint one: two namespaces, two
        // credential references.
        assert_ne!(
            catalog.catalog_write_credentials(),
            derived.derived_write_credentials()
        );
    }

    #[test]
    fn scoped_writers_refuse_a_literal_credential_value() {
        // A pasted value where a writer credential reference belongs is a
        // construction failure of the pair surface — never a store
        // (CFG-032). The delegated gate is the writer surface's own, so
        // the detail names the scoped-writer credential, and neither
        // rendering echoes the pasted value.
        let catalog_paste = "pasted-catalog-writer-credential-value";
        let error = scoped_writers_builder()
            .catalog_write_credentials(catalog_paste)
            .build()
            .expect_err("a literal value is not a reference");
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
        assert_eq!(
            error.detail(),
            "scoped-writer credential is outside the closed grammar"
        );
        assert!(
            !error.to_string().contains(catalog_paste),
            "the display rendering echoed the pasted value"
        );
        assert!(
            !format!("{error:?}").contains(catalog_paste),
            "the debug rendering echoed the pasted value"
        );

        // The same refusal for the derived-writer setting.
        let derived_paste = "pasted-derived-writer-credential-value";
        let error = scoped_writers_builder()
            .derived_write_credentials(derived_paste)
            .build()
            .expect_err("a literal value is not a reference");
        assert_eq!(error.kind(), S3ConfigErrorKind::MalformedSetting);
        assert_eq!(
            error.detail(),
            "scoped-writer credential is outside the closed grammar"
        );
        assert!(
            !error.to_string().contains(derived_paste),
            "the display rendering echoed the pasted value"
        );
        assert!(
            !format!("{error:?}").contains(derived_paste),
            "the debug rendering echoed the pasted value"
        );
    }

    #[test]
    fn scoped_writers_refuse_one_credential_for_both_namespaces() {
        // The one refusal the two halves cannot see on their own: both
        // namespaces mapped onto one credential collapses the authority
        // split the pair exists to keep (plan Section 7.5).
        let shared = "file:/etc/archivist/storage/shared-writer-credentials";
        let error = scoped_writers_builder()
            .catalog_write_credentials(shared)
            .derived_write_credentials(shared)
            .build()
            .expect_err("one credential cannot provision both namespaces");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(
            error.detail(),
            "the two scoped writers share one credential"
        );
        assert!(
            !error.to_string().contains(shared),
            "the display rendering echoed the shared reference"
        );
        assert!(
            !format!("{error:?}").contains(shared),
            "the debug rendering echoed the shared reference"
        );

        // The same violation stated from the catalog half's side: the
        // rule is over the pair, not over one setting.
        let error = scoped_writers_builder()
            .catalog_write_credentials(DERIVED_REF)
            .build()
            .expect_err("one credential cannot provision both namespaces");
        assert_eq!(error.kind(), S3ConfigErrorKind::DuplicateIdentity);
        assert_eq!(
            error.detail(),
            "the two scoped writers share one credential"
        );
        assert!(
            !format!("{error:?}").contains(DERIVED_REF),
            "the debug rendering echoed the shared reference"
        );
    }
}
