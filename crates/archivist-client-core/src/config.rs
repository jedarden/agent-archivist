// SPDX-License-Identifier: Apache-2.0

//! The client configuration loader: XDG-native TOML discovery, the
//! flag/environment/file/default tier precedence, protected secret
//! references, and the stable exit-64 error surface (plan Section 7.9,
//! Phase 5; conventions `docs/notes/configuration.md`).
//!
//! # What the loader guarantees
//!
//! - **One configuration surface.** Every key the loader resolves is an
//!   entry of the embedded [`registry`] copy of `tools/config-keys.toml`
//!   (CFG-001). A name the registry does not declare — from the file
//!   tier, the `ARCHIVIST_` environment namespace, or a flag — is a
//!   usage error, never a warning and never a silent ignore (CFG-012).
//! - **Per-key precedence.** Flag, then environment, then config file,
//!   then the registry default; lower tiers are not merged or reported
//!   (CFG-010). Every *supplied* value in every tier is validated, not
//!   just the winner: a malformed lower-tier value that is shadowed
//!   today becomes the active setting the moment the higher tier is
//!   removed, so it announces itself now (the CFG-012 ethos applied to
//!   values).
//! - **The file tier reads exactly one TOML file** (CFG-011): an
//!   explicit `--config` path (absolute after `HOME` expansion), else
//!   `${XDG_CONFIG_HOME}/archivist/archivist.toml` defaulting under
//!   `HOME` per the XDG specification (CFG-022). A missing default file
//!   is not an error; a selected file that cannot be read or parsed is.
//! - **Secrets are references, resolved lazily and protected.** A
//!   secret-bearing setting is a `file:` or `env:` reference (CFG-028,
//!   CFG-029); it never has a flag tier (CFG-031), and the loader never
//!   resolves it during [`ConfigSources::load`] — `status` must not need
//!   credentials. [`ResolvedConfig::resolve_secret`] resolves on demand
//!   and fails closed: a `file:` target that is not a regular file, that
//!   carries any group or other permission, that is not owner-readable,
//!   that is empty after trimming at most one trailing newline, or that
//!   exceeds the credential size bound is refused (CFG-030), and an
//!   `env:` target that is unset or empty is refused likewise.
//! - **Non-interactive discipline is structural.** This module contains
//!   no prompt and no stdin read on any path — v1 commands do not read
//!   stdin at all (CLI-023) — so a daemon invocation cannot prompt or
//!   consume implicit stdin regardless of configuration (CLI-021,
//!   CFG-026). [`Interactivity`] records the declared invocation mode:
//!   [`ConfigSources::daemon`] is non-interactive by construction, and
//!   in v1 both modes fail a missing required key identically, with
//!   exit 64 and a stable `archivist.error/v1` body naming the field
//!   (CFG-020, CLI-022).
//! - **Diagnostics are content-free.** [`ConfigError`] carries a closed
//!   condition class, an optional field name validated against the
//!   error-body placeholder grammar, and an optional line number — never
//!   a value, a path, or a reference string (CFG-013, CFG-027, ERR-013).
//!   Its [`ConfigError::error_body`] renders the registered template
//!   over the embedded error registry, so the emitted code, retryability,
//!   exit code, and message always agree with `tools/error-codes.toml`.
//!
//! # Ownership
//!
//! The loader resolves *every* registered key, whatever the owning
//! crate, because one configuration file serves a host that runs several
//! commands (CLI-010). Consumers read their own keys back through the
//! typed accessors ([`ResolvedConfig::text`], [`ResolvedConfig::path`],
//! …) and apply any cross-field or URL-grammar validation of their own —
//! the loader validates the registry's per-key contract and nothing
//! above it.

pub mod registry;
pub(crate) mod toml;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod cli_conformance;

use std::collections::BTreeMap;
use std::fmt::{self, Write as _};
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_protocol::json;
use archivist_protocol::vocabulary::RequestId;

use registry::{KeyType, RegistryValue};
use toml::{Scalar, TomlValue};

/// The declared interaction mode of one invocation (CLI-021, CFG-025).
///
/// v1 has no prompt anywhere: no command reads stdin (CLI-023), so the
/// loader never prompts in either mode and a missing required key fails
/// identically in both. The mode is still declared at the call boundary
/// so a daemon cannot accidentally construct an interactive loader, and
/// so a future TTY prompt (CLI-022 allows one for non-secret keys only)
/// has exactly one switch to land on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Interactivity {
    /// A human invocation; in v1 this behaves exactly like
    /// [`Interactivity::NonInteractive`].
    Interactive,
    /// An automated invocation; the only mode a daemon or service may
    /// use.
    NonInteractive,
}

impl Interactivity {
    /// Whether the mode is the non-interactive one.
    #[must_use]
    pub const fn is_non_interactive(self) -> bool {
        matches!(self, Self::NonInteractive)
    }
}

/// The reserved configuration-tier prefix an `env:` target must not use
/// (CFG-029): a secret's channel can never be confused with a
/// configuration key. The same prefix defines the environment namespace
/// the env tier owns (CFG-006).
const RESERVED_ENV_PREFIX: &str = "ARCHIVIST_";

/// Longest accepted `env:` variable name (CFG-029).
const ENV_NAME_MAX: usize = 64;

/// Longest accepted `file:` target path.
const REF_TARGET_MAX: usize = 4096;

/// Upper bound on a resolved credential value: a secret file larger than
/// this is refused rather than read into memory. Real credentials are
/// tens to hundreds of bytes; the bound exists so a mistyped reference
/// to a large file cannot turn into an unbounded read.
const SECRET_MAX_BYTES: usize = 64 * 1024;

/// A parsed, validated secret reference: `file:` with an absolute path
/// or `env:` with an environment-variable name (CFG-029).
///
/// The type holds the *pointer*, never the value. Its [`fmt::Debug`] and
/// [`fmt::Display`] render the kind alone: the `file:` target is
/// operator configuration and appears in no diagnostic (CFG-027), and a
/// reference string is never echoed back.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum SecretRef {
    /// `file:` — a mode-restricted regular file on this host (CFG-030).
    File {
        /// The absolute target path. Never rendered by this type.
        path: Box<Path>,
    },
    /// `env:` — an environment variable on this host. The name is not
    /// secret and is the one target a diagnostic may name.
    Env {
        /// The variable name, matching the pinned grammar.
        name: Box<str>,
    },
}

impl SecretRef {
    /// Parse a reference string, failing closed on anything outside the
    /// pinned grammar (CFG-029):
    ///
    /// - `file:` plus an absolute path whose segments use only
    ///   `[A-Za-z0-9._+-]`, with no `.` or `..` segment and no tilde;
    /// - `env:` plus a name matching `[A-Z][A-Z0-9_]{0,63}` that does
    ///   not start with the reserved `ARCHIVIST_` prefix.
    ///
    /// # Errors
    /// [`ConfigErrorCode::Usage`] for anything else. The malformed
    /// input is not echoed.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        if let Some(path) = text.strip_prefix("file:") {
            return Self::parse_file(path);
        }
        if let Some(name) = text.strip_prefix("env:") {
            return Self::parse_env(name);
        }
        Err(malformed_reference())
    }

    /// Validate and adopt a `file:` target.
    fn parse_file(path: &str) -> Result<Self, ConfigError> {
        // Absolute, no tilde, every segment in the pinned class, no dot
        // segments. A relative path cannot be checked the way CFG-030's
        // mode check requires, so it is refused outright.
        let well_formed = (2..=REF_TARGET_MAX).contains(&path.len())
            && path.starts_with('/')
            && !path.contains('~')
            && path.split('/').skip(1).all(|segment| {
                !segment.is_empty()
                    && segment != "."
                    && segment != ".."
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-')
                    })
            });
        if !well_formed {
            return Err(malformed_reference());
        }
        Ok(Self::File {
            path: PathBuf::from(path).into_boxed_path(),
        })
    }

    /// Validate and adopt an `env:` target.
    fn parse_env(name: &str) -> Result<Self, ConfigError> {
        let well_formed = (1..=ENV_NAME_MAX).contains(&name.len())
            && name
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase())
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && !name.starts_with(RESERVED_ENV_PREFIX);
        if !well_formed {
            return Err(malformed_reference());
        }
        Ok(Self::Env { name: name.into() })
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The path is configuration; naming it in output is
            // forbidden (CFG-027), and Debug output is output.
            Self::File { .. } => f.write_str("SecretRef::file:<redacted>"),
            Self::Env { name } => write!(f, "SecretRef::env:{name}"),
        }
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { .. } => f.write_str("secret-reference(file)"),
            Self::Env { name } => write!(f, "secret-reference(env:{name})"),
        }
    }
}

/// A resolved secret value. The type exposes its bytes to the consumer
/// that asked for them and renders nothing else: [`fmt::Debug`] shows
/// the length only, and there is no [`fmt::Display`].
#[derive(Clone)]
pub struct SecretValue(Box<[u8]>);

impl SecretValue {
    /// The secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The secret length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is empty. Only constructible through
    /// [`ResolvedConfig::resolve_secret`], which refuses empty values —
    /// so a `SecretValue` is never empty and this is always false.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume the value into its bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretValue({} bytes)", self.0.len())
    }
}

/// The registered condition codes the loader emits (ERR-008: each is an
/// entry of `tools/error-codes.toml`, embedded through
/// [`registry::error_registry`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigErrorCode {
    /// `cli.usage_error` — the invocation's arguments, environment, or
    /// configuration file are unusable (CFG-012, CFG-013).
    Usage,
    /// `cli.decision_missing` — a required key resolved from no tier
    /// (CFG-020, CLI-022).
    DecisionMissing,
    /// `client.secret_ref_refused` — a secret reference did not resolve
    /// to protected material (CFG-030).
    SecretRefRefused,
}

impl ConfigErrorCode {
    /// The registered code token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Usage => "cli.usage_error",
            Self::DecisionMissing => "cli.decision_missing",
            Self::SecretRefRefused => "client.secret_ref_refused",
        }
    }
}

/// The closed set of load-time condition details. Static literals only:
/// a configuration error can never echo a value, a path, or a reference
/// string (CFG-013, CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigDetail {
    /// A file, environment, or flag name that derives to no registered
    /// key (CFG-012).
    UnknownKey,
    /// A value that fails its key's type grammar or range (CFG-013).
    MalformedValue,
    /// A value that is not a well-formed `file:`/`env:` reference
    /// (CFG-029).
    MalformedReference,
    /// The same flag supplied twice (CLI-012).
    DuplicateInput,
    /// A tier the key does not accept — the secret-keys-have-no-flags
    /// rule included (CFG-031).
    TierNotAllowed,
    /// The selected configuration file does not exist or cannot be read.
    ConfigFileUnreadable,
    /// The configuration file failed to parse.
    ConfigFileMalformed,
    /// A path value or selection could not expand to an absolute path.
    TemplateUnresolvable,
    /// A required key resolved from no tier (CFG-020).
    DecisionMissing,
    /// A secret reference failed its existence, protection, or
    /// readability check (CFG-030).
    SecretRefused,
    /// `resolve_secret` was asked for a key that is not a secret
    /// reference.
    SecretKeyMismatch,
    /// The process environment is not valid UTF-8.
    EnvironmentUnreadable,
}

impl ConfigDetail {
    const fn text(self) -> &'static str {
        match self {
            Self::UnknownKey => "the name does not belong to a registered configuration key",
            Self::MalformedValue => "the value does not parse or range-check as the key's type",
            Self::MalformedReference => "the value is not a well-formed secret reference",
            Self::DuplicateInput => "the same input was supplied twice",
            Self::TierNotAllowed => "the key does not accept this configuration tier",
            Self::ConfigFileUnreadable => "the selected configuration file could not be read",
            Self::ConfigFileMalformed => {
                "the configuration file is outside the accepted toml grammar"
            }
            Self::TemplateUnresolvable => "a path value could not expand to an absolute path",
            Self::DecisionMissing => "a required key resolved from no tier",
            Self::SecretRefused => "the reference did not resolve to protected material",
            Self::SecretKeyMismatch => "the key is not a secret reference",
            Self::EnvironmentUnreadable => "the process environment is not valid utf-8",
        }
    }
}

/// Why a load or resolution failed: a registered condition code, an
/// optional field name validated against the error-body placeholder
/// grammar, and an optional configuration-file line.
///
/// The type is incapable of carrying a setting value, a filesystem
/// path, or a reference string by construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    code: ConfigErrorCode,
    detail: ConfigDetail,
    field: Option<Box<str>>,
    line: Option<u32>,
}

impl ConfigError {
    fn new(code: ConfigErrorCode, detail: ConfigDetail) -> Self {
        Self {
            code,
            detail,
            field: None,
            line: None,
        }
    }

    fn with_field(mut self, field: &str) -> Self {
        // ERR-013: a field that fails the placeholder grammar is not
        // carried verbatim; the rendered message falls back to the
        // bracketed placeholder name.
        self.field = valid_field(field).map(Box::from);
        self
    }

    fn at_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }

    /// The registered condition code.
    #[must_use]
    pub const fn code(&self) -> ConfigErrorCode {
        self.code
    }

    /// The field the condition names, when it names one and the name
    /// fits the placeholder grammar.
    #[must_use]
    pub fn field(&self) -> Option<&str> {
        self.field.as_deref()
    }

    /// The configuration-file line a parse failure was detected on.
    #[must_use]
    pub const fn line(&self) -> Option<u32> {
        self.line
    }

    /// The process exit code the condition's class allocates (ERR-022):
    /// every loader condition is usage-class, exit 64.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        let error_registry = registry::error_registry();
        error_registry
            .code(self.code.token())
            .and_then(|definition| error_registry.class(definition.class()))
            .map_or(64, registry::ErrorClass::exit_code)
    }

    /// The stable `archivist.error/v1` body for this condition: the
    /// namespace, the registered code, the class retryability, the
    /// rendered registered message, a `null` `request_id` (this is a
    /// client-local condition; ERR-027), and a freshly minted
    /// client-side `correlation_id` (ERR-026). Canonically serializable
    /// with [`ConfigError::error_body_bytes`].
    #[must_use]
    pub fn error_body(&self) -> json::Value {
        let error_registry = registry::error_registry();
        let definition = error_registry.code(self.code.token());
        let retryable = definition
            .and_then(|definition| error_registry.class(definition.class()))
            .is_some_and(registry::ErrorClass::retryable);
        let message = definition.map_or_else(
            || "configuration load failed".to_owned(),
            |definition| render_message(definition.message(), self.field.as_deref()),
        );
        let mut object = json::Object::new();
        object.set("schema", json::Value::Text("archivist.error/v1".to_owned()));
        object.set("code", json::Value::Text(self.code.token().to_owned()));
        object.set("retryable", json::Value::Bool(retryable));
        object.set("message", json::Value::Text(message));
        object.set("request_id", json::Value::Null);
        object.set(
            "correlation_id",
            json::Value::Text(mint_correlation_id().as_str().to_owned()),
        );
        json::Value::Object(object)
    }

    /// The canonical bytes of [`ConfigError::error_body`] — the exact
    /// stderr JSON a `--json` invocation emits for this condition.
    #[must_use]
    pub fn error_body_bytes(&self) -> Vec<u8> {
        self.error_body().canonical_bytes()
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "archivist {}: {}", self.code.token(), self.detail.text())?;
        if let Some(field) = &self.field {
            write!(f, " (field: {field})")?;
        }
        if let Some(line) = self.line {
            write!(f, " (line {line})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigError {}

fn malformed_reference() -> ConfigError {
    ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::MalformedReference)
}

/// The refused-secret error, naming the key that asked (never the
/// target or the value).
fn refused(key: &str) -> ConfigError {
    ConfigError::new(
        ConfigErrorCode::SecretRefRefused,
        ConfigDetail::SecretRefused,
    )
    .with_field(key)
}

/// Whether `text` fits the error-body `field` placeholder grammar
/// (ERR-012): `[a-z0-9_.-]{1,64}`.
pub(crate) fn valid_field(text: &str) -> Option<&str> {
    let well_formed = !text.is_empty()
        && text.len() <= 64
        && text.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
        });
    well_formed.then_some(text)
}

/// Render a registered message template with the `field` placeholder
/// (ERR-013): a missing or grammar-failing field renders as the
/// bracketed placeholder name, and the result is truncated to the
/// rendered-message bound of 200 characters.
pub(crate) fn render_message(template: &str, field: Option<&str>) -> String {
    let rendered = match field.and_then(valid_field) {
        Some(field) => template.replace("{field}", field),
        None => template.replace("{field}", "[field]"),
    };
    if rendered.chars().count() <= 200 {
        rendered
    } else {
        rendered.chars().take(200).collect()
    }
}

/// Mint a client-side correlation identifier (ERR-026): a `UUIDv7` built
/// from the wall clock and host randomness.
///
/// # Panics
/// Never in practice: the minted text is constructed in canonical form
/// and re-validated through the protocol's own grammar as a
/// belt-and-braces check.
// The fallback's final random byte is deliberately the low 8 bits of a
// wider hash mix — narrowing is the point, not a defect.
#[allow(clippy::cast_possible_truncation)]
pub fn mint_correlation_id() -> RequestId {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ms = u64::try_from(now.as_millis()).unwrap_or(u64::MAX);
    let mut random = [0u8; 9];
    if File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut random))
        .is_err()
    {
        // Deterministic-unique fallback when the host has no urandom:
        // nanosecond clock, process id, and a process-local counter.
        use std::sync::atomic::{AtomicU64, Ordering};
        static FALLBACK: AtomicU64 = AtomicU64::new(0);
        let nanos = u64::try_from(now.as_nanos()).unwrap_or(u64::MAX);
        let tick = FALLBACK.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        let mixed = nanos ^ (u64::from(std::process::id()) << 32) ^ tick;
        random[..8].copy_from_slice(&mixed.to_be_bytes());
        random[8] = ((nanos >> 32) ^ tick ^ (mixed >> 17)) as u8;
    }
    // UUIDv7 layout: 48-bit unix millisecond timestamp, version 7,
    // 12-bit rand_a, variant `10`, 62 bits of rand_b.
    let rand_a = (u16::from(random[0]) << 4) | u16::from(random[1] >> 4);
    let bytes = [
        ((ms >> 40) & 0xff) as u8,
        ((ms >> 32) & 0xff) as u8,
        ((ms >> 24) & 0xff) as u8,
        ((ms >> 16) & 0xff) as u8,
        ((ms >> 8) & 0xff) as u8,
        (ms & 0xff) as u8,
        0x70 | ((rand_a >> 8) & 0x0f) as u8,
        (rand_a & 0xff) as u8,
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
        // Writing to a `String` cannot fail.
        let _ = write!(text, "{byte:02x}");
    }
    RequestId::parse(&text).expect("the minted identifier is canonical uuid v7")
}

/// The configuration file selection (CFG-011): `--config PATH` when
/// given, otherwise the XDG default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum ConfigFileSelection {
    /// The XDG default location (CFG-022).
    #[default]
    Default,
    /// An explicitly selected file, absolute after `HOME` expansion.
    Explicit(PathBuf),
}

/// The unvalidated tier inputs under assembly. The CLI hands over flag
/// tokens it parsed (CFG-007 forms, with or without the `--`); the
/// environment arrives as a snapshot so loading is deterministic and
/// testable; the file tier is a path selection, read at load.
#[derive(Clone, Debug)]
pub struct ConfigSources {
    interactivity: Interactivity,
    env: BTreeMap<String, String>,
    flags: Vec<(String, String)>,
    config_file: ConfigFileSelection,
}

impl ConfigSources {
    /// An interactive invocation with no inputs yet.
    #[must_use]
    pub fn interactive() -> Self {
        Self {
            interactivity: Interactivity::Interactive,
            env: BTreeMap::new(),
            flags: Vec::new(),
            config_file: ConfigFileSelection::Default,
        }
    }

    /// A non-interactive invocation with no inputs yet.
    #[must_use]
    pub fn non_interactive() -> Self {
        Self {
            interactivity: Interactivity::NonInteractive,
            ..Self::interactive()
        }
    }

    /// A daemon invocation: non-interactive by construction, with the
    /// process environment captured (CLI-021 — a service invocation can
    /// never be made interactive by forgetting the flag).
    ///
    /// # Errors
    /// [`ConfigErrorCode::Usage`] when the process environment carries a
    /// name or value that is not valid UTF-8.
    pub fn daemon() -> Result<Self, ConfigError> {
        Self::non_interactive().capture_environment()
    }

    /// Record one flag-tier input: the flag token as written (a leading
    /// `--` is accepted and stripped) and its value text. Validated
    /// against the registry at load; repetition is refused there
    /// (CLI-012).
    #[must_use]
    pub fn flag(mut self, token: &str, value: impl Into<String>) -> Self {
        self.flags.push((token.to_owned(), value.into()));
        self
    }

    /// Record or override one environment variable in the snapshot.
    /// Later calls win, which is what synthetic tests and embedding
    /// harnesses want; the XDG/`HOME` variables the path tier expands
    /// come from the same snapshot (CFG-009).
    #[must_use]
    pub fn env(mut self, name: &str, value: impl Into<String>) -> Self {
        self.env.insert(name.to_owned(), value.into());
        self
    }

    /// Capture the process environment into the snapshot, replacing any
    /// previously recorded variables.
    ///
    /// # Errors
    /// [`ConfigErrorCode::Usage`] when a name or value is not valid
    /// UTF-8 — fail closed rather than guessing at a mojibake setting.
    pub fn capture_environment(mut self) -> Result<Self, ConfigError> {
        let mut env = BTreeMap::new();
        for (name, value) in std::env::vars_os() {
            let unreadable =
                || ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::EnvironmentUnreadable);
            let name = name.into_string().map_err(|_| unreadable())?;
            let value = value.into_string().map_err(|_| unreadable())?;
            env.insert(name, value);
        }
        self.env = env;
        Ok(self)
    }

    /// Select the configuration file explicitly (CFG-011). The path is
    /// used as given; `~/` expands against `HOME` at load, and the
    /// result must be absolute.
    #[must_use]
    pub fn config_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.config_file = ConfigFileSelection::Explicit(path.into());
        self
    }

    /// The declared interaction mode.
    #[must_use]
    pub const fn interactivity(&self) -> Interactivity {
        self.interactivity
    }

    /// Resolve every registered key against the tiers.
    ///
    /// # Errors
    /// [`ConfigErrorCode::Usage`] for an unrecognized name in any tier,
    /// a malformed or out-of-bounds value in any supplied tier, a
    /// repeated flag, or an unusable configuration file;
    /// [`ConfigErrorCode::DecisionMissing`] for a required key that no
    /// tier supplied. Nothing prompts and nothing reads stdin.
    pub fn load(&self) -> Result<ResolvedConfig, ConfigError> {
        let registry = registry::config_registry();
        let file_values = self.file_values(registry)?;
        let env_values = self.env_values(registry)?;
        let flag_values = self.flag_values(registry)?;

        let mut values = BTreeMap::new();
        for definition in registry.keys() {
            let name = definition.name();
            let tiers = [
                flag_values
                    .get(name)
                    .map(|value| Input::Text(value.as_str())),
                env_values
                    .get(name)
                    .map(|value| Input::Text(value.as_str())),
                file_values.get(name).map(Input::Toml),
            ];
            // Every supplied tier validates, winner or not (CFG-010's
            // per-key rule with CFG-012's strictness): a malformed
            // value that is shadowed today announces itself now.
            for tier in tiers.iter().copied().flatten() {
                resolve_value(definition, &tier, self).map_err(|error| error.with_field(name))?;
            }
            match tiers.into_iter().flatten().next() {
                Some(input) => {
                    let value = resolve_value(definition, &input, self)
                        .map_err(|error| error.with_field(name))?;
                    values.insert(name.into(), value);
                }
                None => match definition.default() {
                    Some(default) => {
                        let value = resolve_default(definition, default, self)
                            .map_err(|error| error.with_field(name))?;
                        values.insert(name.into(), value);
                    }
                    None if definition.required() => {
                        return Err(ConfigError::new(
                            ConfigErrorCode::DecisionMissing,
                            ConfigDetail::DecisionMissing,
                        )
                        .with_field(name));
                    }
                    None => {}
                },
            }
        }
        Ok(ResolvedConfig {
            values,
            env: self
                .env
                .iter()
                .map(|(name, value)| (name.as_str().into(), value.as_str().into()))
                .collect(),
        })
    }

    /// The file tier: locate, read, and parse the one TOML file, then
    /// require every path it defines to be a registered key (CFG-012).
    fn file_values(
        &self,
        registry: &registry::KeyRegistry,
    ) -> Result<BTreeMap<String, TomlValue>, ConfigError> {
        let (path, selected) = match &self.config_file {
            ConfigFileSelection::Explicit(path) => (Some(expand_config_path(path, self)?), true),
            // Neither variable resolving a default location is not an
            // error: the file tier is absent, and any *key* that needed
            // those variables reports its own named failure instead.
            ConfigFileSelection::Default => (self.default_config_path(), false),
        };
        let Some(path) = path else {
            return Ok(BTreeMap::new());
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            // A default file that is simply absent leaves the tier
            // empty (CFG-011: only `--config` makes a file mandatory);
            // a default file that exists but cannot be read is refused.
            Err(_) if !selected && !path.exists() => return Ok(BTreeMap::new()),
            Err(_) => {
                return Err(ConfigError::new(
                    ConfigErrorCode::Usage,
                    ConfigDetail::ConfigFileUnreadable,
                ));
            }
        };
        let root = toml::parse(&text).map_err(|error| {
            ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::ConfigFileMalformed)
                .at_line(error.line)
        })?;
        let mut flat: BTreeMap<String, TomlValue> = BTreeMap::new();
        flatten_table("", &root, &mut flat);
        let mut values = BTreeMap::new();
        for (name, value) in flat {
            if registry.key(&name).is_none() {
                return Err(
                    ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::UnknownKey)
                        .with_field(&name),
                );
            }
            values.insert(name, value);
        }
        Ok(values)
    }

    /// The environment tier: every `ARCHIVIST_*` name must derive from a
    /// registered key that accepts the environment tier (CFG-006,
    /// CFG-012).
    fn env_values(
        &self,
        registry: &registry::KeyRegistry,
    ) -> Result<BTreeMap<String, String>, ConfigError> {
        let mut values = BTreeMap::new();
        for (name, value) in &self.env {
            let Some(rest) = name.strip_prefix(RESERVED_ENV_PREFIX) else {
                continue;
            };
            match registry.key_by_environment_name(name) {
                Some(definition) if definition.env_tier() => {
                    values.insert(definition.name().to_owned(), value.clone());
                }
                // A registered key that excludes the environment tier
                // cannot appear there either: the derivation is the
                // only sanctioned spelling (CFG-006).
                Some(_) => {
                    return Err(ConfigError::new(
                        ConfigErrorCode::Usage,
                        ConfigDetail::TierNotAllowed,
                    )
                    .with_field(&name.to_lowercase()));
                }
                None => {
                    return Err(
                        ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::UnknownKey)
                            .with_field(&rest.to_lowercase()),
                    );
                }
            }
        }
        Ok(values)
    }

    /// The flag tier: each token must derive from a registered key that
    /// accepts a flag tier, and no token may repeat (CFG-007, CFG-031,
    /// CLI-012).
    fn flag_values(
        &self,
        registry: &registry::KeyRegistry,
    ) -> Result<BTreeMap<String, String>, ConfigError> {
        let mut values = BTreeMap::new();
        for (token, value) in &self.flags {
            let bare = token.strip_prefix("--").unwrap_or(token);
            match registry.key_by_flag_name(bare) {
                Some(definition) if definition.flag_tier() => {
                    if values.contains_key(definition.name()) {
                        return Err(ConfigError::new(
                            ConfigErrorCode::Usage,
                            ConfigDetail::DuplicateInput,
                        )
                        .with_field(definition.name()));
                    }
                    values.insert(definition.name().to_owned(), value.clone());
                }
                // A secret key has no flag tier, so this branch also
                // refuses `--storage-raw-write-credentials-ref` and
                // every other secret spelling (CFG-031, CLI-024).
                Some(_) => {
                    return Err(ConfigError::new(
                        ConfigErrorCode::Usage,
                        ConfigDetail::TierNotAllowed,
                    )
                    .with_field(bare));
                }
                None => {
                    return Err(
                        ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::UnknownKey)
                            .with_field(&bare.to_lowercase()),
                    );
                }
            }
        }
        Ok(values)
    }

    /// The default configuration file location (CFG-022):
    /// `${XDG_CONFIG_HOME}/archivist/archivist.toml`, defaulting under
    /// `HOME` per the XDG specification.
    fn default_config_path(&self) -> Option<PathBuf> {
        self.xdg_home_dir("XDG_CONFIG_HOME", ".config")
            .map(|base| base.join("archivist").join("archivist.toml"))
    }

    /// One XDG base directory: the variable when it is set to an
    /// absolute path (a non-absolute value is ignored per the
    /// specification), else the given default under `HOME`.
    fn xdg_home_dir(&self, variable: &str, default_suffix: &str) -> Option<PathBuf> {
        if let Some(value) = self.env.get(variable)
            && Path::new(value).is_absolute()
        {
            return Some(PathBuf::from(value));
        }
        self.home().map(|home| home.join(default_suffix))
    }

    fn home(&self) -> Option<PathBuf> {
        self.env
            .get("HOME")
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
    }
}

/// A tier value awaiting validation: text from the flag or environment
/// tier, a parsed TOML value from the file tier.
#[derive(Clone, Copy)]
enum Input<'a> {
    /// Raw text as supplied.
    Text(&'a str),
    /// A parsed file-tier value.
    Toml(&'a TomlValue),
}

/// Recursively flatten a parsed file into dotted key names. Only the
/// two-segment CFG-005 shape can be registered; deeper tables flatten to
/// names the unknown-key check refuses.
fn flatten_table(prefix: &str, table: &toml::TomlTable, out: &mut BTreeMap<String, TomlValue>) {
    for (name, value) in table.iter() {
        let path = if prefix.is_empty() {
            name.to_owned()
        } else {
            format!("{prefix}.{name}")
        };
        match value {
            TomlValue::Table(nested) => flatten_table(&path, nested, out),
            other => {
                out.insert(path, other.clone());
            }
        }
    }
}

/// Expand an explicitly selected configuration path (CFG-011): a
/// leading `~` or `~/` expands against `HOME`, and the result must be
/// absolute.
fn expand_config_path(path: &Path, sources: &ConfigSources) -> Result<PathBuf, ConfigError> {
    let text = path.to_string_lossy();
    let expanded = if let Some(rest) = text.strip_prefix("~/") {
        let home = sources.home().ok_or_else(|| {
            ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::TemplateUnresolvable)
        })?;
        home.join(rest)
    } else if text == "~" {
        sources.home().ok_or_else(|| {
            ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::TemplateUnresolvable)
        })?
    } else {
        path.to_path_buf()
    };
    if !expanded.is_absolute() {
        return Err(ConfigError::new(
            ConfigErrorCode::Usage,
            ConfigDetail::TemplateUnresolvable,
        ));
    }
    Ok(expanded)
}

/// One resolved, validated value for a registered key.
#[derive(Clone, Debug, PartialEq)]
pub enum ResolvedValue {
    /// A boolean.
    Boolean(bool),
    /// An integer inside its suffix bounds.
    Integer(i64),
    /// A string or enum token (CFG-016 grammar).
    Text(Box<str>),
    /// An absolute path, template-expanded (CFG-018).
    Path(Box<Path>),
    /// A secret reference (CFG-029 grammar), unresolved.
    Reference(SecretRef),
}

/// The outcome of [`ConfigSources::load`]: every registered key resolved
/// from its winning tier, with the environment snapshot retained for
/// lazy secret resolution.
///
/// No secret value is held here — not even resolved. Callers that need
/// secret material ask for it by key and receive the checks of CFG-030
/// on the way out.
#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    values: BTreeMap<Box<str>, ResolvedValue>,
    env: BTreeMap<Box<str>, Box<str>>,
}

impl ResolvedConfig {
    /// The resolved value of `key`.
    #[must_use]
    pub fn value(&self, key: &str) -> Option<&ResolvedValue> {
        self.values.get(key)
    }

    /// The resolved value of `key` as a boolean.
    #[must_use]
    pub fn boolean(&self, key: &str) -> Option<bool> {
        match self.value(key) {
            Some(ResolvedValue::Boolean(value)) => Some(*value),
            _ => None,
        }
    }

    /// The resolved value of `key` as an integer inside its bounds.
    #[must_use]
    pub fn integer(&self, key: &str) -> Option<i64> {
        match self.value(key) {
            Some(ResolvedValue::Integer(value)) => Some(*value),
            _ => None,
        }
    }

    /// The resolved value of `key` as text (string or enum token).
    #[must_use]
    pub fn text(&self, key: &str) -> Option<&str> {
        match self.value(key) {
            Some(ResolvedValue::Text(value)) => Some(value),
            _ => None,
        }
    }

    /// The resolved value of `key` as an absolute path.
    #[must_use]
    pub fn path(&self, key: &str) -> Option<&Path> {
        match self.value(key) {
            Some(ResolvedValue::Path(value)) => Some(value),
            _ => None,
        }
    }

    /// The resolved value of `key` as an unresolved secret reference.
    #[must_use]
    pub fn reference(&self, key: &str) -> Option<&SecretRef> {
        match self.value(key) {
            Some(ResolvedValue::Reference(value)) => Some(value),
            _ => None,
        }
    }

    /// Iterate every resolved key and value in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &ResolvedValue)> {
        self.values
            .iter()
            .map(|(name, value)| (name.as_ref(), value))
    }

    /// Resolve the secret `key` names, enforcing CFG-030 on the way:
    /// the `file:` target must be a regular file with no group or other
    /// permission and an owner-read bit, bounded in size, non-empty
    /// after trimming at most one trailing newline; the `env:` target
    /// must be set and non-empty. Nothing is echoed on failure — the
    /// error names the key and the condition class only.
    ///
    /// # Errors
    /// [`ConfigErrorCode::SecretRefRefused`] when the target fails its
    /// existence, protection, or readability check;
    /// [`ConfigErrorCode::Usage`] when `key` is not a secret reference
    /// key.
    pub fn resolve_secret(&self, key: &str) -> Result<SecretValue, ConfigError> {
        let Some(ResolvedValue::Reference(reference)) = self.value(key) else {
            return Err(
                ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::SecretKeyMismatch)
                    .with_field(key),
            );
        };
        let bytes = match reference {
            SecretRef::File { path } => read_protected_file(path, key)?,
            SecretRef::Env { name } => {
                let value: Option<&str> =
                    self.env.get(name.as_ref()).map(std::convert::AsRef::as_ref);
                match value {
                    Some(value) if !value.is_empty() && value.len() <= SECRET_MAX_BYTES => {
                        value.as_bytes().to_vec()
                    }
                    _ => return Err(refused(key)),
                }
            }
        };
        if bytes.is_empty() {
            return Err(refused(key));
        }
        Ok(SecretValue(bytes.into()))
    }
}

/// Read a `file:` secret target with the mode check against the opened
/// file itself — the bytes read are the bytes checked (CFG-030).
#[cfg(unix)]
fn read_protected_file(path: &Path, key: &str) -> Result<Vec<u8>, ConfigError> {
    use std::os::unix::fs::PermissionsExt;

    let mut file = File::open(path).map_err(|_| refused(key))?;
    let metadata = file.metadata().map_err(|_| refused(key))?;
    if !metadata.is_file() || metadata.len() > SECRET_MAX_BYTES as u64 {
        return Err(refused(key));
    }
    // 0600 or stricter: any group or other permission bit is a refusal,
    // and the running user must hold the read bit.
    let mode = metadata.permissions().mode();
    if (mode & 0o077) != 0 || (mode & 0o400) == 0 {
        return Err(refused(key));
    }
    let mut value = Vec::new();
    file.read_to_end(&mut value).map_err(|_| refused(key))?;
    if value.len() > SECRET_MAX_BYTES {
        return Err(refused(key));
    }
    if value.last() == Some(&b'\n') {
        value.pop();
    }
    Ok(value)
}

/// Without POSIX permission bits there is no protection to verify, so
/// the reference is refused rather than trusted (CFG-030).
#[cfg(not(unix))]
fn read_protected_file(_path: &Path, key: &str) -> Result<Vec<u8>, ConfigError> {
    Err(refused(key))
}

/// Validate one tier input against a key's registered type and produce
/// the resolved value (CFG-013, CFG-014 through CFG-018, CFG-029).
fn resolve_value(
    definition: &registry::KeyDefinition,
    input: &Input<'_>,
    sources: &ConfigSources,
) -> Result<ResolvedValue, ConfigError> {
    let malformed = || ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::MalformedValue);
    match definition.key_type() {
        KeyType::Boolean => match input {
            Input::Text("true") => Ok(ResolvedValue::Boolean(true)),
            Input::Text("false") => Ok(ResolvedValue::Boolean(false)),
            Input::Toml(TomlValue::Scalar(Scalar::Boolean(value))) => {
                Ok(ResolvedValue::Boolean(*value))
            }
            _ => Err(malformed()),
        },
        KeyType::Integer(suffix) => {
            // Text tiers accept plain decimal; the file tier's parsed
            // integer is the same value by construction.
            let value = match input {
                Input::Text(text) => text.parse::<i64>().ok(),
                Input::Toml(TomlValue::Scalar(Scalar::Integer(value))) => Some(*value),
                Input::Toml(_) => None,
            }
            .ok_or_else(malformed)?;
            let (min, max) = suffix.bounds();
            if !(min..=max).contains(&value) {
                return Err(malformed());
            }
            Ok(ResolvedValue::Integer(value))
        }
        KeyType::Text => {
            let text = scalar_text(input).ok_or_else(malformed)?;
            check_string(text).ok_or_else(malformed)?;
            Ok(ResolvedValue::Text(text.into()))
        }
        KeyType::Path => {
            let text = scalar_text(input).ok_or_else(malformed)?;
            let path = expand_path_value(text, sources).ok_or_else(malformed)?;
            Ok(ResolvedValue::Path(path.into_boxed_path()))
        }
        KeyType::Enum(values) => {
            let text = scalar_text(input).ok_or_else(malformed)?;
            if !values.iter().any(|value| value.as_ref() == text) {
                return Err(malformed());
            }
            Ok(ResolvedValue::Text(text.into()))
        }
        KeyType::Reference => {
            let text = scalar_text(input).ok_or_else(malformed)?;
            let reference = SecretRef::parse(text).map_err(|_| malformed())?;
            Ok(ResolvedValue::Reference(reference))
        }
    }
}

/// Validate a registry default. Defaults re-enter through the same text
/// grammar the tiers validate against, so a registry regression is a
/// named load failure rather than a silent divergence.
fn resolve_default(
    definition: &registry::KeyDefinition,
    value: &RegistryValue,
    sources: &ConfigSources,
) -> Result<ResolvedValue, ConfigError> {
    let malformed = || ConfigError::new(ConfigErrorCode::Usage, ConfigDetail::MalformedValue);
    match value {
        // A text default re-enters through the tier grammar so a registry
        // regression cannot smuggle a value past validation.
        RegistryValue::Text(text) => resolve_value(definition, &Input::Text(text), sources),
        RegistryValue::Integer(number) => match definition.key_type() {
            KeyType::Integer(suffix) => {
                let (min, max) = suffix.bounds();
                if (min..=max).contains(number) {
                    Ok(ResolvedValue::Integer(*number))
                } else {
                    Err(malformed())
                }
            }
            _ => Err(malformed()),
        },
        RegistryValue::Boolean(flag) => match definition.key_type() {
            KeyType::Boolean => Ok(ResolvedValue::Boolean(*flag)),
            _ => Err(malformed()),
        },
    }
}

/// The text of a scalar input; integers and booleans are not text, and
/// arrays are not scalars (no v1 key type accepts either).
fn scalar_text<'a>(input: &Input<'a>) -> Option<&'a str> {
    match input {
        Input::Text(text) => Some(text),
        Input::Toml(TomlValue::Scalar(Scalar::Text(text))) => Some(text),
        Input::Toml(_) => None,
    }
}

/// The registry string grammar (CFG-016): printable ASCII, at most 128
/// characters, no braces, and not empty.
fn check_string(text: &str) -> Option<()> {
    let well_formed = !text.is_empty()
        && text.len() <= 128
        && text.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        && !text.contains(['{', '}']);
    well_formed.then_some(())
}

/// Expand a `path`-typed value (CFG-018): a leading XDG/`HOME` template
/// variable followed by an absolute suffix (or alone), or a literal
/// absolute path. Tilde shorthand, relative paths, and empty, `.`, or
/// `..` segments are rejected — in the value and in the expansion.
fn expand_path_value(text: &str, sources: &ConfigSources) -> Option<PathBuf> {
    if text.contains('~') {
        return None;
    }
    let joined = if let Some(rest) = text.strip_prefix("${") {
        let (name, suffix) = rest.split_once('}')?;
        let base = match name {
            "XDG_CONFIG_HOME" => sources.xdg_home_dir("XDG_CONFIG_HOME", ".config"),
            "XDG_STATE_HOME" => sources.xdg_home_dir("XDG_STATE_HOME", ".local/state"),
            "XDG_DATA_HOME" => sources.xdg_home_dir("XDG_DATA_HOME", ".local/share"),
            "XDG_CACHE_HOME" => sources.xdg_home_dir("XDG_CACHE_HOME", ".cache"),
            "HOME" => sources.home(),
            _ => return None,
        }?;
        if suffix.is_empty() {
            base
        } else {
            let suffix = suffix.strip_prefix('/')?;
            if !clean_segments(suffix) {
                return None;
            }
            base.join(suffix)
        }
    } else {
        if !text.starts_with('/') || !clean_segments(&text[1..]) {
            return None;
        }
        PathBuf::from(text)
    };
    if !joined.is_absolute() {
        return None;
    }
    // Defense in depth: an expanded base carrying a parent hop from the
    // environment is as unusable as one written in the value.
    joined
        .components()
        .all(|component| matches!(component, Component::Normal(_) | Component::RootDir))
        .then_some(joined)
}

/// Path segments after the root: non-empty, and neither `.` nor `..`.
fn clean_segments(text: &str) -> bool {
    text.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

// --- typed accessors for the client-engine keys -------------------------
//
// `load` resolves every registered key, and each of these keys carries a
// registry default, so the accessors are total by construction; the
// expects name the invariant, not a runtime condition.

impl ResolvedConfig {
    /// The client state directory root (`client.state_dir`).
    ///
    /// # Panics
    /// Only if `client.state_dir` did not resolve — impossible in a
    /// config this load returned, because the key carries a registry
    /// default.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        self.path("client.state_dir")
            .expect("client.state_dir always resolves from its default")
    }

    /// The spool high-water cap (`spool.max_bytes`).
    ///
    /// # Panics
    /// Only if `spool.max_bytes` did not resolve — impossible in a
    /// config this load returned, because the key carries a registry
    /// default.
    #[must_use]
    pub fn spool_max_bytes(&self) -> i64 {
        self.integer("spool.max_bytes")
            .expect("spool.max_bytes always resolves from its default")
    }

    /// The filesystem free-space floor (`spool.free_floor_bytes`).
    ///
    /// # Panics
    /// Only if `spool.free_floor_bytes` did not resolve — impossible in
    /// a config this load returned, because the key carries a registry
    /// default.
    #[must_use]
    pub fn spool_free_floor_bytes(&self) -> i64 {
        self.integer("spool.free_floor_bytes")
            .expect("spool.free_floor_bytes always resolves from its default")
    }

    /// The cap-utilization resume point (`spool.resume_percent`).
    ///
    /// # Panics
    /// Only if `spool.resume_percent` did not resolve — impossible in a
    /// config this load returned, because the key carries a registry
    /// default.
    #[must_use]
    pub fn spool_resume_percent(&self) -> i64 {
        self.integer("spool.resume_percent")
            .expect("spool.resume_percent always resolves from its default")
    }

    /// The daemon loop period (`schedule.interval_seconds`).
    ///
    /// # Panics
    /// Only if `schedule.interval_seconds` did not resolve — impossible
    /// in a config this load returned, because the key carries a
    /// registry default.
    #[must_use]
    pub fn schedule_interval_seconds(&self) -> i64 {
        self.integer("schedule.interval_seconds")
            .expect("schedule.interval_seconds always resolves from its default")
    }

    /// The scheduling jitter bound (`schedule.jitter_percent`).
    ///
    /// # Panics
    /// Only if `schedule.jitter_percent` did not resolve — impossible
    /// in a config this load returned, because the key carries a
    /// registry default.
    #[must_use]
    pub fn schedule_jitter_percent(&self) -> i64 {
        self.integer("schedule.jitter_percent")
            .expect("schedule.jitter_percent always resolves from its default")
    }

    /// The per-source backfill quantum (`schedule.backfill_quantum_bytes`).
    ///
    /// # Panics
    /// Only if `schedule.backfill_quantum_bytes` did not resolve —
    /// impossible in a config this load returned, because the key
    /// carries a registry default.
    #[must_use]
    pub fn schedule_backfill_quantum_bytes(&self) -> i64 {
        self.integer("schedule.backfill_quantum_bytes")
            .expect("schedule.backfill_quantum_bytes always resolves from its default")
    }

    /// The ingestion endpoint URL (`ingest.endpoint_url`).
    ///
    /// # Panics
    /// Only if `ingest.endpoint_url` did not resolve — impossible in a
    /// config this load returned, because the key is required and a
    /// missing value fails the load itself.
    #[must_use]
    pub fn ingest_endpoint_url(&self) -> &str {
        self.text("ingest.endpoint_url")
            .expect("ingest.endpoint_url is required and always resolves on success")
    }
}
