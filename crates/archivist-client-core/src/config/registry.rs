// SPDX-License-Identifier: Apache-2.0

//! The embedded configuration-key and error-code registries: the binary's
//! in-memory copy of the data `tools/config-keys.toml` and
//! `tools/error-codes.toml` pin (CFG-001, ERR-008).
//!
//! Both files are embedded with `include_str!` rather than restated in
//! Rust, so the committed registry stays the single source of truth: the
//! gate (`tools/check-config.py`, `tools/check-error-codes.py`) validates
//! the committed file, and this module parses the *same bytes* the gate
//! checked. A key the registry does not declare cannot be read from any
//! tier, and a code the registry does not declare cannot be emitted —
//! the register-before-implement discipline, enforced by construction
//! rather than by discipline.
//!
//! Parsing happens once, lazily; failure is unreachable in a built binary
//! (the committed registries are gate-clean and the embedding cannot
//! drift), so the accessors treat a parse failure as the programming
//! error it is. The runtime parse still re-validates shape — schema
//! token, closed attribute set, exactly one of default/required/optional
//! — as defense in depth behind the gate.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use super::toml::{self, Scalar, TomlTable, TomlValue};

/// The committed configuration-key registry, embedded at build time.
const CONFIG_REGISTRY_TEXT: &str = include_str!("../../../../tools/config-keys.toml");

/// The committed error-code registry, embedded at build time.
const ERROR_REGISTRY_TEXT: &str = include_str!("../../../../tools/error-codes.toml");

/// The schema token the configuration registry must declare.
const CONFIG_REGISTRY_SCHEMA: &str = "archivist.config-registry/v1";

/// The schema token the error registry must declare.
const ERROR_REGISTRY_SCHEMA: &str = "archivist.error-registry/v1";

/// The `ARCHIVIST_` prefix every environment-tier name carries (CFG-006).
const ENV_PREFIX: &str = "ARCHIVIST_";

/// The integer unit suffixes and the bounds each fixes (CFG-015). The
/// gate pins the same table; this is the runtime copy the loader
/// validates values against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerSuffix {
    /// `_bytes`: 1 .. 2^48.
    Bytes,
    /// `_seconds`: 1 .. 31,536,000.
    Seconds,
    /// `_percent`: 0 .. 100.
    Percent,
    /// `_count`: 0 .. 2^31−1.
    Count,
    /// `_ratio`: 1 .. 10,000.
    Ratio,
}

impl IntegerSuffix {
    /// The suffix token as it appears in key names.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Seconds => "seconds",
            Self::Percent => "percent",
            Self::Count => "count",
            Self::Ratio => "ratio",
        }
    }

    /// The inclusive bounds the suffix fixes.
    #[must_use]
    pub const fn bounds(self) -> (i64, i64) {
        match self {
            Self::Bytes => (1, 1 << 48),
            Self::Seconds => (1, 31_536_000),
            Self::Percent => (0, 100),
            Self::Count => (0, 2_147_483_647),
            Self::Ratio => (1, 10_000),
        }
    }

    /// The suffix a key name ends in, or [`None`] when the name carries
    /// no registered unit (it cannot be an integer key).
    #[must_use]
    pub fn of_key_name(name: &str) -> Option<Self> {
        let suffix = name.rsplit_once('_')?.1;
        match suffix {
            "bytes" => Some(Self::Bytes),
            "seconds" => Some(Self::Seconds),
            "percent" => Some(Self::Percent),
            "count" => Some(Self::Count),
            "ratio" => Some(Self::Ratio),
            _ => None,
        }
    }
}

/// The closed v1 type set (CFG-014).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyType {
    /// `boolean`.
    Boolean,
    /// `integer`, with the unit suffix that fixes its bounds.
    Integer(IntegerSuffix),
    /// `string` (CFG-016 grammar).
    Text,
    /// `path` (CFG-018 grammar, template expansion at load).
    Path,
    /// `enum`, with the closed value set the registry declares.
    Enum(Vec<Box<str>>),
    /// `reference` (CFG-029 grammar); always secret.
    Reference,
}

/// A raw registry value: the shape a default or example may take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistryValue {
    /// A text value.
    Text(Box<str>),
    /// An integer value.
    Integer(i64),
    /// A boolean value.
    Boolean(bool),
}

impl RegistryValue {
    /// The value as text, if it is one.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The value as an integer, if it is one.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }
}

impl From<&Scalar> for RegistryValue {
    fn from(scalar: &Scalar) -> Self {
        match scalar {
            Scalar::Text(text) => Self::Text(text.clone()),
            Scalar::Integer(value) => Self::Integer(*value),
            Scalar::Boolean(value) => Self::Boolean(*value),
        }
    }
}

/// One registered configuration key: the complete declaration the loader
/// resolves values against (CFG-033's closed per-key shape).
// The booleans are the registry's closed per-key attribute set, pinned
// one-to-one by CFG-033; folding them into packed flags would obscure
// the mapping to the committed TOML they mirror.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug)]
pub struct KeyDefinition {
    name: Box<str>,
    owner: Box<str>,
    key_type: KeyType,
    flag_tier: bool,
    env_tier: bool,
    file_tier: bool,
    secret: bool,
    required: bool,
    optional: bool,
    default: Option<RegistryValue>,
    description: Box<str>,
    #[allow(dead_code)] // carried for completeness; no v1 behavior reads it
    deprecated: bool,
}

impl KeyDefinition {
    /// The key's two-segment name, `section.name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The owning crate.
    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// The key's type.
    #[must_use]
    pub fn key_type(&self) -> &KeyType {
        &self.key_type
    }

    /// Whether the key accepts a flag tier.
    #[must_use]
    pub const fn flag_tier(&self) -> bool {
        self.flag_tier
    }

    /// Whether the key accepts an environment tier.
    #[must_use]
    pub const fn env_tier(&self) -> bool {
        self.env_tier
    }

    /// Whether the key accepts a file tier. Every key does (CFG-031).
    #[must_use]
    pub const fn file_tier(&self) -> bool {
        self.file_tier
    }

    /// Whether the key is a secret reference (the CFG-028 conjunction).
    #[must_use]
    pub const fn secret(&self) -> bool {
        self.secret
    }

    /// Whether the key is required rather than defaulted or optional.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }

    /// Whether the key is an optional secret reference a deployment may
    /// omit: neither required nor defaulted (CFG-019). Absent from every
    /// tier it resolves to nothing; supplied, it validates like any
    /// reference.
    #[must_use]
    pub const fn optional(&self) -> bool {
        self.optional
    }

    /// The declared default, when the key has one.
    #[must_use]
    pub const fn default(&self) -> Option<&RegistryValue> {
        self.default.as_ref()
    }

    /// The one-line description the registry carries.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }

    /// The environment-tier name derived from the key (CFG-006).
    #[must_use]
    pub fn environment_name(&self) -> String {
        format!(
            "{}{}",
            ENV_PREFIX,
            self.name.to_uppercase().replace('.', "_")
        )
    }

    /// The flag-tier name derived from the key (CFG-007).
    #[must_use]
    pub fn flag_name(&self) -> String {
        self.name.replace(['.', '_'], "-")
    }
}

/// The parsed configuration-key registry with its lookup indexes. The
/// derived-name indexes are the runtime expression of CFG-008's
/// injectivity rule: two keys that derive to one environment or flag
/// name cannot coexist, because they cannot both be inserted.
#[derive(Debug)]
pub struct KeyRegistry {
    keys: Vec<KeyDefinition>,
    by_name: BTreeMap<Box<str>, usize>,
    by_environment_name: BTreeMap<String, usize>,
    by_flag_name: BTreeMap<String, usize>,
}

impl KeyRegistry {
    /// Every key, in registry declaration order.
    #[must_use]
    pub fn keys(&self) -> &[KeyDefinition] {
        &self.keys
    }

    /// The definition of `name`, when it is registered.
    #[must_use]
    pub fn key(&self, name: &str) -> Option<&KeyDefinition> {
        self.by_name.get(name).map(|&at| &self.keys[at])
    }

    /// The key an environment-tier name derives from (CFG-006).
    #[must_use]
    pub fn key_by_environment_name(&self, name: &str) -> Option<&KeyDefinition> {
        self.by_environment_name.get(name).map(|&at| &self.keys[at])
    }

    /// The key a flag-tier name derives from (CFG-007).
    #[must_use]
    pub fn key_by_flag_name(&self, name: &str) -> Option<&KeyDefinition> {
        self.by_flag_name.get(name).map(|&at| &self.keys[at])
    }
}

/// The embedded configuration-key registry.
///
/// # Panics
/// Only if the committed registry fails its runtime shape check — which
/// the gate makes unreachable for any committed tree.
#[must_use]
pub fn config_registry() -> &'static KeyRegistry {
    static REGISTRY: OnceLock<KeyRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        parse_config_registry(CONFIG_REGISTRY_TEXT)
            .expect("the committed config-key registry is gate-checked and must parse")
    })
}

/// One error-code registry entry.
#[derive(Clone, Debug)]
pub struct ErrorDefinition {
    code: Box<str>,
    class: Box<str>,
    message: Box<str>,
    description: Box<str>,
}

impl ErrorDefinition {
    /// The stable code, `domain.condition`.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// The code's class.
    #[must_use]
    pub fn class(&self) -> &str {
        &self.class
    }

    /// The registered message template.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The one-line condition description.
    #[must_use]
    pub fn description(&self) -> &str {
        &self.description
    }
}

/// One frozen error class (ERR-006): the attributes the exit path needs.
#[derive(Clone, Debug)]
pub struct ErrorClass {
    name: Box<str>,
    retryable: bool,
    exit_code: i32,
}

impl ErrorClass {
    /// The class name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the class is retryable.
    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.retryable
    }

    /// The process exit code the class allocates (ERR-022).
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

/// The parsed error-code registry.
#[derive(Debug)]
pub struct ErrorRegistry {
    classes: BTreeMap<Box<str>, ErrorClass>,
    codes: BTreeMap<Box<str>, ErrorDefinition>,
}

impl ErrorRegistry {
    /// The definition of `code`, when it is registered.
    #[must_use]
    pub fn code(&self, code: &str) -> Option<&ErrorDefinition> {
        self.codes.get(code)
    }

    /// The class entry `name` declares.
    #[must_use]
    pub fn class(&self, name: &str) -> Option<&ErrorClass> {
        self.classes.get(name)
    }
}

/// The embedded error-code registry.
///
/// # Panics
/// Only if the committed registry fails its runtime shape check — which
/// the gate makes unreachable for any committed tree.
#[must_use]
pub fn error_registry() -> &'static ErrorRegistry {
    static REGISTRY: OnceLock<ErrorRegistry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        parse_error_registry(ERROR_REGISTRY_TEXT)
            .expect("the committed error-code registry is gate-checked and must parse")
    })
}

/// Parse the configuration-key registry, validating its closed shape.
fn parse_config_registry(text: &str) -> Result<KeyRegistry, &'static str> {
    let root = toml::parse(text).map_err(|_| "config-key registry is not parseable")?;
    match root
        .get("schema")
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_text)
    {
        Some(CONFIG_REGISTRY_SCHEMA) => {}
        _ => return Err("config-key registry declares the wrong schema"),
    }
    let keys_table = root
        .get("keys")
        .and_then(TomlValue::as_table)
        .ok_or("config-key registry has no keys table")?;
    let mut keys = Vec::new();
    let mut by_name = BTreeMap::new();
    let mut by_environment_name = BTreeMap::new();
    let mut by_flag_name = BTreeMap::new();
    for (name, entry) in keys_table.iter() {
        let table = entry
            .as_table()
            .ok_or("config-key registry entry is not a table")?;
        let definition = parse_key_entry(name, table)?;
        let environment_name = definition.environment_name();
        let flag_name = definition.flag_name();
        let at = keys.len();
        if by_name.insert(definition.name.clone(), at).is_some()
            || by_environment_name.insert(environment_name, at).is_some()
            || by_flag_name.insert(flag_name, at).is_some()
        {
            return Err("config-key registry derives colliding names");
        }
        keys.push(definition);
    }
    if keys.is_empty() {
        return Err("config-key registry is empty");
    }
    Ok(KeyRegistry {
        keys,
        by_name,
        by_environment_name,
        by_flag_name,
    })
}

/// Parse and shape-check one registry entry (CFG-033's closed attribute
/// set; the exactly-one-of default/required/optional rule; the
/// secret/tier conjunctions).
fn parse_key_entry(name: &str, table: &TomlTable) -> Result<KeyDefinition, &'static str> {
    for attribute in table.iter().map(|(member, _)| member) {
        if !matches!(
            attribute,
            "owner"
                | "type"
                | "tiers"
                | "secret"
                | "default"
                | "required"
                | "optional"
                | "description"
                | "example"
                | "values"
                | "deprecated"
        ) {
            return Err("config-key registry entry carries an unknown attribute");
        }
    }
    let owner = text_attribute(table, "owner")?;
    let type_token = text_attribute(table, "type")?;
    let secret = boolean_attribute(table, "secret")?;
    let required = table
        .get("required")
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_boolean)
        .unwrap_or(false);
    let default = match table.get("default") {
        Some(value) => Some(
            value
                .as_scalar()
                .map(RegistryValue::from)
                .ok_or("config-key default is not a scalar")?,
        ),
        None => None,
    };
    let optional = table
        .get("optional")
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_boolean)
        .unwrap_or(false);
    if optional && (default.is_some() || required) {
        return Err("an optional key carries neither a default nor required");
    }
    if !optional && default.is_some() == required {
        return Err("config-key must declare exactly one of default and required");
    }
    let tiers = text_array_attribute(table, "tiers")?;
    let file_tier = tiers.iter().any(|tier| tier.as_ref() == "file");
    if !file_tier {
        return Err("config-key must include the file tier");
    }
    let flag_tier = tiers.iter().any(|tier| tier.as_ref() == "flag");
    let env_tier = tiers.iter().any(|tier| tier.as_ref() == "env");
    if secret && flag_tier {
        return Err("a secret key never exposes a flag tier");
    }
    if optional && !secret {
        return Err("only a secret reference key may be optional");
    }
    let key_type = match type_token {
        "boolean" => KeyType::Boolean,
        "integer" => KeyType::Integer(
            IntegerSuffix::of_key_name(name).ok_or("an integer key must end in a unit suffix")?,
        ),
        "string" => KeyType::Text,
        "path" => KeyType::Path,
        "enum" => KeyType::Enum(
            text_array_attribute(table, "values")?
                .into_iter()
                .collect::<Vec<_>>(),
        ),
        "reference" => KeyType::Reference,
        _ => return Err("config-key type is outside the closed v1 set"),
    };
    let deprecated = table
        .get("deprecated")
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_boolean)
        .unwrap_or(false);
    Ok(KeyDefinition {
        name: name.into(),
        owner: owner.into(),
        key_type,
        flag_tier,
        env_tier,
        file_tier,
        secret,
        required,
        optional,
        default,
        description: text_attribute(table, "description")?.into(),
        deprecated,
    })
}

/// Parse the error-code registry, validating the closed shape the exit
/// path depends on: every class carries its frozen attributes, every
/// code names a declared class.
fn parse_error_registry(text: &str) -> Result<ErrorRegistry, &'static str> {
    let root = toml::parse(text).map_err(|_| "error-code registry is not parseable")?;
    match root
        .get("schema")
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_text)
    {
        Some(ERROR_REGISTRY_SCHEMA) => {}
        _ => return Err("error-code registry declares the wrong schema"),
    }
    let classes_table = root
        .get("classes")
        .and_then(TomlValue::as_table)
        .ok_or("error-code registry has no classes table")?;
    let mut classes = BTreeMap::new();
    for (name, entry) in classes_table.iter() {
        let table = entry.as_table().ok_or("error class entry is not a table")?;
        let retryable = boolean_attribute(table, "retryable")?;
        let exit_code = match table
            .get("exit")
            .and_then(TomlValue::as_scalar)
            .and_then(Scalar::as_integer)
        {
            Some(code) => i32::try_from(code).map_err(|_| "exit code is outside i32")?,
            None => return Err("error class carries no exit code"),
        };
        classes.insert(
            name.into(),
            ErrorClass {
                name: name.into(),
                retryable,
                exit_code,
            },
        );
    }
    let codes_table = root
        .get("codes")
        .and_then(TomlValue::as_table)
        .ok_or("error-code registry has no codes table")?;
    let mut codes = BTreeMap::new();
    for (code, entry) in codes_table.iter() {
        let table = entry.as_table().ok_or("error code entry is not a table")?;
        let class = text_attribute(table, "class")?;
        if !classes.contains_key(class) {
            return Err("error code names an undeclared class");
        }
        codes.insert(
            code.into(),
            ErrorDefinition {
                code: code.into(),
                class: class.into(),
                message: text_attribute(table, "message")?.into(),
                description: text_attribute(table, "description")?.into(),
            },
        );
    }
    if codes.is_empty() {
        return Err("error-code registry is empty");
    }
    Ok(ErrorRegistry { classes, codes })
}

fn text_attribute<'t>(table: &'t TomlTable, name: &str) -> Result<&'t str, &'static str> {
    table
        .get(name)
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_text)
        .ok_or("registry attribute has the wrong shape")
}

fn boolean_attribute(table: &TomlTable, name: &str) -> Result<bool, &'static str> {
    table
        .get(name)
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_boolean)
        .ok_or("registry attribute has the wrong shape")
}

fn text_array_attribute(table: &TomlTable, name: &str) -> Result<Vec<Box<str>>, &'static str> {
    match table.get(name) {
        Some(TomlValue::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_text()
                    .map(Box::from)
                    .ok_or("registry array carries a non-text element")
            })
            .collect(),
        _ => Err("registry attribute has the wrong shape"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The registry the gate and the docs agree on: the embedded bytes
    /// parse, and every structural rule holds at runtime too.
    #[test]
    fn embedded_config_registry_parses() {
        let registry = config_registry();
        assert!(registry.keys().len() >= 29, "the v1 surface has 29 keys");
        for key in registry.keys() {
            assert_eq!(
                u8::from(key.default().is_some())
                    + u8::from(key.required())
                    + u8::from(key.optional()),
                1,
                "{}: exactly one of default, required, and optional",
                key.name()
            );
            assert!(key.file_tier(), "{}: file tier is universal", key.name());
            assert_eq!(
                key.secret(),
                matches!(key.key_type(), KeyType::Reference),
                "{}: secretness is the reference conjunction",
                key.name()
            );
            if key.secret() {
                assert!(key.name().ends_with("_ref"));
                assert!(!key.flag_tier());
            }
            if let KeyType::Integer(suffix) = key.key_type() {
                assert_eq!(
                    IntegerSuffix::of_key_name(key.name()),
                    Some(*suffix),
                    "{}: suffix matches its type",
                    key.name()
                );
            }
            if let Some(default) = key.default()
                && let Some(value) = default.as_integer()
                && let KeyType::Integer(suffix) = key.key_type()
            {
                let (min, max) = suffix.bounds();
                assert!(
                    (min..=max).contains(&value),
                    "{}: default inside its suffix bounds",
                    key.name()
                );
            }
        }
        // A spot check of one documented key and its derived names.
        let state_dir = registry.key("client.state_dir").expect("state dir key");
        assert_eq!(state_dir.owner(), "archivist-client-core");
        assert_eq!(state_dir.environment_name(), "ARCHIVIST_CLIENT_STATE_DIR");
        assert_eq!(state_dir.flag_name(), "client-state-dir");
        assert!(
            registry
                .key("storage.raw_write_credentials_ref")
                .is_some_and(|key| key.secret() && key.required())
        );
        // The optional roles the storage crate maps but a deployment may
        // omit: registered secret references that are neither required
        // nor defaulted (CFG-019).
        for name in [
            "storage.raw_read_credentials_ref",
            "storage.offline_restore_credentials_ref",
        ] {
            let key = registry
                .key(name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert!(key.secret() && key.optional() && !key.required());
            assert!(!key.flag_tier());
        }
    }

    #[test]
    fn embedded_error_registry_parses() {
        let registry = error_registry();
        for code in [
            "cli.usage_error",
            "cli.decision_missing",
            "client.secret_ref_refused",
        ] {
            let definition = registry
                .code(code)
                .unwrap_or_else(|| panic!("{code} must be registered before the loader emits it"));
            let class = registry
                .class(definition.class())
                .unwrap_or_else(|| panic!("{} class must be declared", definition.class()));
            assert_eq!(class.exit_code(), 64, "{code}: usage class exits 64");
            assert!(!class.retryable());
            assert!(definition.message().len() <= 160);
        }
    }

    #[test]
    fn derived_names_are_injective() {
        let registry = config_registry();
        let mut env_names = std::collections::BTreeSet::new();
        let mut flag_names = std::collections::BTreeSet::new();
        for key in registry.keys() {
            assert!(env_names.insert(key.environment_name()));
            assert!(flag_names.insert(key.flag_name()));
        }
    }
}
