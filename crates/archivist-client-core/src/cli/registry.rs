// SPDX-License-Identifier: Apache-2.0

//! Runtime view of the pinned command registry.
//!
//! The source TOML is embedded rather than copied into Rust. The small
//! closed-subset TOML reader already used by configuration loading parses the
//! same committed bytes that `tools/check-cli.py` validates.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crate::config::toml::{self, Scalar, TomlTable, TomlValue};

const COMMAND_REGISTRY_TEXT: &str = include_str!("../../../../tools/cli-commands.toml");
const REGISTRY_SCHEMA: &str = "archivist.cli-registry/v1";

/// A command-specific boolean flag from the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalFlag {
    name: Box<str>,
    summary: Box<str>,
    required: bool,
}

impl OperationalFlag {
    /// The flag name without its leading `--`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The bounded help summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Whether the command requires this flag.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// One registry command path and its pinned command metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Command {
    path: Box<[String]>,
    summary: Box<str>,
    stdout: Box<str>,
    operand: Box<str>,
    keys: Box<[String]>,
    flags: Box<[OperationalFlag]>,
    result_schema: Option<Box<str>>,
}

impl Command {
    /// The space-separated command path as users type it.
    #[must_use]
    pub fn path(&self) -> &[String] {
        &self.path
    }

    /// The command path in its registry form.
    #[must_use]
    pub fn path_text(&self) -> String {
        self.path.join(" ")
    }

    /// The hyphen-joined output token (CLI-005).
    #[must_use]
    pub fn joined(&self) -> String {
        self.path.join("-")
    }

    /// The bounded registry summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// The pinned stdout kind.
    #[must_use]
    pub fn stdout_kind(&self) -> &str {
        &self.stdout
    }

    /// The pinned positional operand kind.
    #[must_use]
    pub fn operand_kind(&self) -> &str {
        &self.operand
    }

    /// The registered configuration keys consumed by this command.
    #[must_use]
    pub fn keys(&self) -> &[String] {
        &self.keys
    }

    /// The command-specific boolean flags.
    #[must_use]
    pub fn flags(&self) -> &[OperationalFlag] {
        &self.flags
    }

    /// The delegated result schema, when this command has shipped.
    #[must_use]
    pub fn result_schema(&self) -> Option<&str> {
        self.result_schema.as_deref()
    }

    /// Find one operational flag by its bare name.
    #[must_use]
    pub fn flag(&self, name: &str) -> Option<&OperationalFlag> {
        self.flags.iter().find(|flag| flag.name() == name)
    }
}

/// The complete registry view used by parsing, help, and routing.
#[derive(Debug)]
pub struct Registry {
    commands: BTreeMap<Box<str>, Command>,
}

impl Registry {
    /// Return the embedded, gate-checked registry.
    #[must_use]
    ///
    /// # Panics
    /// Panics only if the committed registry fails the same closed-shape
    /// parsing that the repository gate validates.
    pub fn pinned() -> &'static Self {
        static REGISTRY: OnceLock<Registry> = OnceLock::new();
        REGISTRY.get_or_init(|| {
            parse_registry(COMMAND_REGISTRY_TEXT)
                .expect("the committed command registry is gate-checked and must parse")
        })
    }

    /// All commands in joined-token order.
    #[must_use = "iterate over the registered commands"]
    pub fn commands(&self) -> impl Iterator<Item = &Command> {
        self.commands.values()
    }

    /// Look up a command by its space-separated path.
    #[must_use]
    pub fn command(&self, path: &[String]) -> Option<&Command> {
        let text = path.join(" ");
        self.commands.get(text.as_str())
    }

    /// Render human-readable help directly from the registry.
    #[must_use]
    pub fn help(&self, command: Option<&Command>) -> String {
        let mut text = String::new();
        text.push_str("archivist — Agent Archivist command registry\n");
        text.push_str("Registry: tools/cli-commands.toml (archivist.cli-registry/v1)\n\n");
        if let Some(command) = command {
            text.push_str("Usage: archivist [mode flags] ");
            text.push_str(&command.path_text());
            if command.operand_kind() != "none" {
                text.push_str(" OPERAND");
            }
            text.push('\n');
            text.push_str(command.summary());
            text.push('\n');
            for flag in command.flags() {
                text.push_str("  --");
                text.push_str(flag.name());
                if flag.required() {
                    text.push_str(" (required)");
                }
                text.push_str("  ");
                text.push_str(flag.summary());
                text.push('\n');
            }
        } else {
            text.push_str("Usage: archivist [mode flags] <command> [flags] [--] [operand]\n\n");
            text.push_str("Commands:\n");
            for command in self.commands() {
                text.push_str("  ");
                text.push_str(&command.path_text());
                text.push_str("  ");
                text.push_str(command.summary());
                text.push('\n');
            }
        }
        text.push_str("\nMode flags: --json, --non-interactive, --config PATH, --help");
        if command.is_none() {
            text.push_str(", --version");
        }
        text.push('\n');
        text
    }
}

fn table<'a>(value: Option<&'a TomlValue>, what: &str) -> Result<&'a TomlTable, String> {
    value
        .and_then(TomlValue::as_table)
        .ok_or_else(|| format!("{what} is not a table"))
}

fn text(table: &TomlTable, field: &str, what: &str) -> Result<String, String> {
    table
        .get(field)
        .and_then(TomlValue::as_scalar)
        .and_then(Scalar::as_text)
        .map(str::to_owned)
        .ok_or_else(|| format!("{what} is missing text field {field}"))
}

fn optional_boolean(table: &TomlTable, field: &str) -> Result<bool, String> {
    match table.get(field) {
        None => Ok(false),
        Some(value) => value
            .as_scalar()
            .and_then(Scalar::as_boolean)
            .ok_or_else(|| format!("optional field {field} is not boolean")),
    }
}

fn strings(table: &TomlTable, field: &str, what: &str) -> Result<Vec<String>, String> {
    let Some(TomlValue::Array(values)) = table.get(field) else {
        return Err(format!("{what} is missing string array field {field}"));
    };
    values
        .iter()
        .map(|value| match value {
            Scalar::Text(text) => Ok(text.to_string()),
            Scalar::Integer(_) | Scalar::Boolean(_) => {
                Err(format!("{what} field {field} contains a non-string"))
            }
        })
        .collect()
}

fn parse_registry(document: &str) -> Result<Registry, String> {
    // The command registry uses TOML's readable multi-line string arrays for
    // command key lists. The configuration-file reader intentionally accepts
    // only scalar deployment values, so normalize this registry-only form
    // before handing it to that closed reader.
    let mut normalized = String::new();
    let mut in_keys = false;
    for line in document.lines() {
        let trimmed = line.trim();
        if !in_keys && trimmed.starts_with("keys") && trimmed.ends_with('[') {
            in_keys = true;
            normalized.push_str(trimmed);
            normalized.push(' ');
        } else if in_keys {
            if trimmed == "]" {
                in_keys = false;
                while normalized.ends_with(' ') {
                    normalized.pop();
                }
                if normalized.ends_with(',') {
                    normalized.pop();
                }
                normalized.push_str("]\n");
            } else {
                normalized.push_str(trimmed);
                normalized.push(' ');
            }
        } else {
            normalized.push_str(line);
            normalized.push('\n');
        }
    }
    let root = toml::parse(&normalized).map_err(|error| error.to_string())?;
    let schema = text(&root, "schema", "registry")?;
    if schema != REGISTRY_SCHEMA {
        return Err("command registry declares the wrong schema".to_owned());
    }
    let commands_table = table(root.get("commands"), "commands")?;
    let mut commands = BTreeMap::new();
    for (path, value) in commands_table.iter() {
        let entry = table(Some(value), path)?;
        let flags = match entry.get("flags") {
            None => Vec::new(),
            Some(value) => {
                let flag_table = table(Some(value), "flags")?;
                let mut parsed = Vec::new();
                for (name, value) in flag_table.iter() {
                    let flag = table(Some(value), name)?;
                    parsed.push(OperationalFlag {
                        name: name.to_owned().into_boxed_str(),
                        summary: text(flag, "summary", name)?.into_boxed_str(),
                        required: optional_boolean(flag, "required")?,
                    });
                }
                parsed
            }
        };
        let path_parts = path.split(' ').map(str::to_owned).collect::<Vec<_>>();
        if path_parts.is_empty() || path_parts.len() > 2 {
            return Err(format!("command path {path:?} is not one or two segments"));
        }
        let result_schema = entry
            .get("result_schema")
            .map(|value| {
                value
                    .as_scalar()
                    .and_then(Scalar::as_text)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("command {path:?} has an invalid result_schema"))
            })
            .transpose()?
            .map(String::into_boxed_str);
        let command = Command {
            path: path_parts.into_boxed_slice(),
            summary: text(entry, "summary", path)?.into_boxed_str(),
            stdout: text(entry, "stdout", path)?.into_boxed_str(),
            operand: text(entry, "operand", path)?.into_boxed_str(),
            keys: strings(entry, "keys", path)?.into_boxed_slice(),
            flags: flags.into_boxed_slice(),
            result_schema,
        };
        let key = command.path_text().into_boxed_str();
        if commands.insert(key, command).is_some() {
            return Err(format!("duplicate command path {path:?}"));
        }
    }
    if commands.is_empty() {
        return Err("command registry is empty".to_owned());
    }
    Ok(Registry { commands })
}
