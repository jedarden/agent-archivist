// SPDX-License-Identifier: Apache-2.0

//! Strict command-line parsing for the v1 command grammar.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::PathBuf;

use crate::config::{self, ConfigSources, Interactivity};

use super::registry::{Command, Registry};

/// The mode flags parsed before handlers run.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ModeFlags {
    json: bool,
    non_interactive: bool,
    help: bool,
    version: bool,
}

impl ModeFlags {
    /// Whether JSON success and diagnostic framing was requested.
    #[must_use]
    pub const fn json(self) -> bool {
        self.json
    }

    /// Whether non-interactive operation was requested.
    #[must_use]
    pub const fn non_interactive(self) -> bool {
        self.non_interactive
    }

    /// Whether help was requested.
    #[must_use]
    pub const fn help(self) -> bool {
        self.help
    }

    /// Whether top-level version was requested.
    #[must_use]
    pub const fn version(self) -> bool {
        self.version
    }
}

/// The parsed, validated invocation handed to a command handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invocation {
    command_path: Box<[String]>,
    modes: ModeFlags,
    config_path: Option<PathBuf>,
    operands: Box<[String]>,
    operational: BTreeSet<Box<str>>,
    key_flags: BTreeMap<Box<str>, String>,
}

impl Invocation {
    /// The parsed mode flags.
    #[must_use]
    pub const fn modes(&self) -> ModeFlags {
        self.modes
    }

    /// The command path as separate segments.
    #[must_use]
    pub fn command_path(&self) -> &[String] {
        &self.command_path
    }

    /// The command's joined output token.
    #[must_use]
    pub fn command_token(&self) -> String {
        self.command_path.join("-")
    }

    /// The positional operands after closed-kind validation.
    #[must_use]
    pub fn operands(&self) -> &[String] {
        &self.operands
    }

    /// The explicitly selected config path, if one was supplied.
    #[must_use]
    pub fn config_path(&self) -> Option<&std::path::Path> {
        self.config_path.as_deref()
    }

    /// Whether a command-specific boolean flag was supplied.
    #[must_use]
    pub fn has_operational_flag(&self, name: &str) -> bool {
        self.operational.contains(name)
    }

    /// The supplied key-tier values, keyed by their derived flag name.
    pub fn key_flags(&self) -> impl Iterator<Item = (&str, &str)> {
        self.key_flags
            .iter()
            .map(|(name, value)| (name.as_ref(), value.as_str()))
    }

    /// Build the configuration source set for a later library-owned handler.
    #[must_use]
    pub fn config_sources(&self) -> ConfigSources {
        let mut sources = if self.modes.non_interactive {
            ConfigSources::non_interactive()
        } else {
            ConfigSources::interactive()
        };
        if let Some(path) = &self.config_path {
            sources = sources.config_path(path.clone());
        }
        for (name, value) in &self.key_flags {
            sources = sources.flag(name.as_ref(), value.clone());
        }
        sources
    }

    /// Whether this invocation declares interactive configuration behavior.
    #[must_use]
    pub const fn interactivity(&self) -> Interactivity {
        if self.modes.non_interactive {
            Interactivity::NonInteractive
        } else {
            Interactivity::Interactive
        }
    }
}

/// Why strict parsing rejected an invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// No registered command path was supplied.
    MissingCommand,
    /// A command path is not in the registry.
    UnknownCommand,
    /// A flag is not in the applicable mode, key, or operational namespace.
    UnknownFlag,
    /// One flag appeared more than once.
    RepeatedFlag,
    /// A value-taking flag has no value.
    MissingFlagValue,
    /// A top-level-only mode was used with a command.
    VersionWithCommand,
    /// A mode combination is ambiguous.
    AmbiguousModes,
    /// The command received too many or an invalid positional operand.
    OperandViolation,
    /// A required operational flag was omitted.
    RequiredFlagMissing,
    /// An argument was not valid UTF-8.
    NonUtf8Argument,
}

/// A parse failure with enough mode context to frame its diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    kind: ParseErrorKind,
    json: bool,
}

impl ParseError {
    /// The parse failure category.
    #[must_use]
    pub const fn kind(self) -> ParseErrorKind {
        self.kind
    }

    /// Whether stderr must use JSON error framing.
    #[must_use]
    pub const fn json(self) -> bool {
        self.json
    }
}

/// A successful parse, a help/version short-circuit, or a command invocation.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Human-readable registry help, optionally for one command.
    Help(Option<Box<[String]>>),
    /// The top-level version short-circuit.
    Version,
    /// A command invocation ready for routing.
    Command(Invocation),
}

/// Parse one `archivist` argument vector against the pinned registry.
///
/// # Errors
/// Returns a [`ParseError`] for any unknown, repeated, misplaced, or
/// malformed argument.
#[allow(clippy::too_many_lines)]
pub fn parse(args: &[OsString], registry: &Registry) -> Result<Parsed, ParseError> {
    let mut modes = ModeFlags::default();
    let mut config_path = None;
    let mut seen_modes = BTreeSet::new();
    let mut command_words = Vec::new();
    let mut command_flags = Vec::new();
    let mut marker_operands = Vec::new();
    let mut flag_phase = false;
    let mut terminated = false;
    let mut index = 0;
    let mut json_context = args.iter().any(|arg| arg == "--json");

    while index < args.len() {
        let text = args[index].to_str().ok_or(ParseError {
            kind: ParseErrorKind::NonUtf8Argument,
            json: json_context,
        })?;
        if terminated {
            marker_operands.push(text.to_owned());
            index += 1;
            continue;
        }
        if text == "--" {
            terminated = true;
            index += 1;
            continue;
        }
        if text.starts_with("--") {
            if let Some(mode) = text.strip_prefix("--") {
                match mode {
                    "json" | "non-interactive" | "help" | "version" => {
                        if !seen_modes.insert(mode.to_owned()) {
                            return Err(ParseError {
                                kind: ParseErrorKind::RepeatedFlag,
                                json: modes.json || mode == "json" || json_context,
                            });
                        }
                        match mode {
                            "json" => {
                                modes.json = true;
                                json_context = true;
                            }
                            "non-interactive" => modes.non_interactive = true,
                            "help" => modes.help = true,
                            "version" => modes.version = true,
                            _ => {}
                        }
                    }
                    "config" => {
                        if !seen_modes.insert("config".to_owned()) {
                            return Err(ParseError {
                                kind: ParseErrorKind::RepeatedFlag,
                                json: modes.json || json_context,
                            });
                        }
                        let Some(value) = args.get(index + 1) else {
                            return Err(ParseError {
                                kind: ParseErrorKind::MissingFlagValue,
                                json: modes.json || json_context,
                            });
                        };
                        let value = value.to_str().ok_or(ParseError {
                            kind: ParseErrorKind::NonUtf8Argument,
                            json: modes.json || json_context,
                        })?;
                        if value == "--" || value.starts_with('-') {
                            return Err(ParseError {
                                kind: ParseErrorKind::MissingFlagValue,
                                json: modes.json || json_context,
                            });
                        }
                        config_path = Some(PathBuf::from(value));
                        index += 1;
                    }
                    _ => {
                        flag_phase = true;
                        command_flags.push(text.to_owned());
                    }
                }
            } else {
                flag_phase = true;
                command_flags.push(text.to_owned());
            }
        } else if flag_phase {
            command_flags.push(text.to_owned());
        } else {
            command_words.push(text.to_owned());
        }
        index += 1;
    }

    if modes.version {
        if modes.help
            || !command_words.is_empty()
            || !command_flags.is_empty()
            || !marker_operands.is_empty()
        {
            return Err(ParseError {
                kind: if command_words.is_empty() {
                    ParseErrorKind::AmbiguousModes
                } else {
                    ParseErrorKind::VersionWithCommand
                },
                json: modes.json || json_context,
            });
        }
        return Ok(Parsed::Version);
    }

    if command_words.is_empty() {
        if modes.help && command_flags.is_empty() && marker_operands.is_empty() {
            return Ok(Parsed::Help(None));
        }
        return Err(ParseError {
            kind: ParseErrorKind::MissingCommand,
            json: modes.json || json_context,
        });
    }

    let (path, mut operands) = select_command_path(&command_words, registry);
    let Some(command) = registry.command(&path) else {
        return Err(ParseError {
            kind: ParseErrorKind::UnknownCommand,
            json: modes.json || json_context,
        });
    };
    operands.extend(marker_operands);

    let mut operational = BTreeSet::new();
    let mut key_flags = BTreeMap::new();
    let mut seen_command_flags = BTreeSet::new();
    let mut index = 0;
    while index < command_flags.len() {
        let token = &command_flags[index];
        if !token.starts_with("--") || token.len() == 2 || token.contains('=') {
            if token.starts_with('-') {
                return Err(ParseError {
                    kind: ParseErrorKind::UnknownFlag,
                    json: modes.json || json_context,
                });
            }
            operands.push(token.clone());
            index += 1;
            continue;
        }
        let name = &token[2..];
        if !seen_command_flags.insert(name.to_owned()) {
            return Err(ParseError {
                kind: ParseErrorKind::RepeatedFlag,
                json: modes.json || json_context,
            });
        }
        if command.flag(name).is_some() {
            operational.insert(name.to_owned().into_boxed_str());
            index += 1;
            continue;
        }
        let key = config::registry::config_registry()
            .key_by_flag_name(name)
            .filter(|key| key.flag_tier());
        let Some(key) = key else {
            return Err(ParseError {
                kind: ParseErrorKind::UnknownFlag,
                json: modes.json || json_context,
            });
        };
        if !command
            .keys()
            .iter()
            .any(|registered| registered == key.name())
        {
            return Err(ParseError {
                kind: ParseErrorKind::UnknownFlag,
                json: modes.json || json_context,
            });
        }
        let Some(value) = command_flags.get(index + 1) else {
            return Err(ParseError {
                kind: ParseErrorKind::MissingFlagValue,
                json: modes.json || json_context,
            });
        };
        if value.starts_with('-') {
            return Err(ParseError {
                kind: ParseErrorKind::MissingFlagValue,
                json: modes.json || json_context,
            });
        }
        key_flags.insert(name.to_owned().into_boxed_str(), value.clone());
        index += 2;
    }

    if modes.help {
        return Ok(Parsed::Help(Some(path.into_boxed_slice())));
    }
    if modes.version {
        return Err(ParseError {
            kind: ParseErrorKind::VersionWithCommand,
            json: modes.json || json_context,
        });
    }
    for flag in command.flags() {
        if flag.required() && !operational.contains(flag.name()) {
            return Err(ParseError {
                kind: ParseErrorKind::RequiredFlagMissing,
                json: modes.json || json_context,
            });
        }
    }
    if operands.len() > 1 || !valid_operand_count(command, &operands) {
        return Err(ParseError {
            kind: ParseErrorKind::OperandViolation,
            json: modes.json || json_context,
        });
    }
    Ok(Parsed::Command(Invocation {
        command_path: path.into_boxed_slice(),
        modes,
        config_path,
        operands: operands.into_boxed_slice(),
        operational,
        key_flags,
    }))
}

fn select_command_path(words: &[String], registry: &Registry) -> (Vec<String>, Vec<String>) {
    if words.len() >= 2 {
        let two = vec![words[0].clone(), words[1].clone()];
        if registry.command(&two).is_some() {
            return (two, words[2..].to_vec());
        }
    }
    (vec![words[0].clone()], words[1..].to_vec())
}

fn valid_operand_count(command: &Command, operands: &[String]) -> bool {
    match command.operand_kind() {
        "none" => operands.is_empty(),
        "path" => operands.iter().all(|operand| {
            !operand.is_empty() && !operand.starts_with('-') && !operand.contains('\0')
        }),
        "identifier" => operands.iter().all(|operand| {
            !operand.is_empty()
                && operand.len() <= 128
                && operand.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.' | b':')
                        || (index == 0 && byte.is_ascii_uppercase())
                })
        }),
        _ => false,
    }
}
