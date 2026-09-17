// SPDX-License-Identifier: Apache-2.0

//! CLI cross-registry and process-behavior conformance (CLI-002, CLI-031).
//!
//! Three registries pin the command surface — the command registry
//! (`tools/cli-commands.toml`), the configuration-key registry
//! (`tools/config-keys.toml`), and the error-code registry
//! (`tools/error-codes.toml`) — and CLI-002 requires that they agree. The
//! fast-lane gate (`tools/check-cli.py`) proves that agreement over the
//! committed files; this suite re-proves it from the binary's side, over the
//! same committed bytes the runtime embeds, so the runtime's own view cannot
//! drift from the gate's:
//!
//! 1. the command registry parses under its closed v1 shape and every
//!    command carries the attributes generated help needs (CLI-003,
//!    CLI-017);
//! 2. every key a command consumes is registered and every registered key
//!    is consumed — checked against the *runtime*
//!    [`registry::config_registry`], the parsed [`include_str!`] bytes the
//!    loader resolves tiers against, not a second copy (CLI-010, CFG-001);
//! 3. the three flag namespaces — mode flags, key-derived flags,
//!    operational flags — stay pairwise disjoint (CLI-008 through CLI-012);
//! 4. the exit mappings the CLI contract names hold: usage exits 64 carrying
//!    the two registered usage conditions, lock contention exits 75 carrying
//!    `client.lock_held`, and no class claims exit 0 or the `128+n` signal
//!    range (CLI-007, CLI-018, CLI-020, CLI-022) — against both the raw
//!    bytes and the runtime [`registry::error_registry`];
//! 5. the output envelope schema agrees with the command registry: the
//!    joined-form command token accepts every registered command and still
//!    refuses unregistered shapes (CLI-005, CLI-014);
//! 6. the loader's own conditions stay registered — the code tokens
//!    [`ConfigErrorCode`] names exist in the committed registry, and a real
//!    load failure exits on the class the registry allocates, names its
//!    field, renders the registered message, and emits the canonical
//!    one-value stderr body a `--json` invocation promises (CLI-022,
//!    ERR-029);
//! 7. `daemon` is non-interactive by construction (CLI-021).
//!
//! Negative fixtures mutate copies of the committed registries — an
//! unregistered command, flag, key, or error condition — and fail unless
//! every mutation is rejected, mirroring the gate's `--self-test` suite on
//! the runtime side: the rejection paths are proven, not assumed (the
//! CLI-030 ethos).
//!
//! The command and error registries are read by the minimal line-oriented
//! reader below, scoped to the closed v1 shapes those files pin; anything
//! outside the subset fails the parse loudly rather than mis-reading a
//! registry edit. The configuration-key registry is deliberately *not*
//! re-parsed: the runtime registry parsed from the same embedded bytes is
//! the thing under test, and a second parse of identical bytes would prove
//! nothing about the embedder.

use std::collections::{BTreeMap, BTreeSet};

use archivist_protocol::json;

use super::registry::{self, error_registry};
use super::{ConfigErrorCode, ConfigSources, Interactivity};

/// The committed command registry, the same bytes the gate checks.
const COMMAND_REGISTRY_TEXT: &str = include_str!("../../../../tools/cli-commands.toml");

/// The committed error-code registry, the same bytes the runtime embeds.
const ERROR_REGISTRY_TEXT: &str = include_str!("../../../../tools/error-codes.toml");

/// The committed output-envelope schema, the same bytes the gate validates.
const ENVELOPE_SCHEMA_TEXT: &str = include_str!("../../../../schemas/v1/cli-output.json");

/// The committed common schema, for the `generated_at` reference target.
const COMMON_SCHEMA_TEXT: &str = include_str!("../../../../schemas/v1/common.json");

// ---------------------------------------------------------------------------
// Pinned constants — the same values tools/check-cli.py pins, cited by the
// cli.md rules they carry. A drift between the two implementations is a
// conformance failure this suite exists to catch.
// ---------------------------------------------------------------------------

/// The mode flags (CFG-003, CLI-009) with whether each takes a value;
/// exactly one does, and it is a path.
const MODE_FLAGS: [(&str, bool); 5] = [
    ("non-interactive", false),
    ("json", false),
    ("config", true),
    ("help", false),
    ("version", false),
];

/// The closed per-command attribute values (CLI-006, CLI-027).
const STATE_LOCKS: [&str; 3] = ["exclusive", "read_only", "none"];
/// The closed stdout kinds (CLI-016).
const STDOUT_KINDS: [&str; 2] = ["document", "none"];
/// The closed operand kinds (CLI-025).
const OPERAND_KINDS: [&str; 3] = ["none", "path", "identifier"];
/// The closed stdin kinds (CLI-023).
const STDIN_KINDS: [&str; 2] = ["none", "payload"];

/// The plan phases a command may name (the gate's `PHASE_BOUNDS`).
const PHASE_RANGE: (i64, i64) = (2, 11);
/// The longest bounded summary (the gate's `SUMMARY_MAX`).
const SUMMARY_MAX: usize = 160;
/// The usage-class exit the CLI contract names (CLI-008, CLI-022).
const USAGE_EXIT: i32 = 64;
/// The lock-contention exit the CLI contract names (CLI-007).
const LOCK_EXIT: i32 = 75;
/// The success exit no class may claim (CLI-018).
const SUCCESS_EXIT: i64 = 0;
/// The floor of the `128+n` signal range no class may enter (CLI-020).
const SIGNAL_EXIT_FLOOR: i64 = 128;
/// The usage class the CLI contract exits on.
const USAGE_CLASS: &str = "usage";
/// The lock-contention class the CLI contract exits on.
const LOCK_CLASS: &str = "lock_contention";
/// The usage-class code tokens the CLI contract exits on (CLI-008, CLI-022).
const USAGE_CODES: [&str; 2] = ["cli.usage_error", "cli.decision_missing"];
/// The lock-contention code token (CLI-007).
const LOCK_CODE: &str = "client.lock_held";
/// The envelope's namespace constant (CLI-014).
const OUTPUT_NAMESPACE: &str = "archivist.cli-output/v1";
/// The envelope schema's `$id`.
const ENVELOPE_SCHEMA_ID: &str = "urn:agent-archivist:schema:v1:cli-output";
/// The `generated_at` reference the envelope resolves (CLI-014).
const TIMESTAMP_REF: &str = "urn:agent-archivist:schema:v1:common#/$defs/rfc3339-utc-timestamp";
/// The four envelope members and no others (CLI-014).
const ENVELOPE_MEMBERS: [&str; 4] = ["schema", "command", "generated_at", "result"];
/// The command-token grammar bound the envelope schema pins (CLI-005).
const COMMAND_TOKEN_MAX: usize = 64;
/// A command path segment's grammar bound (CLI-004).
const SEGMENT_MAX: usize = 32;
/// An operational flag name's grammar bound (CLI-011).
const FLAG_NAME_MAX: usize = 64;

// ---------------------------------------------------------------------------
// A minimal reader for the registries' closed v1 shape: section headers with
// quoted segments, scalar fields, and one-line or multi-line scalar arrays.
// Anything else is a loud parse failure, never a silent mis-read.
// ---------------------------------------------------------------------------

/// One scalar as the registries may store it.
#[derive(Clone, Debug, PartialEq)]
enum Scalar {
    /// A basic string.
    Text(String),
    /// A TOML integer.
    Integer(i64),
    /// `true` or `false`.
    Boolean(bool),
}

/// A field value: one scalar or an array of scalars.
#[derive(Clone, Debug, PartialEq)]
enum FieldValue {
    /// A single scalar.
    One(Scalar),
    /// An array of scalars.
    Many(Vec<Scalar>),
}

impl FieldValue {
    /// The value as text, when it is a single text scalar.
    fn text(&self) -> Option<&str> {
        match self {
            Self::One(Scalar::Text(text)) => Some(text),
            Self::One(Scalar::Integer(_) | Scalar::Boolean(_)) | Self::Many(_) => None,
        }
    }

    /// The value as an integer, when it is one.
    fn integer(&self) -> Option<i64> {
        match self {
            Self::One(Scalar::Integer(value)) => Some(*value),
            Self::One(Scalar::Text(_) | Scalar::Boolean(_)) | Self::Many(_) => None,
        }
    }

    /// The value as a boolean, when it is one.
    fn boolean(&self) -> Option<bool> {
        match self {
            Self::One(Scalar::Boolean(value)) => Some(*value),
            Self::One(Scalar::Text(_) | Scalar::Integer(_)) | Self::Many(_) => None,
        }
    }

    /// The value as a text array, when every element is text.
    fn text_array(&self) -> Option<Vec<&str>> {
        match self {
            Self::Many(items) => items
                .iter()
                .map(|item| match item {
                    Scalar::Text(text) => Some(text.as_str()),
                    Scalar::Integer(_) | Scalar::Boolean(_) => None,
                })
                .collect(),
            Self::One(_) => None,
        }
    }
}

/// One table's direct fields, keyed by its header path.
struct Section {
    /// The header segments; empty for the document root.
    path: Vec<String>,
    /// The direct `key = value` fields in document order.
    fields: Vec<(String, FieldValue)>,
}

/// Parse a header's inner text (`commands."admin approve".flags`) into its
/// segments: bare segments end at `.`; quoted segments may carry any bytes.
fn split_header(inner: &str) -> Result<Vec<String>, String> {
    let mut segments = Vec::new();
    let mut chars = inner.chars().peekable();
    loop {
        while matches!(chars.peek(), Some(' ')) {
            chars.next();
        }
        let segment = if chars.peek() == Some(&'"') {
            chars.next();
            let mut text = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some(found) => text.push(found),
                    None => return Err("unterminated quoted header segment".to_owned()),
                }
            }
            text
        } else {
            let mut text = String::new();
            while let Some(&found) = chars.peek() {
                if found == '.' {
                    break;
                }
                text.push(found);
                chars.next();
            }
            text.trim().to_owned()
        };
        if segment.is_empty() {
            return Err("empty header segment".to_owned());
        }
        segments.push(segment);
        match chars.next() {
            None => break,
            Some('.') => {}
            Some(found) => return Err(format!("unexpected {found:?} in a table header")),
        }
    }
    Ok(segments)
}

/// Parse one scalar token: a basic string, an integer, or a boolean.
fn parse_scalar(token: &str) -> Result<Scalar, String> {
    if let Some(rest) = token.strip_prefix('"') {
        let Some(body) = rest.strip_suffix('"') else {
            return Err("unterminated string".to_owned());
        };
        let mut text = String::new();
        let mut escaped = false;
        for found in body.chars() {
            match (escaped, found) {
                (false, '\\') => escaped = true,
                (true, '"' | '\\') => {
                    text.push(found);
                    escaped = false;
                }
                (true, _) => return Err("unsupported string escape".to_owned()),
                (false, _) => text.push(found),
            }
        }
        if escaped {
            return Err("dangling string escape".to_owned());
        }
        return Ok(Scalar::Text(text));
    }
    if token == "true" {
        return Ok(Scalar::Boolean(true));
    }
    if token == "false" {
        return Ok(Scalar::Boolean(false));
    }
    token
        .parse::<i64>()
        .map(Scalar::Integer)
        .map_err(|_| format!("unsupported scalar {token:?}"))
}

/// Split an inline array body on commas that sit outside quoted strings.
fn split_array_items(body: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for found in body.chars() {
        match (found, quoted) {
            ('"', _) => {
                quoted = !quoted;
                current.push(found);
            }
            (',', false) => {
                items.push(current.trim().to_owned());
                current.clear();
            }
            (_, _) => current.push(found),
        }
    }
    let tail = current.trim();
    if !tail.is_empty() {
        items.push(tail.to_owned());
    }
    items.retain(|item| !item.is_empty());
    items
}

/// Parse one field's value: an inline scalar, an inline array, or a
/// multi-line array whose items continue over `lines` until the closing
/// bracket.
fn parse_field_value(rest: &str, lines: &mut std::str::Lines<'_>) -> Result<FieldValue, String> {
    if rest == "[]" {
        return Ok(FieldValue::Many(Vec::new()));
    }
    if let Some(body) = rest.strip_prefix('[').and_then(|b| b.strip_suffix(']')) {
        let items = split_array_items(body)
            .iter()
            .map(|item| parse_scalar(item))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(FieldValue::Many(items));
    }
    if rest.starts_with('[') {
        let mut items = Vec::new();
        loop {
            let Some(raw) = lines.next() else {
                return Err("unterminated array".to_owned());
            };
            let item = raw.trim();
            if item == "]" {
                break;
            }
            let item = item.strip_suffix(',').unwrap_or(item);
            if item.is_empty() || item.starts_with('#') {
                continue;
            }
            items.push(parse_scalar(item)?);
        }
        return Ok(FieldValue::Many(items));
    }
    parse_scalar(rest).map(FieldValue::One)
}

/// Parse a registry document into its sections. Full-line comments and blank
/// lines are skipped; the registries carry no trailing comments, and one
/// would fail the scalar grammar loudly rather than be mis-read.
fn parse_sections(document: &str) -> Result<Vec<Section>, String> {
    let mut sections = Vec::new();
    let mut current = Section {
        path: Vec::new(),
        fields: Vec::new(),
    };
    let mut lines = document.lines();
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[') {
            let Some(inner) = inner.strip_suffix(']') else {
                return Err("unterminated table header".to_owned());
            };
            sections.push(current);
            current = Section {
                path: split_header(inner)?,
                fields: Vec::new(),
            };
            continue;
        }
        let Some((key, rest)) = line.split_once('=') else {
            return Err(format!("line outside any field grammar: {line:?}"));
        };
        let key = key.trim().to_owned();
        let value = parse_field_value(rest.trim(), &mut lines)?;
        current.fields.push((key, value));
    }
    sections.push(current);
    Ok(sections)
}

/// One field of a section, failing the lookup with the section's label when
/// absent.
fn field<'a>(section: &'a Section, name: &str, label: &str) -> Result<&'a FieldValue, String> {
    section
        .fields
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value)
        .ok_or_else(|| format!("{label} is missing {name}"))
}

/// One field of a section as text, failing when absent or another kind.
fn text_field(section: &Section, name: &str, label: &str) -> Result<String, String> {
    field(section, name, label)?
        .text()
        .map(str::to_owned)
        .ok_or_else(|| format!("{label}: {name} is not text"))
}

/// Reject a field set that leaves the registry's closed shape (CLI-027).
fn check_closed_fields(
    section: &Section,
    required: &[&str],
    optional: &[&str],
    label: &str,
) -> Result<(), String> {
    for name in required {
        if !section.fields.iter().any(|(key, _)| key == name) {
            return Err(format!("{label} is missing required {name}"));
        }
    }
    for (key, _) in &section.fields {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(format!("{label} carries unknown attribute {key}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The command registry model and its validators.
// ---------------------------------------------------------------------------

/// One registered operational flag (CLI-011).
#[derive(Clone, Debug)]
struct OperationalFlag {
    /// The flag name as invoked (`once`, `from-occurrences`).
    name: String,
    /// The bounded summary generated help prints.
    summary: String,
    /// Whether invoking the command without the flag is a usage error.
    required: bool,
}

/// One registered command (CLI-006).
#[derive(Clone, Debug)]
struct Command {
    /// The command path segments (`["catalog", "rebuild"]`).
    path: Vec<String>,
    /// The bounded summary generated help prints.
    summary: String,
    /// The implementing plan phase.
    phase: i64,
    /// The owning workspace crate.
    owner: String,
    /// The state-lock relationship (CLI-007).
    state_lock: String,
    /// The stdout kind (CLI-016).
    stdout: String,
    /// The operand kind (CLI-025).
    operand: String,
    /// The stdin kind (CLI-023).
    stdin: String,
    /// The consumed configuration keys (CLI-010).
    keys: Vec<String>,
    /// The operational flags, in registry order.
    flags: Vec<OperationalFlag>,
    /// The attached result schema, when the command has shipped one (CLI-015).
    result_schema: Option<String>,
}

impl Command {
    /// The command path as text (`catalog rebuild`).
    fn path_text(&self) -> String {
        self.path.join(" ")
    }

    /// The joined-form output token (CLI-005): each segment's internal
    /// blanks become hyphens (`admin approve` → `admin-approve`).
    fn joined(&self) -> String {
        self.path
            .iter()
            .map(|segment| segment.replace(' ', "-"))
            .collect::<Vec<_>>()
            .join("-")
    }
}

/// Build the command registry from its committed bytes, enforcing the closed
/// section and attribute shapes as the parse goes.
fn command_registry(document: &str) -> Result<Vec<Command>, String> {
    const COMMAND_REQUIRED: [&str; 8] = [
        "summary", "phase", "owner", "state_lock", "stdout", "operand", "stdin", "keys",
    ];
    const COMMAND_OPTIONAL: [&str; 3] = ["flags", "result_schema", "deprecated"];
    const FLAG_REQUIRED: [&str; 1] = ["summary"];
    const FLAG_OPTIONAL: [&str; 1] = ["required"];

    let sections = parse_sections(document)?;
    let (root, body) = sections
        .split_first()
        .ok_or_else(|| "empty registry document".to_owned())?;
    check_closed_fields(root, &["schema"], &[], "the registry root")?;
    if root.fields.first().and_then(|(_, value)| value.text())
        != Some("archivist.cli-registry/v1")
    {
        return Err(
            "the registry root does not declare schema archivist.cli-registry/v1".to_owned()
        );
    }

    let mut commands: Vec<Command> = Vec::new();
    for section in body {
        let label = section.path.join(".");
        match section.path.as_slice() {
            [head, name] if head == "commands" => {
                check_closed_fields(section, &COMMAND_REQUIRED, &COMMAND_OPTIONAL, &label)?;
                let keys = field(section, "keys", &label)?
                    .text_array()
                    .ok_or_else(|| format!("{label}: keys is not an array of strings"))?
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                let result_schema = match section.fields.iter().find(|(key, _)| key == "result_schema")
                {
                    Some((_, value)) => Some(
                        value
                            .text()
                            .ok_or_else(|| format!("{label}: result_schema is not text"))?
                            .to_owned(),
                    ),
                    None => None,
                };
                commands.push(Command {
                    path: vec![name.clone()],
                    summary: text_field(section, "summary", &label)?,
                    phase: field(section, "phase", &label)?
                        .integer()
                        .ok_or_else(|| format!("{label}: phase is not an integer"))?,
                    owner: text_field(section, "owner", &label)?,
                    state_lock: text_field(section, "state_lock", &label)?,
                    stdout: text_field(section, "stdout", &label)?,
                    operand: text_field(section, "operand", &label)?,
                    stdin: text_field(section, "stdin", &label)?,
                    keys,
                    flags: Vec::new(),
                    result_schema,
                });
            }
            [head, name, kind, flag] if head == "commands" && kind == "flags" => {
                check_closed_fields(section, &FLAG_REQUIRED, &FLAG_OPTIONAL, &label)?;
                let required = match section.fields.iter().find(|(key, _)| key == "required") {
                    Some((_, value)) => value
                        .boolean()
                        .ok_or_else(|| format!("{label}: required is not a boolean"))?,
                    None => false,
                };
                let command = commands
                    .iter_mut()
                    .find(|command| {
                        command.path.len() == 1 && command.path[0] == *name
                    })
                    .ok_or_else(|| format!("[{label}] arrives before its command"))?;
                command.flags.push(OperationalFlag {
                    name: flag.clone(),
                    summary: text_field(section, "summary", &label)?,
                    required,
                });
            }
            _ => return Err(format!("unexpected section [{label}]")),
        }
    }
    Ok(commands)
}

/// Whether `text` matches the lowercase-hyphen grammar the CLI pins, within
/// `max_chars` characters: `^[a-z][a-z0-9-]{0,bound}$`.
fn grammar_ok(text: &str, max_chars: usize) -> bool {
    let mut count = 0usize;
    for (index, found) in text.chars().enumerate() {
        let allowed = if index == 0 {
            found.is_ascii_lowercase()
        } else {
            found.is_ascii_lowercase() || found.is_ascii_digit() || found == '-'
        };
        if !allowed {
            return false;
        }
        count += 1;
    }
    count > 0 && count <= max_chars
}

/// Whether a command path segment is blank-separated words each matching
/// the lowercase grammar (a two-word subcommand like `link request`),
/// within `max_chars` characters.
fn segment_ok(segment: &str, max_chars: usize) -> bool {
    segment.chars().count() <= max_chars
        && !segment.is_empty()
        && segment.split(' ').all(|word| grammar_ok(word, max_chars))
}

/// Whether every byte is printable ASCII (the gate's `STRING_RE` domain).
fn printable(text: &str) -> bool {
    text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Whether a summary is non-empty, printable, and within the bound.
fn summary_ok(summary: &str) -> bool {
    !summary.is_empty()
        && printable(summary)
        && summary.chars().count() <= SUMMARY_MAX
}

/// Validate the command registry's own shape (CLI-004 through CLI-006,
/// CLI-011, CLI-015, CLI-025, CLI-027): grammar, bounds, closed kinds,
/// joined-form uniqueness, flag summaries, and the result-schema rule.
fn validate_commands(commands: &[Command]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut joined_forms: BTreeMap<String, String> = BTreeMap::new();
    for command in commands {
        let label = command.path_text();
        if command.path.is_empty() || command.path.len() > 2 {
            violations.push(format!("{label}: a command path is one or two segments"));
        }
        for segment in &command.path {
            if !segment_ok(segment, SEGMENT_MAX) {
                violations.push(format!(
                    "{label}: segment {segment:?} leaves the command grammar"
                ));
            }
        }
        if !grammar_ok(&command.joined(), COMMAND_TOKEN_MAX) {
            violations.push(format!(
                "{label}: joined form {:?} leaves the output-token grammar",
                command.joined()
            ));
        }
        if let Some(previous) = joined_forms.get(&command.joined()) {
            violations.push(format!(
                "{label}: joined form {} collides with {previous}",
                command.joined()
            ));
        } else {
            joined_forms.insert(command.joined(), label.clone());
        }
        if !summary_ok(&command.summary) {
            violations.push(format!("{label}: summary leaves the bounded printable shape"));
        }
        if !(command.phase >= PHASE_RANGE.0 && command.phase <= PHASE_RANGE.1) {
            violations.push(format!("{label}: phase {} leaves the plan range", command.phase));
        }
        if !grammar_ok(&command.owner, FLAG_NAME_MAX) {
            violations.push(format!(
                "{label}: owner {:?} leaves the crate-name grammar",
                command.owner
            ));
        }
        if !STATE_LOCKS.contains(&command.state_lock.as_str()) {
            violations.push(format!(
                "{label}: state_lock {:?} is not a registered kind",
                command.state_lock
            ));
        }
        if !STDOUT_KINDS.contains(&command.stdout.as_str()) {
            violations.push(format!(
                "{label}: stdout {:?} is not a registered kind",
                command.stdout
            ));
        }
        if !OPERAND_KINDS.contains(&command.operand.as_str()) {
            violations.push(format!(
                "{label}: operand {:?} is not a registered kind",
                command.operand
            ));
        }
        if !STDIN_KINDS.contains(&command.stdin.as_str()) {
            violations.push(format!(
                "{label}: stdin {:?} is not a registered kind",
                command.stdin
            ));
        }
        let mut seen = BTreeSet::new();
        for key in &command.keys {
            if !seen.insert(key.as_str()) {
                violations.push(format!("{label}: key {key} appears twice in the command's list"));
            }
        }
        if command.stdout != "document" && command.result_schema.is_some() {
            violations.push(format!(
                "{label}: a result schema may attach only to a stdout-document command"
            ));
        }
        if let Some(schema) = &command.result_schema
            && !(schema.starts_with("schemas/v1/")
                && std::path::Path::new(schema)
                    .extension()
                    .is_some_and(|extension| extension.to_str() == Some("json")))
        {
            violations.push(format!("{label}: result schema {schema:?} leaves schemas/v1/"));
        }
        for flag in &command.flags {
            if !grammar_ok(&flag.name, FLAG_NAME_MAX) {
                violations.push(format!(
                    "{label}: flag {:?} leaves the flag-name grammar",
                    flag.name
                ));
            }
            if !summary_ok(&flag.summary) {
                violations.push(format!(
                    "{label}: flag {} leaves the bounded summary shape",
                    flag.name
                ));
            }
        }
    }
    violations
}

/// Validate the three flag namespaces against each other (CLI-008 through
/// CLI-012): operational flags are globally unique and disjoint from the
/// mode-flag set and from every key-derived flag name.
fn validate_flag_namespaces(commands: &[Command], key_flag_names: &BTreeSet<String>) -> Vec<String> {
    let mut violations = Vec::new();
    let mode_names: BTreeSet<&str> = MODE_FLAGS.iter().map(|(name, _)| *name).collect();
    let mut operational: BTreeMap<String, String> = BTreeMap::new();
    for command in commands {
        for flag in &command.flags {
            let label = command.path_text();
            if mode_names.contains(flag.name.as_str()) {
                violations.push(format!(
                    "{label}: operational flag {} invades the mode-flag namespace",
                    flag.name
                ));
            }
            if key_flag_names.contains(&flag.name) {
                violations.push(format!(
                    "{label}: operational flag {} invades the key-flag namespace",
                    flag.name
                ));
            }
            if let Some(previous) = operational.get(&flag.name) {
                violations.push(format!(
                    "{label}: operational flag {} is already registered on {previous}",
                    flag.name
                ));
            } else {
                operational.insert(flag.name.clone(), label.clone());
            }
        }
    }
    for name in mode_names {
        if key_flag_names.contains(name) {
            violations.push(format!("key-flag namespace invades the mode flag --{name}"));
        }
    }
    violations
}

/// Validate command-to-key consumption in both directions (CLI-002, CLI-010,
/// CFG-001): every consumed key is registered, every registered key is
/// consumed by at least one command.
fn validate_key_consumption(commands: &[Command], registered: &BTreeSet<String>) -> Vec<String> {
    let mut violations = Vec::new();
    let mut consumed: BTreeSet<&str> = BTreeSet::new();
    for command in commands {
        for key in &command.keys {
            if !registered.contains(key) {
                violations.push(format!(
                    "{}: consumes unregistered key {key}",
                    command.path_text()
                ));
            }
            consumed.insert(key);
        }
    }
    for key in registered {
        if !consumed.contains(key.as_str()) {
            violations.push(format!("registered key {key} is consumed by no command"));
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// The error registry model and the exit-mapping validator.
// ---------------------------------------------------------------------------

/// One registered class, narrowed to what the CLI contract cites.
#[derive(Clone, Debug)]
struct ClassRow {
    /// The class name.
    name: String,
    /// The process exit the class allocates.
    exit: i64,
    /// Whether the class is retryable.
    retryable: bool,
}

/// One registered condition code and its class.
#[derive(Clone, Debug)]
struct CodeRow {
    /// The code token.
    name: String,
    /// The class that allocates its behavior.
    class: String,
}

/// Parse the error registry into its class and code rows.
fn error_registry_rows(document: &str) -> Result<(Vec<ClassRow>, Vec<CodeRow>), String> {
    const CLASS_REQUIRED: [&str; 4] = ["retryable", "client_action", "exit", "description"];
    const CLASS_OPTIONAL: [&str; 1] = ["http"];
    const CODE_REQUIRED: [&str; 3] = ["class", "message", "description"];
    const CODE_OPTIONAL: [&str; 2] = ["http", "deprecated"];

    let sections = parse_sections(document)?;
    let (root, body) = sections
        .split_first()
        .ok_or_else(|| "empty registry document".to_owned())?;
    check_closed_fields(root, &["schema"], &[], "the error registry root")?;
    if root.fields.first().and_then(|(_, value)| value.text())
        != Some("archivist.error-registry/v1")
    {
        return Err(
            "the error registry root does not declare schema archivist.error-registry/v1"
                .to_owned(),
        );
    }
    let mut classes = Vec::new();
    let mut codes = Vec::new();
    for section in body {
        let label = section.path.join(".");
        match section.path.as_slice() {
            [head, name] if head == "classes" => {
                check_closed_fields(section, &CLASS_REQUIRED, &CLASS_OPTIONAL, &label)?;
                classes.push(ClassRow {
                    name: name.clone(),
                    exit: field(section, "exit", &label)?
                        .integer()
                        .ok_or_else(|| format!("{label}: exit is not an integer"))?,
                    retryable: field(section, "retryable", &label)?
                        .boolean()
                        .ok_or_else(|| format!("{label}: retryable is not a boolean"))?,
                });
            }
            [head, name] if head == "codes" => {
                check_closed_fields(section, &CODE_REQUIRED, &CODE_OPTIONAL, &label)?;
                codes.push(CodeRow {
                    name: name.clone(),
                    class: text_field(section, "class", &label)?,
                });
            }
            _ => return Err(format!("unexpected section [{label}]")),
        }
    }
    Ok((classes, codes))
}

/// Validate the exit mappings the CLI contract names (CLI-002, CLI-007,
/// CLI-008, CLI-018, CLI-020, CLI-022): the named conditions sit in the
/// named classes, those classes allocate the named exits, and no class
/// claims the success exit or enters the signal range.
fn validate_exit_mappings(classes: &[ClassRow], codes: &[CodeRow]) -> Vec<String> {
    let mut violations = Vec::new();
    let class_by_name: BTreeMap<&str, &ClassRow> =
        classes.iter().map(|row| (row.name.as_str(), row)).collect();
    let code_by_name: BTreeMap<&str, &CodeRow> =
        codes.iter().map(|row| (row.name.as_str(), row)).collect();

    for (code, expected_class) in [
        (USAGE_CODES[0], USAGE_CLASS),
        (USAGE_CODES[1], USAGE_CLASS),
        (LOCK_CODE, LOCK_CLASS),
    ] {
        match code_by_name.get(code) {
            Some(row) if row.class != expected_class => violations.push(format!(
                "code {code} sits in class {:?}, the CLI contract exits on {expected_class}",
                row.class
            )),
            None => violations.push(format!("code {code} is not registered")),
            Some(_) => {}
        }
    }
    for (class_name, expected_exit) in [(USAGE_CLASS, USAGE_EXIT), (LOCK_CLASS, LOCK_EXIT)] {
        match class_by_name.get(class_name) {
            Some(row) if row.exit != i64::from(expected_exit) => violations.push(format!(
                "class {class_name} allocates exit {}, the CLI contract allocates {expected_exit}",
                row.exit
            )),
            None => violations.push(format!("class {class_name} is not registered")),
            Some(_) => {}
        }
    }
    for row in classes {
        if row.exit == SUCCESS_EXIT {
            violations.push(format!("class {} claims exit 0, the success exit", row.name));
        } else if row.exit >= SIGNAL_EXIT_FLOOR {
            violations.push(format!(
                "class {} claims exit {} inside the 128+n signal range",
                row.name, row.exit
            ));
        }
    }
    for row in codes {
        if !class_by_name.contains_key(row.class.as_str()) {
            violations.push(format!(
                "code {} names unregistered class {}",
                row.name, row.class
            ));
        }
    }
    violations
}

// ---------------------------------------------------------------------------
// Fixtures: the committed registries and the runtime views they must agree
// with.
// ---------------------------------------------------------------------------

/// The committed command registry, parsed.
fn committed_commands() -> Vec<Command> {
    command_registry(COMMAND_REGISTRY_TEXT).expect("the committed command registry parses")
}

/// The committed error registry, parsed.
fn committed_error_registry() -> (Vec<ClassRow>, Vec<CodeRow>) {
    error_registry_rows(ERROR_REGISTRY_TEXT).expect("the committed error registry parses")
}

/// The runtime configuration registry's key names.
fn runtime_key_names() -> BTreeSet<String> {
    registry::config_registry()
        .keys()
        .iter()
        .map(|definition| definition.name().to_owned())
        .collect()
}

/// The runtime configuration registry's flag-tier derivations (CFG-007).
fn runtime_key_flag_names() -> BTreeSet<String> {
    registry::config_registry()
        .keys()
        .iter()
        .filter(|definition| definition.flag_tier())
        .map(registry::KeyDefinition::flag_name)
        .collect()
}

/// Assert one mutation is rejected, naming the rule the violation carries.
fn rejects(violations: &[String], must_mention: &str, label: &str) {
    assert!(
        violations
            .iter()
            .any(|violation| violation.contains(must_mention)),
        "{label} must be rejected with a violation naming {must_mention:?}; got {violations:?}"
    );
}

/// A clone of one committed entry, the fixture most mutations touch.
fn entry(commands: &[Command], path: &[&str]) -> Command {
    commands
        .iter()
        .find(|command| {
            command.path.len() == path.len()
                && command
                    .path
                    .iter()
                    .zip(path.iter())
                    .all(|(segment, expected)| segment == expected)
        })
        .cloned()
        .unwrap_or_else(|| panic!("the registry registers {}", path.join(" ")))
}

/// The members of a JSON object value, for closed-shape assertions.
fn object_members(value: &json::Value) -> Option<Vec<&str>> {
    match value {
        json::Value::Object(object) => Some(object.iter().map(|(name, _)| name).collect()),
        _ => None,
    }
}

/// A JSON object member as text.
fn text_member<'a>(value: &'a json::Value, name: &str) -> Option<&'a str> {
    match as_object(value)?.get(name) {
        Some(json::Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// A JSON value as an object.
fn as_object(value: &json::Value) -> Option<&json::Object> {
    match value {
        json::Value::Object(object) => Some(object),
        _ => None,
    }
}

/// A JSON value as an array.
fn as_array(value: &json::Value) -> Option<&[json::Value]> {
    match value {
        json::Value::Array(items) => Some(items),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The conformance suite.
// ---------------------------------------------------------------------------

#[test]
fn the_committed_command_registry_satisfies_its_own_shape() {
    let commands = committed_commands();
    let violations = validate_commands(&commands);
    assert!(
        violations.is_empty(),
        "the committed command registry must be valid: {violations:?}"
    );
}

#[test]
fn every_consumed_key_is_registered_and_every_registered_key_is_consumed() {
    let commands = committed_commands();
    let registered = runtime_key_names();
    let violations = validate_key_consumption(&commands, &registered);
    assert!(
        violations.is_empty(),
        "the command and configuration-key registries must agree (CLI-002): {violations:?}"
    );
}

#[test]
fn the_flag_namespaces_are_pairwise_disjoint() {
    let commands = committed_commands();
    let key_flags = runtime_key_flag_names();
    let violations = validate_flag_namespaces(&commands, &key_flags);
    assert!(
        violations.is_empty(),
        "the three flag namespaces must stay disjoint (CLI-008): {violations:?}"
    );
}

#[test]
fn the_exit_mappings_the_cli_contract_names_hold() {
    let (classes, codes) = committed_error_registry();
    let violations = validate_exit_mappings(&classes, &codes);
    assert!(
        violations.is_empty(),
        "the error registry must satisfy the CLI exit contract: {violations:?}"
    );
}

#[test]
fn the_runtime_error_registry_agrees_with_the_committed_bytes() {
    let (classes, codes) = committed_error_registry();
    let runtime = error_registry();
    for row in &classes {
        let class = runtime
            .class(&row.name)
            .unwrap_or_else(|| panic!("class {} is missing at runtime", row.name));
        let exit = i32::try_from(row.exit).expect("the exit fits i32");
        assert_eq!(
            class.exit_code(),
            exit,
            "class {} exit drifts between the bytes and the runtime",
            row.name
        );
        assert_eq!(
            class.retryable(),
            row.retryable,
            "class {} retryability drifts between the bytes and the runtime",
            row.name
        );
    }
    for row in &codes {
        let definition = runtime
            .code(&row.name)
            .unwrap_or_else(|| panic!("code {} is missing at runtime", row.name));
        assert_eq!(
            definition.class(),
            row.class,
            "code {} class drifts between the bytes and the runtime",
            row.name
        );
    }
}

#[test]
fn the_output_envelope_schema_agrees_with_the_command_registry() {
    let schema = json::parse(ENVELOPE_SCHEMA_TEXT.as_bytes()).expect("the envelope schema parses");
    let root = as_object(&schema).expect("the envelope schema is an object");
    assert_eq!(
        root.get("$id"),
        Some(&json::Value::Text(ENVELOPE_SCHEMA_ID.to_owned()))
    );
    let properties = as_object(root.get("properties").expect("the schema types its members"))
        .expect("properties is an object");
    let namespace_const = as_object(properties.get("schema").expect("the schema member"))
        .and_then(|schema| schema.get("const"));
    assert_eq!(
        namespace_const,
        Some(&json::Value::Text(OUTPUT_NAMESPACE.to_owned())),
        "the envelope namespace const is the one the CLI pins"
    );
    let required = as_array(root.get("required").expect("the envelope pins required members"))
        .expect("required is an array");
    let members: Vec<Option<&str>> = required
        .iter()
        .map(|value| match value {
            json::Value::Text(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    let expected: Vec<Option<&str>> = ENVELOPE_MEMBERS.iter().map(|name| Some(*name)).collect();
    assert_eq!(members, expected, "the envelope members are closed");
    assert_eq!(
        root.get("additionalProperties"),
        Some(&json::Value::Bool(false)),
        "the envelope shape is closed"
    );
    let command_property = as_object(properties.get("command").expect("the command member"))
        .expect("the command member is an object");
    assert_eq!(
        command_property.get("pattern"),
        Some(&json::Value::Text(format!(
            "^[a-z][a-z0-9-]{{0,{COMMAND_TOKEN_MAX}}}$"
        ))),
        "the command-token pattern is the one the registry's joined forms must satisfy"
    );
    assert_eq!(
        command_property.get("maxLength"),
        Some(&json::Value::Int(i64::try_from(COMMAND_TOKEN_MAX + 1).expect("fits"))),
        "the command-token length bound agrees with the pattern"
    );
    let generated_at = as_object(properties.get("generated_at").expect("the generated_at member"))
        .expect("the generated_at member is an object");
    assert_eq!(
        generated_at.get("$ref"),
        Some(&json::Value::Text(TIMESTAMP_REF.to_owned())),
        "generated_at resolves the committed RFC 3339 UTC timestamp type"
    );
    let result_type = as_object(properties.get("result").expect("the result member"))
        .and_then(|result| result.get("type"));
    assert_eq!(
        result_type,
        Some(&json::Value::Text("object".to_owned())),
        "the result member stays an object: no float may leak into the envelope"
    );

    let common = json::parse(COMMON_SCHEMA_TEXT.as_bytes()).expect("the common schema parses");
    let timestamp_defined = as_object(&common)
        .and_then(|common| common.get("$defs"))
        .and_then(as_object)
        .and_then(|defs| defs.get("rfc3339-utc-timestamp"))
        .is_some();
    assert!(
        timestamp_defined,
        "the generated_at reference target must exist in schemas/v1/common.json"
    );

    // Both directions of the pattern agreement: every registered joined
    // form satisfies the pinned grammar, and unregistered shapes do not.
    for command in committed_commands() {
        let token = command.joined();
        assert!(
            grammar_ok(&token, COMMAND_TOKEN_MAX),
            "joined form {token:?} must satisfy the envelope's command-token grammar"
        );
    }
    let overlong = "x".repeat(COMMAND_TOKEN_MAX + 1);
    for rejected in ["", "Status", "catalog_rebuild", "a b", overlong.as_str()] {
        assert!(
            !grammar_ok(rejected, COMMAND_TOKEN_MAX),
            "the envelope grammar must refuse the unregistered shape {rejected:?}"
        );
    }
}

#[test]
fn generated_help_is_renderable_from_the_command_registry_alone() {
    // CLI-003: help cites the registry rather than a second list. The
    // render below is what help needs from each entry: the joined-form
    // token, the bounded summary, and each operational flag's own line.
    for command in committed_commands() {
        let line = format!("  {}  {}", command.joined(), command.summary);
        assert!(
            printable(&line),
            "the help line for {} must render from the registry",
            command.path_text()
        );
        for flag in &command.flags {
            let marker = if flag.required { " (required)" } else { "" };
            let flag_line = format!("      --{}{marker}  {}", flag.name, flag.summary);
            assert!(
                printable(&flag_line),
                "the help line for --{} must render from the registry",
                flag.name
            );
        }
    }
}

#[test]
fn the_loader_conditions_are_registered_in_the_classes_the_cli_contract_names() {
    // Every code token the loader can emit is a registered condition, and
    // each sits in the class whose exit the CLI contract names.
    let runtime = error_registry();
    for token in [
        ConfigErrorCode::Usage.token(),
        ConfigErrorCode::DecisionMissing.token(),
        ConfigErrorCode::SecretRefRefused.token(),
    ] {
        let definition = runtime
            .code(token)
            .unwrap_or_else(|| panic!("the loader code {token} must be registered"));
        let class = runtime
            .class(definition.class())
            .unwrap_or_else(|| panic!("the loader code {token} must name a registered class"));
        assert_eq!(
            class.exit_code(),
            USAGE_EXIT,
            "the loader code {token} must exit on the usage-class exit"
        );
    }
    let lock_definition = runtime
        .code(LOCK_CODE)
        .expect("the lock-held condition is registered");
    let lock_class = runtime
        .class(lock_definition.class())
        .expect("the lock-held condition names a registered class");
    assert_eq!(
        lock_class.exit_code(),
        LOCK_EXIT,
        "the lock-held condition must exit on the lock-contention exit"
    );
}

#[test]
fn a_usage_error_exits_on_the_registered_class_exit() {
    let error = ConfigSources::non_interactive()
        .env("HOME", "/home/operator")
        .flag("--teapot-flag", "x")
        .load()
        .expect_err("an unregistered flag is a usage error");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
    assert_eq!(
        error.exit_code(),
        USAGE_EXIT,
        "the usage class allocates exit 64 (CLI-008)"
    );
}

#[test]
fn a_missing_non_interactive_decision_exits_64_naming_the_field() {
    let mut sources = isolated_sources();
    sources.env.remove("ARCHIVIST_SERVER_LISTEN_ADDRESS");
    let error = sources
        .load()
        .expect_err("a required key with no tier is a missing decision");
    assert_eq!(error.code(), ConfigErrorCode::DecisionMissing);
    assert_eq!(error.field(), Some("server.listen_address"));
    assert_eq!(
        error.exit_code(),
        USAGE_EXIT,
        "a missing non-interactive decision exits 64 (CLI-022)"
    );

    // The body renders the committed message template with the named
    // field and keeps the closed archivist.error/v1 shape (ERR-029).
    let runtime = error_registry();
    let template = runtime
        .code(ConfigErrorCode::DecisionMissing.token())
        .expect("the decision-missing condition is registered")
        .message();
    let body = error.error_body();
    let object = as_object(&body).expect("the error body is an object");
    let members = object_members(&body).expect("the error body is an object");
    assert_eq!(
        members.len(),
        6,
        "the error body carries exactly the registered fields: {members:?}"
    );
    assert_eq!(
        object.get("schema"),
        Some(&json::Value::Text("archivist.error/v1".to_owned()))
    );
    assert_eq!(
        object.get("code"),
        Some(&json::Value::Text(
            ConfigErrorCode::DecisionMissing.token().to_owned()
        ))
    );
    assert_eq!(object.get("retryable"), Some(&json::Value::Bool(false)));
    assert_eq!(object.get("request_id"), Some(&json::Value::Null));
    let message = text_member(&body, "message").expect("the body carries the rendered message");
    assert_eq!(
        message,
        template.replace("{field}", "server.listen_address"),
        "the body message renders the committed template with the named field"
    );
}

#[test]
fn the_error_body_bytes_are_the_exact_canonical_stderr_value() {
    let mut sources = isolated_sources();
    sources.env.remove("ARCHIVIST_SERVER_LISTEN_ADDRESS");
    let error = sources.load().expect_err("required key missing");
    let bytes = error.error_body_bytes();
    // The stderr framing is canonical: reparsing the emitted value and
    // re-serializing it reproduces the bytes exactly.
    let parsed = json::parse(&bytes).expect("the stderr value parses back");
    assert_eq!(
        parsed.canonical_bytes(),
        bytes,
        "the stderr value must be in canonical form"
    );
    // And the emitted value is the archivist.error/v1 body: every stable
    // member agrees with a fresh body — `correlation_id` is the one
    // member minted per emission (ERR-026), so it is compared by
    // presence alone.
    let object = as_object(&parsed).expect("the stderr value is an object");
    let fresh_body = error.error_body();
    let body = as_object(&fresh_body).expect("the body is an object");
    let mut stable_members = 0;
    for (name, value) in object.iter() {
        if name == "correlation_id" {
            continue;
        }
        stable_members += 1;
        assert_eq!(
            body.get(name),
            Some(value),
            "stderr member {name} must agree with the fresh body"
        );
    }
    assert_eq!(
        stable_members, 5,
        "the body carries six members, one minted per emission"
    );
    assert!(
        body.get("correlation_id").is_some(),
        "the fresh body carries the minted correlation identifier"
    );
}

#[test]
fn the_daemon_is_non_interactive_by_construction() {
    let sources = ConfigSources::daemon().expect("the process environment is valid utf-8");
    assert_eq!(
        sources.interactivity(),
        Interactivity::NonInteractive,
        "a daemon invocation can never be made interactive by forgetting the flag (CLI-021)"
    );
    assert!(
        sources.interactivity().is_non_interactive(),
        "the mode predicate agrees with the constructed mode"
    );
}

// ---------------------------------------------------------------------------
// Negative fixtures: every mutation of the committed registries below must
// be rejected, mirroring the gate's self-test suite on the runtime side.
// ---------------------------------------------------------------------------

#[test]
fn a_command_path_outside_the_grammar_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["Status".to_owned()];
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "leaves the command grammar",
        "a capitalized command segment",
    );

    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "one or two segments",
        "a three-segment command path",
    );
}

#[test]
fn a_joined_form_collision_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["catalog-rebuild".to_owned()];
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "collides",
        "a joined-form collision",
    );
}

#[test]
fn a_command_with_kind_drift_is_rejected() {
    for (attribute, value, mention) in [
        ("state_lock", "greedy", "state_lock"),
        ("stdout", "progress", "stdout"),
        ("operand", "value", "operand"),
        ("stdin", "tty", "stdin"),
    ] {
        let mut commands = committed_commands();
        let mut intruder = entry(&commands, &["status"]);
        match attribute {
            "state_lock" => intruder.state_lock = value.to_owned(),
            "stdout" => intruder.stdout = value.to_owned(),
            "operand" => intruder.operand = value.to_owned(),
            _ => intruder.stdin = value.to_owned(),
        }
        commands.push(intruder);
        rejects(
            &validate_commands(&commands),
            mention,
            &format!("a command with {attribute} = {value:?}"),
        );
    }
}

#[test]
fn a_summary_over_the_bound_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.summary = "x".repeat(SUMMARY_MAX + 1);
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "summary",
        "a summary over the bound",
    );
}

#[test]
fn a_phase_outside_the_plan_range_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.phase = PHASE_RANGE.0 - 1;
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "phase",
        "a phase below the plan range",
    );
}

#[test]
fn consumption_of_an_unregistered_key_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["fixture".to_owned()];
    intruder.keys.push("teapot.mode".to_owned());
    commands.push(intruder);
    rejects(
        &validate_key_consumption(&commands, &runtime_key_names()),
        "unregistered key",
        "consumption of an unregistered key",
    );
}

#[test]
fn a_duplicate_key_in_one_command_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    let key = intruder.keys[0].clone();
    intruder.path = vec!["fixture".to_owned()];
    intruder.keys.push(key);
    commands.push(intruder);
    rejects(
        &validate_commands(&commands),
        "appears twice",
        "a duplicate key in one command's list",
    );
}

#[test]
fn a_registered_key_consumed_by_no_command_is_rejected() {
    let mut commands = committed_commands();
    commands.retain(|command| command.path != vec!["daemon"]);
    let violations = validate_key_consumption(&commands, &runtime_key_names());
    rejects(
        &violations,
        "consumed by no command",
        "dropping the daemon's command entry",
    );
}

#[test]
fn an_operational_flag_invading_a_mode_or_key_namespace_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["fixture".to_owned()];
    intruder.flags.push(OperationalFlag {
        name: "config".to_owned(),
        summary: "fixture flag".to_owned(),
        required: false,
    });
    commands.push(intruder);
    rejects(
        &validate_flag_namespaces(&commands, &runtime_key_flag_names()),
        "mode-flag namespace",
        "an operational flag colliding with a mode flag",
    );

    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["fixture".to_owned()];
    intruder.flags.push(OperationalFlag {
        name: "spool-max-bytes".to_owned(),
        summary: "fixture flag".to_owned(),
        required: false,
    });
    commands.push(intruder);
    rejects(
        &validate_flag_namespaces(&commands, &runtime_key_flag_names()),
        "key-flag namespace",
        "an operational flag colliding with a key-derived flag",
    );
}

#[test]
fn an_operational_flag_reused_across_commands_is_rejected() {
    let mut commands = committed_commands();
    let mut intruder = entry(&commands, &["status"]);
    intruder.path = vec!["fixture".to_owned()];
    intruder.flags.push(OperationalFlag {
        name: "once".to_owned(),
        summary: "fixture flag".to_owned(),
        required: false,
    });
    commands.push(intruder);
    rejects(
        &validate_flag_namespaces(&commands, &runtime_key_flag_names()),
        "already registered",
        "an operational flag reused across commands",
    );
}

#[test]
fn a_result_schema_on_a_command_with_no_stdout_value_is_rejected() {
    let mut commands = committed_commands();
    let daemon = commands
        .iter_mut()
        .find(|command| command.path == vec!["daemon".to_owned()])
        .expect("the registry registers daemon");
    daemon.result_schema = Some("schemas/v1/cli-output.json".to_owned());
    rejects(
        &validate_commands(&commands),
        "stdout-document",
        "a result schema on a command whose stdout kind is none",
    );
}

#[test]
fn a_usage_exit_drift_is_rejected() {
    let (mut classes, codes) = committed_error_registry();
    let usage = classes
        .iter_mut()
        .find(|row| row.name == USAGE_CLASS)
        .expect("the usage class is registered");
    usage.exit = i64::from(USAGE_EXIT) - 1;
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "allocates",
        "a usage exit drift against the CLI contract",
    );
}

#[test]
fn a_lock_contention_exit_drift_is_rejected() {
    let (mut classes, codes) = committed_error_registry();
    let lock = classes
        .iter_mut()
        .find(|row| row.name == LOCK_CLASS)
        .expect("the lock-contention class is registered");
    lock.exit = i64::from(LOCK_EXIT) + 1;
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "allocates",
        "a lock-contention exit drift against the CLI contract",
    );
}

#[test]
fn an_unregistered_cli_condition_is_rejected() {
    let (classes, mut codes) = committed_error_registry();
    codes.retain(|row| row.name != USAGE_CODES[0]);
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "is not registered",
        "an unregistered cli.usage_error condition",
    );
}

#[test]
fn a_condition_reclassified_off_its_cli_class_is_rejected() {
    let (classes, mut codes) = committed_error_registry();
    let decision = codes
        .iter_mut()
        .find(|row| row.name == USAGE_CODES[1])
        .expect("the decision-missing condition is registered");
    decision.class = "local_state".to_owned();
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "the CLI contract exits on",
        "cli.decision_missing drifting out of the usage class",
    );

    let (classes, mut codes) = committed_error_registry();
    let lock = codes
        .iter_mut()
        .find(|row| row.name == LOCK_CODE)
        .expect("the lock-held condition is registered");
    lock.class = "internal".to_owned();
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "the CLI contract exits on",
        "client.lock_held reclassified off lock contention",
    );
}

#[test]
fn a_class_claiming_the_success_or_signal_exit_is_rejected() {
    let (mut classes, codes) = committed_error_registry();
    let internal = classes
        .iter_mut()
        .find(|row| row.name == "internal")
        .expect("the internal class is registered");
    internal.exit = SUCCESS_EXIT;
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "exit 0",
        "an error class claiming the success exit",
    );

    let (mut classes, codes) = committed_error_registry();
    let internal = classes
        .iter_mut()
        .find(|row| row.name == "internal")
        .expect("the internal class is registered");
    internal.exit = SIGNAL_EXIT_FLOOR + 15;
    rejects(
        &validate_exit_mappings(&classes, &codes),
        "signal range",
        "an error class claiming the 128+n signal range",
    );
}

// ---------------------------------------------------------------------------
// The isolated load fixture: the same complete environment
// src/config/tests.rs assembles, so a missing required key is the only
// condition under test and the default configuration file is never found.
// ---------------------------------------------------------------------------

/// A non-interactive loader whose environment carries every required key,
/// with the configuration file tier pointed at an absent default.
fn isolated_sources() -> ConfigSources {
    ConfigSources::non_interactive()
        .env("HOME", "/home/operator")
        .env("TEST_RAW_CREDENTIAL", "fixture-raw-credential")
        .env(
            "ARCHIVIST_INGEST_ENDPOINT_URL",
            "https://ingest.example.invalid",
        )
        .env(
            "ARCHIVIST_STORAGE_ENDPOINT_URL",
            "https://s3.example.invalid",
        )
        .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
        .env("ARCHIVIST_STORAGE_RAW_BUCKET", "archivist-raw-example")
        .env(
            "ARCHIVIST_STORAGE_CONTROL_BUCKET",
            "archivist-control-example",
        )
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:TEST_RAW_CREDENTIAL",
        )
        .env(
            "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
            "env:TEST_CONTROL_CREDENTIAL",
        )
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087")
}
