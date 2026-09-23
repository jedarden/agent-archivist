// SPDX-License-Identifier: Apache-2.0

//! The `archivist.cli-output/v1` success envelope.

use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_protocol::json;

const OUTPUT_NAMESPACE: &str = "archivist.cli-output/v1";

/// A closed four-member CLI output envelope (CLI-014).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputEnvelope {
    command: Box<str>,
    generated_at: Box<str>,
    result: json::Value,
}

impl OutputEnvelope {
    /// Build an envelope with a current RFC 3339 UTC timestamp.
    ///
    /// # Errors
    /// Returns [`OutputError::ResultNotObject`] when the delegated result is
    /// not an object, as required by the v1 envelope schema.
    pub fn new(command: &str, result: json::Value) -> Result<Self, OutputError> {
        if !is_command_token(command) {
            return Err(OutputError::InvalidCommand);
        }
        if !matches!(result, json::Value::Object(_)) {
            return Err(OutputError::ResultNotObject);
        }
        Ok(Self {
            command: command.to_owned().into_boxed_str(),
            generated_at: now_rfc3339().into_boxed_str(),
            result,
        })
    }

    /// Construct an envelope with an explicit timestamp for deterministic
    /// tests and callers that already captured the production timestamp.
    ///
    /// # Errors
    /// Returns an error when the command, timestamp, or delegated result
    /// leaves the v1 envelope grammar.
    pub fn with_timestamp(
        command: &str,
        generated_at: &str,
        result: json::Value,
    ) -> Result<Self, OutputError> {
        if !is_command_token(command) {
            return Err(OutputError::InvalidCommand);
        }
        if !valid_timestamp(generated_at) {
            return Err(OutputError::InvalidTimestamp);
        }
        if !matches!(result, json::Value::Object(_)) {
            return Err(OutputError::ResultNotObject);
        }
        Ok(Self {
            command: command.to_owned().into_boxed_str(),
            generated_at: generated_at.to_owned().into_boxed_str(),
            result,
        })
    }

    /// The canonical JSON bytes for exactly the four envelope members.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut object = json::Object::new();
        object.set("schema", json::Value::Text(OUTPUT_NAMESPACE.to_owned()));
        object.set("command", json::Value::Text(self.command.to_string()));
        object.set(
            "generated_at",
            json::Value::Text(self.generated_at.to_string()),
        );
        object.set("result", self.result.clone());
        json::Value::Object(object).canonical_bytes()
    }

    /// Write one JSON value followed by one newline to a stream.
    ///
    /// # Errors
    /// Returns the underlying writer error.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.canonical_bytes())?;
        writer.write_all(b"\n")
    }
}

/// Write a result document for a human-facing TTY.
///
/// The machine-facing path is [`OutputEnvelope`], which is deliberately one
/// canonical JSON value. A TTY gets the same content rendered as a small
/// indented field tree so an operator can read it without decoding compact
/// JSON. The renderer is intentionally uncoloured: output remains safe when
/// a terminal is captured or copied into a diagnostic transcript.
pub fn write_human<W: Write>(value: &json::Value, writer: &mut W) -> io::Result<()> {
    let needs_newline = match value {
        json::Value::Object(object) => object.is_empty(),
        json::Value::Array(items) => items.is_empty(),
        _ => true,
    };
    render_human(value, 0, writer)?;
    if needs_newline {
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn render_human<W: Write>(value: &json::Value, indent: usize, writer: &mut W) -> io::Result<()> {
    match value {
        json::Value::Object(object) => {
            if object.is_empty() {
                return writer.write_all(b"{}");
            }
            for (name, child) in object.iter() {
                write_indent(writer, indent)?;
                writer.write_all(name.as_bytes())?;
                match child {
                    json::Value::Object(_) | json::Value::Array(_) => {
                        writer.write_all(b":")?;
                        if child_is_empty(child) {
                            writer.write_all(b" ")?;
                            render_human(child, indent, writer)?;
                            writer.write_all(b"\n")?;
                        } else {
                            writer.write_all(b"\n")?;
                            render_human(child, indent + 2, writer)?;
                        }
                    }
                    _ => {
                        writer.write_all(b": ")?;
                        render_scalar(child, writer)?;
                        writer.write_all(b"\n")?;
                    }
                }
            }
            Ok(())
        }
        json::Value::Array(items) => {
            if items.is_empty() {
                return writer.write_all(b"[]");
            }
            for item in items {
                write_indent(writer, indent)?;
                writer.write_all(b"-")?;
                match item {
                    json::Value::Object(_) | json::Value::Array(_) => {
                        if child_is_empty(item) {
                            writer.write_all(b" ")?;
                            render_human(item, indent, writer)?;
                            writer.write_all(b"\n")?;
                        } else {
                            writer.write_all(b"\n")?;
                            render_human(item, indent + 2, writer)?;
                        }
                    }
                    _ => {
                        writer.write_all(b" ")?;
                        render_scalar(item, writer)?;
                        writer.write_all(b"\n")?;
                    }
                }
            }
            Ok(())
        }
        _ => render_scalar(value, writer),
    }
}

fn child_is_empty(value: &json::Value) -> bool {
    match value {
        json::Value::Object(object) => object.is_empty(),
        json::Value::Array(items) => items.is_empty(),
        _ => false,
    }
}

fn render_scalar<W: Write>(value: &json::Value, writer: &mut W) -> io::Result<()> {
    writer.write_all(&value.canonical_bytes())
}

fn write_indent<W: Write>(writer: &mut W, indent: usize) -> io::Result<()> {
    for _ in 0..indent {
        writer.write_all(b" ")?;
    }
    Ok(())
}

/// Why an output envelope could not be constructed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputError {
    /// The command token is outside the schema grammar.
    InvalidCommand,
    /// The timestamp is not the pinned UTC RFC 3339 shape.
    InvalidTimestamp,
    /// The delegated result is not an object.
    ResultNotObject,
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "the command token is outside the CLI output grammar",
            Self::InvalidTimestamp => "the timestamp is not RFC 3339 UTC",
            Self::ResultNotObject => "the delegated result is not an object",
        })
    }
}

impl std::error::Error for OutputError {}

fn is_command_token(text: &str) -> bool {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
        })
        && text.len() <= 65
}

fn valid_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if !(20..=30).contains(&bytes.len()) || !text.ends_with('Z') {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let digit = byte.is_ascii_digit();
        let separator = matches!(index, 4 | 7) && *byte == b'-'
            || matches!(index, 10) && *byte == b'T'
            || matches!(index, 13 | 16) && *byte == b':'
            || (index == 19 && *byte == b'.')
            || (index == bytes.len() - 1 && *byte == b'Z');
        if !digit && !separator {
            return false;
        }
    }
    match text.split_once('.') {
        Some((_, fraction)) => {
            fraction.len() >= 2 && fraction.len() <= 10 && fraction.ends_with('Z')
        }
        None => true,
    }
}

/// The current UTC instant as RFC 3339 text, to second or subsecond
/// precision, with no date-time dependency. Handlers that must stamp a
/// record with the invocation's instant reuse this so the emitted shape
/// matches the envelope framing's own `generated_at` form — and parses as
/// a protocol `Timestamp`, whose grammar accepts the subsecond form.
#[must_use]
pub fn now_rfc3339() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let day_seconds = seconds % 86_400;
    let days = i64::try_from(days).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let nanos = duration.subsec_nanos();
    if nanos == 0 {
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        let mut fraction = format!("{nanos:09}");
        while fraction.ends_with('0') {
            fraction.pop();
        }
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{fraction}Z")
    }
}

// Howard Hinnant's proleptic Gregorian civil_from_days, expressed with
// integer arithmetic so timestamp production needs no date-time dependency.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year, month, day)
}
