// SPDX-License-Identifier: Apache-2.0

//! A closed-subset TOML reader for the two configuration surfaces this
//! crate loads: the deployment configuration file (CFG-011) and the
//! embedded registries (CFG-033, ERR).
//!
//! The grammar accepted here is deliberately narrower than full TOML:
//! table headers with bare or quoted segments, `key = value` pairs with a
//! single key segment, basic and literal strings, TOML integers, booleans,
//! and one-line arrays of scalars. Dotted keys in a table body,
//! multi-line strings, array-of-tables headers, inline tables, floats,
//! and datetimes are all refused. Every one of those forms expresses a
//! shape the v1 configuration surface does not have — v1 keys are
//! scalar-valued (CFG-004) — so refusing them *is* the fail-closed
//! behavior CFG-012 and CFG-013 require, not a compatibility gap: a value
//! this parser cannot read is a usage error naming the key, never a
//! silently ignored or best-effort-parsed setting.
//!
//! Keeping the reader in-crate also keeps the workspace's external
//! dependency surface at zero for configuration loading: the registry is
//! data this binary already embeds, and a full TOML implementation would
//! pull a parser (and its dependency tree) into the client for grammar
//! the surface never uses.
//!
//! Parsing is strict about duplicates in both directions: a table header
//! defined twice, a key assigned twice in one table, and a key/table
//! collision at the same path are all errors, so a deployment file can
//! never carry two conflicting values for one setting.

use std::collections::BTreeMap;
use std::fmt;

/// One scalar value: text, integer, or boolean.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scalar {
    /// A basic or literal string.
    Text(Box<str>),
    /// A TOML integer in `i64` range.
    Integer(i64),
    /// `true` or `false`.
    Boolean(bool),
}

impl Scalar {
    /// The scalar as text, if it is text.
    #[must_use]
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            _ => None,
        }
    }

    /// The scalar as an integer, if it is one.
    #[must_use]
    pub const fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// The scalar as a boolean, if it is one.
    #[must_use]
    pub const fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }
}

/// A parsed value: a scalar, a one-line array of scalars, or a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TomlValue {
    /// A scalar value.
    Scalar(Scalar),
    /// A one-line array of scalars, possibly empty.
    Array(Vec<Scalar>),
    /// A table introduced by a header (or nested by one).
    Table(TomlTable),
}

impl TomlValue {
    /// The value as a table, if it is one.
    #[must_use]
    pub fn as_table(&self) -> Option<&TomlTable> {
        match self {
            Self::Table(table) => Some(table),
            _ => None,
        }
    }

    /// The value as a scalar, if it is one.
    #[must_use]
    pub const fn as_scalar(&self) -> Option<&Scalar> {
        match self {
            Self::Scalar(scalar) => Some(scalar),
            _ => None,
        }
    }
}

impl From<Scalar> for TomlValue {
    fn from(scalar: Scalar) -> Self {
        Self::Scalar(scalar)
    }
}

/// A table: members keyed by their single segment (a quoted segment may
/// carry dots — those are bytes of the name, not structure).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TomlTable {
    members: BTreeMap<Box<str>, TomlValue>,
}

impl TomlTable {
    /// Look up one member by segment.
    #[must_use]
    pub fn get(&self, segment: &str) -> Option<&TomlValue> {
        self.members.get(segment)
    }

    /// Iterate the members in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &TomlValue)> {
        self.members.iter().map(|(name, value)| (&**name, value))
    }
}

/// Why a document was refused. The variants name the condition class;
/// the line number travels on [`ParseError`] and nothing else does —
/// the offending text is never echoed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The document leaves the accepted grammar at this line.
    Malformed,
    /// Two definitions claim the same path.
    Duplicate,
    /// The line uses a TOML form this closed grammar refuses (dotted
    /// keys, array-of-tables headers, multi-line strings, inline tables,
    /// floats, datetimes).
    Unsupported,
    /// An integer is outside `i64`.
    OutOfRange,
}

impl fmt::Display for ParseErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Malformed => "outside the accepted grammar",
            Self::Duplicate => "defines the same path twice",
            Self::Unsupported => "uses a toml form the configuration grammar refuses",
            Self::OutOfRange => "carries an integer outside i64 range",
        };
        f.write_str(text)
    }
}

/// A parse failure with the 1-based line it was detected on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseError {
    /// The line the failure was detected on.
    pub line: u32,
    /// The failure class.
    pub kind: ParseErrorKind,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.kind)
    }
}

impl std::error::Error for ParseError {}

/// Parse a document within the closed grammar.
///
/// # Errors
/// [`ParseError`] for the first line that leaves the grammar, duplicates
/// a path, uses a refused TOML form, or overflows an integer.
pub fn parse(document: &str) -> Result<TomlTable, ParseError> {
    Reader::new(document).document()
}

/// The byte-level reader: position, line tracking, and the token
/// parsers. `line` is 1-based and advances on every consumed newline.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: u32,
}

impl<'a> Reader<'a> {
    fn new(document: &'a str) -> Self {
        Self {
            bytes: document.as_bytes(),
            pos: 0,
            line: 1,
        }
    }

    fn error(&self, kind: ParseErrorKind) -> ParseError {
        ParseError {
            line: self.line,
            kind,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos + offset).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        if byte == b'\n' {
            self.line += 1;
        }
        Some(byte)
    }

    fn skip_spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.pos += 1;
        }
    }

    /// Consume the rest of the line: optional trailing whitespace and
    /// comment, then a newline or end of input. A carriage return is
    /// accepted only as part of a `\r\n` pair.
    fn end_of_line(&mut self) -> Result<(), ParseError> {
        self.skip_spaces();
        if self.peek() == Some(b'#') {
            while self.peek().is_some_and(|byte| byte != b'\n') {
                self.pos += 1;
            }
        }
        match self.peek() {
            None => Ok(()),
            Some(b'\n') => {
                self.bump();
                Ok(())
            }
            Some(b'\r') if self.peek_at(1) == Some(b'\n') => {
                self.bump();
                self.bump();
                Ok(())
            }
            _ => Err(self.error(ParseErrorKind::Malformed)),
        }
    }

    /// Skip blank lines and comment-only lines.
    fn skip_blank(&mut self) {
        loop {
            let save = self.pos;
            self.skip_spaces();
            match self.peek() {
                Some(b'\n') => {
                    self.bump();
                }
                Some(b'\r') if self.peek_at(1) == Some(b'\n') => {
                    self.bump();
                    self.bump();
                }
                Some(b'#') => {
                    while self.peek().is_some_and(|byte| byte != b'\n') {
                        self.pos += 1;
                    }
                    self.bump();
                }
                _ => {
                    self.pos = save;
                    return;
                }
            }
        }
    }

    fn document(&mut self) -> Result<TomlTable, ParseError> {
        let mut root = TomlTable::default();
        let mut headers: Vec<Vec<String>> = Vec::new();
        let mut current: Vec<String> = Vec::new();
        loop {
            self.skip_blank();
            if self.peek().is_none() {
                return Ok(root);
            }
            if self.peek() == Some(b'[') {
                self.pos += 1;
                if self.peek() == Some(b'[') {
                    return Err(self.error(ParseErrorKind::Unsupported));
                }
                let segments = self.header_segments()?;
                if headers.contains(&segments) {
                    return Err(self.error(ParseErrorKind::Duplicate));
                }
                headers.push(segments.clone());
                insert_table(&mut root, &segments, self.line)?;
                current = segments;
                self.end_of_line()?;
            } else {
                let key = self.key_token()?;
                self.skip_spaces();
                if self.peek() == Some(b'.') {
                    return Err(self.error(ParseErrorKind::Unsupported));
                }
                if self.peek() != Some(b'=') {
                    return Err(self.error(ParseErrorKind::Malformed));
                }
                self.pos += 1;
                self.skip_spaces();
                let value = self.value()?;
                insert_value(&mut root, &current, &key, value, self.line)?;
                self.end_of_line()?;
            }
        }
    }

    /// The dotted segments of a table header, up to the closing bracket.
    fn header_segments(&mut self) -> Result<Vec<String>, ParseError> {
        let mut segments = Vec::new();
        loop {
            self.skip_spaces();
            segments.push(self.key_token()?);
            self.skip_spaces();
            match self.peek() {
                Some(b'.') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(segments);
                }
                _ => return Err(self.error(ParseErrorKind::Malformed)),
            }
        }
    }

    /// A bare key (`[A-Za-z0-9_-]+`) or a quoted key (basic or literal
    /// string).
    fn key_token(&mut self) -> Result<String, ParseError> {
        match self.peek() {
            Some(b'"') => self.basic_string(),
            Some(b'\'') => self.literal_string(),
            Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' => {
                let start = self.pos;
                while matches!(self.peek(), Some(byte) if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
                {
                    self.pos += 1;
                }
                // Bare keys are ASCII by construction, so the slice is a
                // char boundary.
                Ok(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
            }
            _ => Err(self.error(ParseErrorKind::Malformed)),
        }
    }

    /// A value after `=`: string, integer, boolean, or a one-line array
    /// of those scalars.
    fn value(&mut self) -> Result<TomlValue, ParseError> {
        match self.peek() {
            Some(b'"') => Ok(Scalar::Text(self.basic_string()?.into()).into()),
            Some(b'\'') => Ok(Scalar::Text(self.literal_string()?.into()).into()),
            Some(b'[') => self.array(),
            Some(b't' | b'f') => Ok(Scalar::Boolean(self.boolean()?).into()),
            Some(byte) if byte.is_ascii_digit() || byte == b'+' || byte == b'-' => {
                Ok(Scalar::Integer(self.integer()?).into())
            }
            _ => Err(self.error(ParseErrorKind::Malformed)),
        }
    }

    /// A one-line array of scalars. Newlines and nesting are refused.
    fn array(&mut self) -> Result<TomlValue, ParseError> {
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_spaces();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(TomlValue::Array(items));
        }
        loop {
            self.skip_spaces();
            let scalar = match self.peek() {
                Some(b'"') => Scalar::Text(self.basic_string()?.into()),
                Some(b'\'') => Scalar::Text(self.literal_string()?.into()),
                Some(b't' | b'f') => Scalar::Boolean(self.boolean()?),
                Some(byte) if byte.is_ascii_digit() || byte == b'+' || byte == b'-' => {
                    Scalar::Integer(self.integer()?)
                }
                _ => return Err(self.error(ParseErrorKind::Malformed)),
            };
            items.push(scalar);
            self.skip_spaces();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(TomlValue::Array(items));
                }
                // A newline before the bracket leaves the one-line rule.
                Some(b'\n' | b'\r') => {
                    return Err(self.error(ParseErrorKind::Unsupported));
                }
                _ => return Err(self.error(ParseErrorKind::Malformed)),
            }
        }
    }

    fn boolean(&mut self) -> Result<bool, ParseError> {
        let start = self.pos;
        while matches!(self.peek(), Some(byte) if byte.is_ascii_alphabetic()) {
            self.pos += 1;
        }
        match &self.bytes[start..self.pos] {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => {
                self.pos = start;
                Err(self.error(ParseErrorKind::Malformed))
            }
        }
    }

    /// A TOML integer: decimal with `_` separators and optional sign, or
    /// an unsigned `0x`/`0o`/`0b` literal.
    fn integer(&mut self) -> Result<i64, ParseError> {
        let negative = matches!(self.peek(), Some(b'-'));
        let signed = matches!(self.peek(), Some(b'+' | b'-'));
        if signed {
            self.pos += 1;
        }
        let radix = if self.peek() == Some(b'0') {
            match self.peek_at(1) {
                Some(b'x') => Some(16u32),
                Some(b'o') => Some(8),
                Some(b'b') => Some(2),
                _ => None,
            }
        } else {
            None
        };
        // A prefixed integer carries no sign in TOML.
        let radix = match radix {
            Some(_) if signed => return Err(self.error(ParseErrorKind::Malformed)),
            other => other.unwrap_or(10),
        };
        if radix != 10 {
            self.pos += 2;
        }
        let mut digits: Vec<u32> = Vec::new();
        let mut last_was_underscore = true; // a leading `_` is invalid
        while let Some(byte) = self.peek() {
            if byte == b'_' {
                if last_was_underscore {
                    return Err(self.error(ParseErrorKind::Malformed));
                }
                last_was_underscore = true;
                self.pos += 1;
                continue;
            }
            let Some(digit) = (byte as char).to_digit(radix) else {
                break;
            };
            digits.push(digit);
            last_was_underscore = false;
            self.pos += 1;
        }
        if digits.is_empty() || last_was_underscore {
            return Err(self.error(ParseErrorKind::Malformed));
        }
        // Decimal integers have no leading zeros (a lone `0` is fine).
        if radix == 10 && digits.len() > 1 && digits[0] == 0 {
            return Err(self.error(ParseErrorKind::Malformed));
        }
        let magnitude = digits.iter().try_fold(0u64, |acc, digit| {
            acc.checked_mul(u64::from(radix))
                .and_then(|acc| acc.checked_add(u64::from(*digit)))
        });
        let magnitude = magnitude.ok_or_else(|| self.error(ParseErrorKind::OutOfRange))?;
        let value = if negative {
            i64::try_from(magnitude).ok().and_then(i64::checked_neg)
        } else {
            i64::try_from(magnitude).ok()
        };
        value.ok_or_else(|| self.error(ParseErrorKind::OutOfRange))
    }

    /// A basic string: `"..."` with the closed escape set.
    fn basic_string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // opening quote
        let mut out = String::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => return Err(self.error(ParseErrorKind::Malformed)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escape = self
                        .bump()
                        .ok_or_else(|| self.error(ParseErrorKind::Malformed))?;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'b' => out.push('\u{8}'),
                        b't' => out.push('\t'),
                        b'n' => out.push('\n'),
                        b'f' => out.push('\u{c}'),
                        b'r' => out.push('\r'),
                        b'u' => out.push(self.unicode_escape(4)?),
                        b'U' => out.push(self.unicode_escape(8)?),
                        _ => {
                            return Err(self.error(ParseErrorKind::Malformed));
                        }
                    }
                }
                Some(byte) if (byte < 0x20 && byte != b'\t') || byte == 0x7f => {
                    return Err(self.error(ParseErrorKind::Malformed));
                }
                Some(_) => {
                    // Copy one UTF-8 character; only ASCII was handled
                    // above, so anything here is a printable byte or the
                    // start of a multi-byte sequence.
                    let start = self.pos;
                    self.pos += 1;
                    while self.peek().is_some_and(|byte| byte & 0xc0 == 0x80) {
                        self.pos += 1;
                    }
                    out.push_str(
                        std::str::from_utf8(&self.bytes[start..self.pos])
                            .map_err(|_| self.error(ParseErrorKind::Malformed))?,
                    );
                }
            }
        }
    }

    fn unicode_escape(&mut self, count: usize) -> Result<char, ParseError> {
        let mut value: u32 = 0;
        for _ in 0..count {
            let byte = self
                .bump()
                .ok_or_else(|| self.error(ParseErrorKind::Malformed))?;
            let digit = (byte as char)
                .to_digit(16)
                .ok_or_else(|| self.error(ParseErrorKind::Malformed))?;
            value = value * 16 + digit;
        }
        char::from_u32(value).ok_or_else(|| self.error(ParseErrorKind::Malformed))
    }

    /// A literal string: `'...'` with no escapes.
    fn literal_string(&mut self) -> Result<String, ParseError> {
        self.pos += 1; // opening quote
        let start = self.pos;
        loop {
            match self.peek() {
                None | Some(b'\n') => return Err(self.error(ParseErrorKind::Malformed)),
                Some(b'\'') => {
                    let text = std::str::from_utf8(&self.bytes[start..self.pos])
                        .map_err(|_| self.error(ParseErrorKind::Malformed))?
                        .to_owned();
                    self.pos += 1;
                    return Ok(text);
                }
                Some(byte) if (byte < 0x20 && byte != b'\t') || byte == 0x7f => {
                    return Err(self.error(ParseErrorKind::Malformed));
                }
                Some(_) => {
                    self.pos += 1;
                }
            }
        }
    }
}

/// Create (or adopt) the table at `segments`, refusing a collision with a
/// scalar. An intermediate table created by a deeper header may be
/// adopted by a later, shallower header; only an exact repeated header is
/// a duplicate, and the caller has already rejected that.
fn insert_table(root: &mut TomlTable, segments: &[String], line: u32) -> Result<(), ParseError> {
    let mut table = root;
    for segment in segments {
        let entry = table
            .members
            .entry(segment.as_str().into())
            .or_insert_with(|| TomlValue::Table(TomlTable::default()));
        table = match entry {
            TomlValue::Table(table) => table,
            _ => {
                return Err(ParseError {
                    line,
                    kind: ParseErrorKind::Duplicate,
                });
            }
        };
    }
    Ok(())
}

/// Insert `value` at `current` + `key`, refusing duplicates and
/// scalar-on-table collisions.
fn insert_value(
    root: &mut TomlTable,
    current: &[String],
    key: &str,
    value: TomlValue,
    line: u32,
) -> Result<(), ParseError> {
    let mut table = root;
    for segment in current {
        let entry = table
            .members
            .entry(segment.as_str().into())
            .or_insert_with(|| TomlValue::Table(TomlTable::default()));
        table = match entry {
            TomlValue::Table(table) => table,
            _ => {
                return Err(ParseError {
                    line,
                    kind: ParseErrorKind::Duplicate,
                });
            }
        };
    }
    match table.members.entry(key.into()) {
        std::collections::btree_map::Entry::Vacant(vacant) => {
            vacant.insert(value);
            Ok(())
        }
        std::collections::btree_map::Entry::Occupied(_) => Err(ParseError {
            line,
            kind: ParseErrorKind::Duplicate,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> TomlValue {
        Scalar::Text(value.into()).into()
    }

    #[test]
    fn reads_sections_scalars_and_arrays() {
        let document = "\
# leading comment
schema = \"archivist.config-registry/v1\"

[keys.\"client.state_dir\"]
owner = \"archivist-client-core\"   # trailing comment
type = \"path\"
tiers = [\"flag\", \"env\", \"file\"]
secret = false
default = \"${XDG_STATE_HOME}/archivist\"
";
        let root = parse(document).expect("parses");
        assert_eq!(
            root.get("schema"),
            Some(&text("archivist.config-registry/v1"))
        );
        let keys = root
            .get("keys")
            .and_then(TomlValue::as_table)
            .expect("keys");
        let key = keys
            .get("client.state_dir")
            .and_then(TomlValue::as_table)
            .expect("quoted header segment");
        assert_eq!(key.get("owner"), Some(&text("archivist-client-core")));
        assert_eq!(key.get("secret"), Some(&Scalar::Boolean(false).into()));
        let tiers = match key.get("tiers") {
            Some(TomlValue::Array(items)) => items.clone(),
            other => panic!("unexpected tiers: {other:?}"),
        };
        assert_eq!(tiers.len(), 3);
        assert_eq!(tiers[0].as_text(), Some("flag"));
        assert_eq!(
            key.get("default"),
            Some(&text("${XDG_STATE_HOME}/archivist"))
        );
    }

    #[test]
    fn reads_integer_forms_and_booleans() {
        let document = "\
[ints]
plain = 900
under_scored = 1_000_000
hex = 0xff
octal = 0o755
binary = 0b1011
negative = -12
positive = +12
zero = 0
[flags]
yes = true
no = false
empty = []
";
        let root = parse(document).expect("parses");
        let ints = root
            .get("ints")
            .and_then(TomlValue::as_table)
            .expect("ints");
        for name in [
            "plain",
            "under_scored",
            "hex",
            "octal",
            "binary",
            "negative",
            "positive",
            "zero",
        ] {
            assert!(
                ints.get(name).is_some_and(|value| {
                    matches!(value, TomlValue::Scalar(Scalar::Integer(_)))
                }),
                "{name} should parse as an integer"
            );
        }
        assert_eq!(ints.get("plain"), Some(&Scalar::Integer(900).into()));
        assert_eq!(ints.get("hex"), Some(&Scalar::Integer(255).into()));
        assert_eq!(ints.get("negative"), Some(&Scalar::Integer(-12).into()));
        let flags = root
            .get("flags")
            .and_then(TomlValue::as_table)
            .expect("flags");
        assert_eq!(flags.get("yes"), Some(&Scalar::Boolean(true).into()));
        assert_eq!(flags.get("empty"), Some(&TomlValue::Array(Vec::new())));
    }

    #[test]
    fn reads_string_forms() {
        let document = "\
[text]
basic = \"a b \\\"q\\\" \\\\ \\u0041\"
literal = 'no \\escape'
comment_inside = \"value # not a comment\"
";
        let root = parse(document).expect("parses");
        let section = root
            .get("text")
            .and_then(TomlValue::as_table)
            .expect("text");
        assert_eq!(section.get("basic"), Some(&text("a b \"q\" \\ A")));
        assert_eq!(section.get("literal"), Some(&text("no \\escape")));
        assert_eq!(
            section.get("comment_inside"),
            Some(&text("value # not a comment"))
        );
    }

    #[test]
    fn accepts_crlf_and_final_line_without_newline() {
        let root = parse("a = 1\r\nb = \"x\"").expect("parses");
        assert_eq!(root.get("a"), Some(&Scalar::Integer(1).into()));
        assert_eq!(root.get("b"), Some(&text("x")));
    }

    #[test]
    fn refuses_duplicate_paths() {
        for document in [
            "a = 1\na = 2\n",
            "[t]\nx = 1\nx = 2\n",
            "[t]\n[t]\n",
            "t = 1\n[t]\n",
        ] {
            assert_eq!(
                parse(document).unwrap_err().kind,
                ParseErrorKind::Duplicate,
                "{document:?} should be a duplicate"
            );
        }
    }

    #[test]
    fn accepts_super_table_defined_after_subtable() {
        let root = parse("[a.b]\nx = 1\n[a]\ny = 2\n").expect("parses");
        assert!(root.get("a").is_some());
    }

    #[test]
    fn refuses_unsupported_toml_forms() {
        for document in [
            "a = 1.5\n",
            "a = 1979-05-27\n",
            "a = { x = 1 }\n",
            "a.b = 1\n",
            "[a]\nb.c = 1\n",
            "[[a]]\n",
            "a = \"\"\"multi\nline\"\"\"\n",
            "a = '''raw\nmulti'''\n",
            "a = [\n 1,\n]\n",
            "a = inf\n",
            "a = nan\n",
            "a = +0x10\n",
        ] {
            let error = parse(document).unwrap_err();
            assert!(
                error.kind == ParseErrorKind::Unsupported
                    || error.kind == ParseErrorKind::Malformed,
                "{document:?} should be refused, got {error:?}"
            );
        }
    }

    #[test]
    fn refuses_malformed_lines() {
        for document in [
            "a = \n",
            "a\n",
            "= 1\n",
            "\"unterminated = 1\n",
            "a = \"bad\\escape\"\n",
            "a = \"ctrl\u{1}char\"\n",
            "a = 00\n",
            "a = _1\n",
            "a = 1_\n",
            "a = 0x\n",
            "[a\n",
            "[a.]\n",
            "a = truex\n",
            "a = 1 trailing\n",
        ] {
            assert!(parse(document).is_err(), "{document:?} should not parse");
        }
    }

    #[test]
    fn refuses_integer_overflow() {
        assert_eq!(
            parse("a = 9223372036854775808\n").unwrap_err().kind,
            ParseErrorKind::OutOfRange
        );
    }

    #[test]
    fn line_numbers_are_reported() {
        let error = parse("# fine\n\nbogus = \n").unwrap_err();
        assert_eq!(error.line, 3);
    }
}
