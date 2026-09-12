// SPDX-License-Identifier: Apache-2.0

//! RFC 8785 canonical JSON over the protocol's no-float value domain.
//!
//! The protocol's value domain is exactly: objects with text member names,
//! integers, strings, arrays, booleans, and `null`. Floating-point values
//! appear nowhere in any protocol structure (plan Section 7.1), so the value
//! model has no float variant at all: a JSON number with a fraction or
//! exponent is a domain violation the parser reports separately from
//! malformed syntax, because the two map to different wire errors
//! (`envelope.schema_invalid` vs `envelope.malformed`; corpus
//! `canonicalization.json` → `rejections`).
//!
//! Canonical serialization follows RFC 8785 as consumed by every digest in
//! the conformance corpus:
//!
//! - object members are sorted by UTF-16 code unit sequence (RFC 8785 §3.2.3;
//!   identical to byte order for the protocol's ASCII member names, and
//!   implemented generally so nothing depends on that coincidence);
//! - no insignificant whitespace;
//! - strings use the short escapes (`\"` `\\` `\b` `\f` `\n` `\r` `\t`) and
//!   `\u00xx` (lowercase hex) for the remaining control characters, with all
//!   other characters as literal UTF-8;
//! - integers render in plain decimal.
//!
//! Parsing accepts non-canonical transmission (reordered members, arbitrary
//! whitespace, escaped non-control characters) and canonicalization restores
//! the byte form every digest covers — corpus proof
//! `valid-reordered-envelope-framing`. Duplicate member names, lone
//! surrogates, and invalid UTF-8 are rejected outright: they have no RFC 8785
//! canonicalization because parsers disagree on the value.
//!
//! Parsing is bounded: a maximum input length and a maximum nesting depth,
//! both set by the caller ([`parse_with_limits`]). The defaults are
//! documented on [`DEFAULT_MAX_BYTES`] and [`DEFAULT_MAX_DEPTH`].

use std::cmp::Ordering;

/// Default input bound: the multipart part cap from plan Section 7.6.
///
/// The envelope itself is capped at 65,536 *canonical* bytes (a semantic
/// check the [`crate::envelope`] layer owns); this parser bound exists so a
/// hostile part cannot make the parser walk unbounded input before that
/// semantic check runs.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Default nesting bound.
///
/// The deepest legal protocol structure is three levels (receipt →
/// certificate → member); 64 is generous headroom while still bounding
/// recursive descent.
pub const DEFAULT_MAX_DEPTH: usize = 64;

/// A value in the protocol's no-float domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// The JSON `null` literal.
    Null,
    /// A boolean.
    Bool(bool),
    /// An integer in i64 range (the protocol pins the narrower `u63` at the
    /// field level; negative integers parses are kept so validation can
    /// report them rather than the parser guessing).
    Int(i64),
    /// A text string (always valid UTF-8; lone surrogates never parse).
    Text(String),
    /// An array of values.
    Array(Vec<Value>),
    /// An object with uniquely named members kept in canonical order.
    Object(Object),
}

/// An object whose members are kept sorted by UTF-16 code unit order with
/// duplicate names rejected at insertion.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Object {
    members: Vec<(String, Value)>,
}

impl Object {
    /// An empty object.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of members.
    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the object has no members.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Insert `name` → `value`, rejecting a duplicate `name`.
    ///
    /// # Errors
    /// [`ParseError::DuplicateMember`] when `name` is already present —
    /// duplicates have no canonicalization (RFC 8785 §3.2.2 expects unique
    /// names; JSON parsers disagree on which value wins).
    pub fn insert(&mut self, name: &str, value: Value) -> Result<(), ParseError> {
        match self.slot(name) {
            Ok(_) => Err(ParseError::DuplicateMember),
            Err(at) => {
                self.members.insert(at, (name.to_owned(), value));
                Ok(())
            }
        }
    }

    /// Insert or replace `name` → `value` (an upsert for builders that
    /// mutate an existing member in place; the canonical position is kept
    /// either way).
    pub fn set(&mut self, name: &str, value: Value) {
        match self.slot(name) {
            Ok(at) => self.members[at].1 = value,
            Err(at) => self.members.insert(at, (name.to_owned(), value)),
        }
    }

    /// Look up a member.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.slot(name).ok().map(|at| &self.members[at].1)
    }

    /// Remove and return a member — the operation the receipt and
    /// certificate covered-byte constructions need (canonical bytes minus the
    /// signature member).
    #[must_use]
    pub fn remove(&mut self, name: &str) -> Option<Value> {
        match self.slot(name) {
            Ok(at) => Some(self.members.remove(at).1),
            Err(_) => None,
        }
    }

    /// Whether `name` is present.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Iterate members in canonical (UTF-16) order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.members
            .iter()
            .map(|(name, value)| (name.as_str(), value))
    }

    /// Binary-search position for `name`: `Ok(at)` when present, `Err(at)`
    /// when absent (the insertion point).
    fn slot(&self, name: &str) -> Result<usize, usize> {
        self.members
            .binary_search_by(|(existing, _)| cmp_utf16(existing, name))
    }
}

/// Compare two strings as sequences of UTF-16 code units (RFC 8785 §3.2.3).
fn cmp_utf16(a: &str, b: &str) -> Ordering {
    let mut left = a.encode_utf16();
    let mut right = b.encode_utf16();
    loop {
        match (left.next(), right.next()) {
            (Some(x), Some(y)) => {
                let ordering = x.cmp(&y);
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Why a byte sequence is not a protocol value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// Malformed JSON syntax, a duplicate member name, a lone surrogate, or
    /// invalid UTF-8 in a string: no canonicalization exists, so the bytes
    /// are rejected rather than best-effort parsed.
    Malformed {
        /// Byte offset where parsing stopped.
        offset: usize,
        /// What was wrong there.
        reason: &'static str,
    },
    /// A number outside the protocol's integer domain (fraction, exponent, or
    /// beyond i64): well-formed JSON, but no protocol structure contains a
    /// floating-point value.
    NumberOutsideDomain {
        /// Byte offset of the number.
        offset: usize,
    },
    /// Input longer than the configured bound.
    LengthExceeded,
    /// Nesting deeper than the configured bound.
    DepthExceeded {
        /// Byte offset where the depth limit tripped.
        offset: usize,
    },
    /// Duplicate member name at insertion time (the object-builder path).
    DuplicateMember,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { offset, reason } => write!(f, "malformed at byte {offset}: {reason}"),
            Self::NumberOutsideDomain { offset } => {
                write!(f, "number outside the integer domain at byte {offset}")
            }
            Self::LengthExceeded => write!(f, "input exceeds the length bound"),
            Self::DepthExceeded { offset } => {
                write!(f, "nesting exceeds the depth bound at byte {offset}")
            }
            Self::DuplicateMember => write!(f, "duplicate member name"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse `input` with the default bounds ([`DEFAULT_MAX_BYTES`],
/// [`DEFAULT_MAX_DEPTH`]).
///
/// # Errors
/// Any [`ParseError`] describing the first violation.
pub fn parse(input: &[u8]) -> Result<Value, ParseError> {
    parse_with_limits(input, DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH)
}

/// Parse `input` under explicit `max_bytes` and `max_depth` bounds.
///
/// # Errors
/// Any [`ParseError`] describing the first violation.
pub fn parse_with_limits(
    input: &[u8],
    max_bytes: usize,
    max_depth: usize,
) -> Result<Value, ParseError> {
    if input.len() > max_bytes {
        return Err(ParseError::LengthExceeded);
    }
    let mut parser = Parser {
        bytes: input,
        pos: 0,
        max_depth,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.malformed("trailing content after the value"));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    max_depth: usize,
}

impl Parser<'_> {
    fn malformed(&self, reason: &'static str) -> ParseError {
        ParseError::Malformed {
            offset: self.pos,
            reason,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(0x20 | 0x09 | 0x0a | 0x0d)) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), ParseError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(self.malformed("unexpected byte"))
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), ParseError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(self.malformed("unrecognized literal"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ParseError> {
        if depth > self.max_depth {
            return Err(ParseError::DepthExceeded { offset: self.pos });
        }
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Value::Text(self.string()?)),
            Some(b't') => {
                self.literal("true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal("false")?;
                Ok(Value::Bool(false))
            }
            Some(b'n') => {
                self.literal("null")?;
                Ok(Value::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(self.malformed("expected a value")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'{')?;
        let mut out = Object::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(out));
        }
        loop {
            self.skip_ws();
            let name = self.string()?;
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            out.insert(&name, value)?;
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.malformed("expected ',' or '}' in object")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ParseError> {
        self.expect(b'[')?;
        let mut out = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(out));
        }
        loop {
            self.skip_ws();
            out.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.malformed("expected ',' or ']' in array")),
            }
        }
    }

    /// Parse a JSON string. Returns the decoded UTF-8 text.
    fn string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let start = self.pos;
            // Absorb a run of plain bytes; validate UTF-8 afterwards.
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            if self.pos > start {
                let chunk = &self.bytes[start..self.pos];
                match std::str::from_utf8(chunk) {
                    Ok(text) => out.push_str(text),
                    Err(_) => return Err(self.malformed("string is not valid UTF-8")),
                }
            }
            match self.peek() {
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    self.escape(&mut out)?;
                }
                Some(c) if c < 0x20 => {
                    return Err(self.malformed("raw control character in string"));
                }
                _ => return Err(self.malformed("unterminated string")),
            }
        }
    }

    /// Decode one escape sequence (the backslash is already consumed).
    fn escape(&mut self, out: &mut String) -> Result<(), ParseError> {
        let simple = match self.peek() {
            Some(b'"') => Some('"'),
            Some(b'\\') => Some('\\'),
            Some(b'/') => Some('/'),
            Some(b'b') => Some('\u{8}'),
            Some(b'f') => Some('\u{c}'),
            Some(b'n') => Some('\n'),
            Some(b'r') => Some('\r'),
            Some(b't') => Some('\t'),
            Some(b'u') => None,
            _ => return Err(self.malformed("unknown escape")),
        };
        if let Some(c) = simple {
            self.pos += 1;
            out.push(c);
            return Ok(());
        }
        self.pos += 1;
        let first = self.hex4()?;
        if (0xd800..0xdc00).contains(&first) {
            // High surrogate: a low surrogate must follow.
            if self.peek() != Some(b'\\') {
                return Err(self.malformed("lone surrogate"));
            }
            self.pos += 1;
            if self.peek() != Some(b'u') {
                return Err(self.malformed("lone surrogate"));
            }
            self.pos += 1;
            let second = self.hex4()?;
            if !(0xdc00..0xe000).contains(&second) {
                return Err(self.malformed("invalid low surrogate"));
            }
            let combined = 0x1_0000 + ((first - 0xd800) << 10) + (second - 0xdc00);
            let c = char::from_u32(combined).ok_or_else(|| self.malformed("invalid code point"))?;
            out.push(c);
            Ok(())
        } else if (0xdc00..0xe000).contains(&first) {
            Err(self.malformed("lone surrogate"))
        } else {
            let c = char::from_u32(first).ok_or_else(|| self.malformed("invalid code point"))?;
            out.push(c);
            Ok(())
        }
    }

    /// Decode a four-hex-digit `\u` payload.
    fn hex4(&mut self) -> Result<u32, ParseError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(self.malformed("truncated \\u escape"));
        }
        let mut value = 0u32;
        for _ in 0..4 {
            let c = self.bytes[self.pos];
            let digit = match c {
                b'0'..=b'9' => u32::from(c - b'0'),
                b'a'..=b'f' => u32::from(c - b'a' + 10),
                b'A'..=b'F' => u32::from(c - b'A' + 10),
                _ => return Err(self.malformed("invalid hex digit in \\u escape")),
            };
            value = value * 16 + digit;
            self.pos += 1;
        }
        Ok(value)
    }

    /// Parse a number. Fraction or exponent is a domain violation, not a
    /// syntax error; integers must fit i64.
    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                // Strict JSON: an integer part of "0" cannot be followed by
                // another digit.
                if matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    return Err(self.malformed("leading zero in number"));
                }
            }
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.malformed("invalid number")),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(ParseError::NumberOutsideDomain { offset: start });
        }
        let text = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.malformed("invalid number"))?;
        text.parse::<i64>()
            .map(Value::Int)
            .map_err(|_| ParseError::NumberOutsideDomain { offset: start })
    }
}

impl Value {
    /// Append the RFC 8785 canonical serialization to `out`.
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(true) => out.extend_from_slice(b"true"),
            Self::Bool(false) => out.extend_from_slice(b"false"),
            Self::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Self::Text(text) => write_string(text, out),
            Self::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    item.write_canonical(out);
                }
                out.push(b']');
            }
            Self::Object(object) => object.write_canonical(out),
        }
    }

    /// The RFC 8785 canonical bytes of this value.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.write_canonical(&mut out);
        out
    }
}

impl Object {
    /// Append the canonical serialization (members are stored pre-sorted).
    fn write_canonical(&self, out: &mut Vec<u8>) {
        out.push(b'{');
        for (i, (name, value)) in self.members.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            write_string(name, out);
            out.push(b':');
            value.write_canonical(out);
        }
        out.push(b'}');
    }
}

/// Serialize one string with RFC 8785 escaping.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in text.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                let value = c as u32;
                out.push(HEX[((value >> 4) & 0xf) as usize]);
                out.push(HEX[(value & 0xf) as usize]);
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_matches_rfc8785() {
        let mut object = Object::new();
        object.insert("b", Value::Int(2)).unwrap();
        object.insert("a", Value::Int(1)).unwrap();
        object
            .insert("z", Value::Text("x\"y\\z\n\t\u{1}\u{1f}".into()))
            .unwrap();
        object
            .insert("é", Value::Text("literal ünïcode".into()))
            .unwrap();
        object.insert("empty", Value::Array(Vec::new())).unwrap();
        let bytes = Value::Object(object).canonical_bytes();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"a\":1,\"b\":2,\"empty\":[],\"z\":\"x\\\"y\\\\z\\n\\t\\u0001\\u001f\",\"é\":\"literal ünïcode\"}"
        );
    }

    #[test]
    fn parse_accepts_noncanonical_transmission() {
        let parsed = parse(b"{ \"b\" : 2 ,\n\"a\" : 1 }").unwrap();
        assert_eq!(parsed.canonical_bytes(), b"{\"a\":1,\"b\":2}");
        // Escaped non-control characters decode and re-serialize literally.
        let parsed = parse(br#"{"s":"caf\u00e9"}"#).unwrap();
        assert_eq!(parsed.canonical_bytes(), "{\"s\":\"café\"}".as_bytes());
    }

    #[test]
    fn rejects_no_canonicalization_forms() {
        // Duplicate member names.
        assert_eq!(parse(br#"{"a":1,"a":2}"#), Err(ParseError::DuplicateMember));
        // Lone surrogate.
        assert!(matches!(
            parse(br#"{"s":"\ud800"}"#),
            Err(ParseError::Malformed {
                reason: "lone surrogate",
                ..
            })
        ));
        assert!(matches!(
            parse("{\"s\":\"\\udc00\"}".as_bytes()),
            Err(ParseError::Malformed {
                reason: "lone surrogate",
                ..
            })
        ));
        // Floats: domain violation, distinct from malformed.
        assert_eq!(
            parse(br#"{"x":1.5}"#),
            Err(ParseError::NumberOutsideDomain { offset: 5 })
        );
        assert_eq!(
            parse(br#"{"x":1e3}"#),
            Err(ParseError::NumberOutsideDomain { offset: 5 })
        );
        // Beyond i64.
        assert!(matches!(
            parse(b"[99999999999999999999]"),
            Err(ParseError::NumberOutsideDomain { .. })
        ));
    }

    #[test]
    fn rejects_malformed_syntax() {
        for bad in [
            &b""[..],
            b"{",
            b"[1,]",
            b"{\"a\":}",
            b"nul",
            b"\"unterminated",
            b"{\"a\":1} trailing",
            b"\"\x00\" raw control",
        ] {
            assert!(parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn surrogate_pairs_decode() {
        let parsed = parse("\"\\ud83d\\ude00\"".as_bytes()).unwrap();
        assert_eq!(parsed, Value::Text("😀".into()));
        assert_eq!(parsed.canonical_bytes(), "\"😀\"".as_bytes());
    }

    #[test]
    fn bounds_are_enforced() {
        let deep = "[".repeat(10) + &"]".repeat(10);
        assert_eq!(
            parse_with_limits(deep.as_bytes(), 1024, 8),
            Err(ParseError::DepthExceeded { offset: 9 })
        );
        assert_eq!(
            parse_with_limits(b"123", 2, 8),
            Err(ParseError::LengthExceeded)
        );
    }

    #[test]
    fn utf16_order_sorts_astral_before_late_bmp() {
        // U+10000 (astral, high surrogate 0xD800) sorts before U+E000 in
        // UTF-16 code unit order, though after it in code point order.
        let mut object = Object::new();
        object.insert("\u{e000}", Value::Int(1)).unwrap();
        object.insert("\u{10000}", Value::Int(2)).unwrap();
        let text = String::from_utf8(Value::Object(object).canonical_bytes()).unwrap();
        assert_eq!(text, "{\"\u{10000}\":2,\"\u{e000}\":1}");
        // Round trip preserves the order.
        let reparsed = parse(text.as_bytes()).unwrap();
        assert_eq!(reparsed.canonical_bytes(), text.as_bytes());
    }
}
