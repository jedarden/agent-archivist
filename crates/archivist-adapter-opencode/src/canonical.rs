// SPDX-License-Identifier: Apache-2.0

//! RFC 8785 canonical JSON over the projection's value domain.
//!
//! The projection's records are canonical JSON (plan Phase 6B's "RFC 8785
//! JSONL" and requirement CAP-004's versioned projection): byte-stable, so
//! a digest of a record means the same bytes for every reader and every
//! re-projection of an unchanged store. The serialization follows
//! RFC 8785 §3.2 as `archivist-protocol`'s wire canonicalization does:
//!
//! - object members are sorted by UTF-16 code unit sequence (§3.2.3);
//! - no insignificant whitespace;
//! - strings use the short escapes and `\u00xx` (lowercase hex) for the
//!   remaining control characters, all other characters literal UTF-8;
//! - integers render in plain decimal;
//! - numbers that are not integers render as ECMAScript `Number::toString`
//!   does (§3.2.2.3) — the shortest form that round-trips, decimal between
//!   `1e-6` and `1e21`, exponential outside it, and `-0` as `0`.
//!
//! The value domain differs from the wire envelope's on purpose: a store
//! cell can be a 64-bit float (`session.cost` is `REAL`), so this model
//! carries one. A non-finite float has no RFC 8785 form and is rejected at
//! construction — `SQLite` stores `NaN` as `NULL`, but it stores infinities,
//! so the rejection is reachable and must be explicit rather than silent
//! (the projection fails closed on a field it cannot represent faithfully).
//!
//! Member names come only from this crate's compiled-in allowlists and
//! structural tokens, but the ordering is implemented generally over
//! UTF-16 code units so nothing depends on that.

use std::cmp::Ordering;

/// A value in the projection's JSON domain: everything an allowlisted
/// store cell can project to, plus the two structural composites.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    /// The JSON `null` literal — a NULL cell's projected form.
    Null,
    /// A signed 64-bit integer cell.
    Integer(i64),
    /// A finite 64-bit float cell.
    Real(f64),
    /// A text cell's decoded UTF-8.
    Text(String),
    /// An array — the record's ordered key tuple.
    Array(Vec<Json>),
    /// An object with uniquely named members kept in canonical order.
    Object(Object),
}

/// An object whose members are kept sorted by UTF-16 code unit order.
///
/// Insertion is the only way in, and a duplicate name replaces nothing:
/// the projection builds each record's member set from a compiled-in
/// allowlist that is asserted duplicate-free, so a duplicate is a
/// programmer error and panics rather than silently dropping a field.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Object {
    members: Vec<(String, Json)>,
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

    /// Insert `name` → `value`, keeping the canonical order.
    ///
    /// # Panics
    ///
    /// When `name` is already present. The projection's member sets come
    /// from allowlists asserted duplicate-free; a duplicate would mean a
    /// field was silently dropped from a record, which must be loud.
    pub fn insert(&mut self, name: &str, value: Json) {
        match self.slot(name) {
            Ok(_) => panic!("duplicate object member {name}"),
            Err(at) => self.members.insert(at, (name.to_owned(), value)),
        }
    }

    /// The position of `name`, or the insertion slot that keeps the sort.
    fn slot(&self, name: &str) -> Result<usize, usize> {
        self.members
            .binary_search_by(|(existing, _)| cmp_utf16(existing, name))
    }

    /// Iterate the members in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Json)> {
        self.members
            .iter()
            .map(|(name, value)| (name.as_str(), value))
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

impl Json {
    /// Append the RFC 8785 canonical serialization to `out`.
    ///
    /// # Panics
    ///
    /// Panics when a [`Json::Real`] contains a non-finite value. Such a value
    /// has no RFC 8785 representation and is rejected by the projection
    /// before a record reaches this writer.
    pub fn write_canonical(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Self::Real(value) => {
                // Non-finite floats are rejected at construction; the
                // panic is unreachable through the public constructors.
                let rendered = render_real(*value).expect("a constructed real is finite");
                out.extend_from_slice(rendered.as_bytes());
            }
            Self::Text(text) => write_string(text, out),
            Self::Array(items) => {
                out.push(b'[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    item.write_canonical(out);
                }
                out.push(b']');
            }
            Self::Object(object) => {
                out.push(b'{');
                for (index, (name, value)) in object.members.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    write_string(name, out);
                    out.push(b':');
                    value.write_canonical(out);
                }
                out.push(b'}');
            }
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

/// The ECMAScript `Number::toString` form of `value` (RFC 8785 §3.2.2.3),
/// or `None` for a non-finite value, which has no canonical form.
///
/// Rust's `{:e}` already produces the shortest digit sequence that
/// round-trips, which is the digit selection ECMA-262 specifies; the work
/// here is reassembling that digit string into the standard's notation
/// rules. The round-trip is asserted by the module's tests.
fn render_real(value: f64) -> Option<String> {
    if !value.is_finite() {
        return None;
    }
    if value == 0.0 {
        // Both zeros render as "0" (RFC 8785: -0 → "0").
        return Some("0".to_owned());
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("{:e} always renders an exponent");
    let exponent: i32 = exponent.parse().expect("{:e} exponent parses");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    // The value is d.ddd × 10^exponent, i.e. digits × 10^(n - k) with
    // k = digits.len() and n = exponent + 1 (ECMA-262's n).
    let k = i32::try_from(digits.len()).expect("shortest digits are bounded");
    let n = exponent + 1;
    let magnitude = if k <= n && n <= 21 {
        // Whole number: the digits followed by n - k zeros.
        let zeros = usize::try_from(n - k).expect("n >= k");
        let mut text = digits.clone();
        text.extend(std::iter::repeat_n('0', zeros));
        text
    } else if n > 0 && n <= 21 {
        // Decimal point inside the digit string. The whole-number branch
        // above took every `k <= n` value in range, so here `k > n`: the
        // point always lands inside the digits, never past their end.
        let point = usize::try_from(n).expect("n > 0");
        let mut text = String::with_capacity(digits.len() + 1);
        text.push_str(&digits[..point]);
        text.push('.');
        text.push_str(&digits[point..]);
        text
    } else if (-5..=0).contains(&n) {
        // Fraction below one: "0." + leading zeros + the digits.
        let zeros = usize::try_from(-n).expect("n < 0");
        let mut text = String::from("0.");
        text.extend(std::iter::repeat_n('0', zeros));
        text.push_str(&digits);
        text
    } else {
        // Exponential notation: one digit, a fraction when there is one,
        // then e±(n - 1).
        let mut text = String::with_capacity(digits.len() + 6);
        text.push_str(&digits[..1]);
        if digits.len() > 1 {
            text.push('.');
            text.push_str(&digits[1..]);
        }
        let mantissa_exponent = n - 1;
        text.push('e');
        if mantissa_exponent >= 0 {
            text.push('+');
        }
        text.push_str(&mantissa_exponent.to_string());
        text
    };
    Some(if negative {
        format!("-{magnitude}")
    } else {
        magnitude
    })
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

    /// The RFC 8785 §3.2.2.3 rendering of a float: shortest form that
    /// round-trips, in the standard's notation.
    #[test]
    fn reals_render_in_ecmascript_notation() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.0, "-1"),
            (2.5, "2.5"),
            (0.5, "0.5"),
            (123.456, "123.456"),
            (1e-6, "0.000001"),
            (1e-7, "1e-7"),
            (1e20, "100000000000000000000"),
            (1e21, "1e+21"),
            (1e30, "1e+30"),
            // A two-digit mantissa at a large exponent: the whole-number
            // branch must not claim it (n > 21), and the exponential
            // reassembly must not slice past the digit string.
            (9.9e245, "9.9e+245"),
            (1.234_567_89e100, "1.23456789e+100"),
            (4.50, "4.5"),
            (1.0e-28, "1e-28"),
            // RFC 8785's own appendix B vectors over the double domain.
            (333_333_333.333_333_3, "333333333.3333333"),
            (2.225_073_858_507_201_4e-308, "2.2250738585072014e-308"),
            (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
            (2.980_232_238_769_531e8, "298023223.8769531"),
        ];
        for (value, expected) in cases {
            let rendered = render_real(*value).expect("the case is finite");
            assert_eq!(&rendered, expected, "rendering {value:e}");
            // The rendering round-trips bit-exactly — except for the two
            // zeros, whose canonical form is deliberately `0` (RFC 8785
            // maps -0 to 0) and so parses back to +0.
            if *value != 0.0 {
                let reparsed: f64 = rendered.parse().expect("the rendering parses");
                assert_eq!(reparsed.to_bits(), value.to_bits(), "round-trip {value:e}");
            }
        }
    }

    #[test]
    fn non_finite_reals_have_no_canonical_form() {
        assert!(render_real(f64::NAN).is_none());
        assert!(render_real(f64::INFINITY).is_none());
        assert!(render_real(f64::NEG_INFINITY).is_none());
    }

    /// A sweep of values reassembles to the exact bit pattern it came
    /// from: the notation rules may never perturb the digits.
    #[test]
    fn every_finite_real_rendering_round_trips_bit_exactly() {
        let mut bits = 0x4330_0000_0000_0001u64; // a spread of magnitudes
        for _ in 0..20_000 {
            let value = f64::from_bits(bits);
            if value.is_finite() && value != 0.0 {
                let rendered = render_real(value).expect("finite");
                let reparsed: f64 = rendered.parse().expect("the rendering parses");
                assert_eq!(
                    reparsed.to_bits(),
                    bits,
                    "round-trip broke for {value:e} -> {rendered}"
                );
            }
            bits = bits
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
        }
    }

    #[test]
    fn canonical_form_sorts_members_and_escapes_strings() {
        let mut object = Object::new();
        object.insert("zeta", Json::Text("last".to_owned()));
        object.insert("alpha", Json::Null);
        object.insert("middle", Json::Integer(-12));
        let value = Json::Object(object);
        assert_eq!(
            String::from_utf8(value.canonical_bytes()).expect("utf8"),
            r#"{"alpha":null,"middle":-12,"zeta":"last"}"#
        );

        // Escaping: short escapes for the named controls, \u00xx lowercase
        // for the rest, literal UTF-8 beyond ASCII.
        let escaped =
            Json::Text("quote\" back\\ new\n line\r tab\t del\u{7f} ctrl\u{1} é\n".to_owned());
        assert_eq!(
            String::from_utf8(escaped.canonical_bytes()).expect("utf8"),
            "\"quote\\\" back\\\\ new\\n line\\r tab\\t del\u{7f} ctrl\\u0001 é\\n\""
        );
    }

    #[test]
    fn utf16_member_order_matches_rfc_8785() {
        // Code-unit order, not code-point order: U+10000's leading
        // surrogate (0xD800) sorts below U+FFFD (0xFFFD), so the non-BMP
        // character comes first even though its code point is the larger.
        let mut object = Object::new();
        object.insert("\u{fffd}", Json::Null);
        object.insert("\u{10000}", Json::Null);
        let bytes = Json::Object(object).canonical_bytes();
        let rendered = String::from_utf8(bytes).expect("utf8");
        assert_eq!(rendered, "{\"\u{10000}\":null,\"\u{fffd}\":null}");
    }

    #[test]
    fn integers_render_in_plain_decimal_and_arrays_compactly() {
        let value = Json::Array(vec![
            Json::Integer(0),
            Json::Integer(i64::MIN),
            Json::Integer(i64::MAX),
            Json::Null,
        ]);
        assert_eq!(
            String::from_utf8(value.canonical_bytes()).expect("utf8"),
            "[0,-9223372036854775808,9223372036854775807,null]"
        );
    }

    #[test]
    fn duplicate_members_are_a_programmer_error() {
        let mut object = Object::new();
        object.insert("a", Json::Null);
        let result = std::panic::catch_unwind(move || {
            object.insert("a", Json::Null);
        });
        assert!(result.is_err(), "a duplicate member must be loud");
    }
}
