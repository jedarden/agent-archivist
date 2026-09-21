// SPDX-License-Identifier: Apache-2.0

//! The source-fingerprint allowlist: the exact, embedded set of
//! adapter-detectable schema/version fingerprints one adapter supports, and
//! the fail-closed admission decision every read path must pass first
//! (plan `EC-08`, requirement CAP-002's documented plugin boundary).
//!
//! A fingerprint is a **content-free** token naming what an adapter can
//! detect about a source's layout — a schema version, a format generation,
//! a storage revision. It is not source content and not a coordinate: the
//! fleet inventory retained exactly these tokens as its aggregate
//! evidence, and the committed compatibility matrix names every supported
//! one. Because a fingerprint token is publishable, the denial type may
//! carry it — an operator who sees `unsupported` can file the token and
//! get an adapter update, without any transcript content having been
//! read to produce the report.
//!
//! The contract the rest of the SDK relies on: [`FingerprintAllowlist`] is
//! constructed once per adapter from a compile-time-constant list, is
//! non-empty (an adapter that supports nothing is a configuration error,
//! not an adapter), and admits only membership. There is deliberately no
//! "closest match", no prefix match, and no parse-anyway mode: an unknown
//! fingerprint reads no projected content and reports `unsupported`
//! through [`ScanClassification::FingerprintUnsupported`].
//!
//! [`ScanClassification::FingerprintUnsupported`]: crate::status::ScanClassification::FingerprintUnsupported

use std::fmt;
use std::str::FromStr;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::GrammarError;

use crate::status::ScanClassification;

/// The largest number of fingerprints one adapter may pin. The allowlist is
/// embedded per adapter and published in the compatibility matrix, so it
/// stays small by construction; the cap keeps a malformed descriptor from
/// growing without bound before validation rejects it.
pub const MAX_FINGERPRINTS: usize = 32;

/// Why an allowlist could not be constructed. Closed and content-free: a
/// duplicate names nothing (the caller supplied the list), and the counts
/// are self-explanatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FingerprintError {
    /// The list was empty: an adapter must pin at least one supported
    /// fingerprint, because an empty allowlist would silently turn every
    /// source `unsupported`.
    Empty,
    /// The list contained the same fingerprint twice.
    Duplicate,
    /// The list exceeded [`MAX_FINGERPRINTS`] entries.
    TooMany,
    /// A token failed the fingerprint grammar.
    Malformed,
}

impl fmt::Display for FingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::Empty => "fingerprint_allowlist_empty",
            Self::Duplicate => "fingerprint_allowlist_duplicate",
            Self::TooMany => "fingerprint_allowlist_too_many",
            Self::Malformed => "fingerprint_allowlist_malformed",
        };
        f.write_str(token)
    }
}

impl std::error::Error for FingerprintError {}

/// One adapter-detectable schema/version fingerprint
/// (`source-fingerprint`): 1–128 characters of
/// `[A-Za-z0-9._:-]` with an alphanumeric first character.
///
/// The token is chosen by the adapter and must be stable across adapter
/// versions — it names a source layout, not a release. Uppercase letters
/// are allowed (schema names often carry them) but path separators,
/// whitespace, and quote characters are rejected by the grammar, so a
/// fingerprint can never smuggle a coordinate into status or a matrix.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SourceFingerprint(String);

impl SourceFingerprint {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] when the grammar fails.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        if fingerprint_grammar(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(GrammarError::NotCanonical)
        }
    }

    /// The canonical token.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SourceFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SourceFingerprint {
    type Err = GrammarError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

fn fingerprint_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 128 || !raw[0].is_ascii_alphanumeric() {
        return false;
    }
    raw[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// The exact supported-fingerprint set one adapter embeds (plan Section 6:
/// "each released adapter embeds the exact supported fingerprint
/// allowlist; an unknown fingerprint fails closed as `unsupported`
/// instead of attempting a best-effort parse").
///
/// Constructed once from the adapter's compile-time list; membership is
/// the only query. The set is kept sorted so the canonical JSON — the
/// compatibility matrix's per-adapter row — is byte-stable regardless of
/// how the constant was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FingerprintAllowlist {
    fingerprints: Vec<SourceFingerprint>,
}

impl FingerprintAllowlist {
    /// Build the allowlist from an iterable of already-validated
    /// fingerprints.
    ///
    /// # Errors
    /// [`FingerprintError::Empty`] for an empty list,
    /// [`FingerprintError::Duplicate`] for a repeated fingerprint, and
    /// [`FingerprintError::TooMany`] beyond [`MAX_FINGERPRINTS`] entries.
    pub fn new<I, F>(fingerprints: I) -> Result<Self, FingerprintError>
    where
        I: IntoIterator<Item = F>,
        F: Into<SourceFingerprint>,
    {
        Self::from_validated(fingerprints.into_iter().map(Into::into).collect())
    }

    /// Build the allowlist by parsing token strings, so an adapter can
    /// embed plain literals.
    ///
    /// # Errors
    /// [`FingerprintError::Malformed`] when any token fails the
    /// fingerprint grammar, in addition to [`FingerprintError`]'s
    /// set-level rules.
    pub fn parse<I, S>(tokens: I) -> Result<Self, FingerprintError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut list = Vec::new();
        for token in tokens {
            list.push(
                SourceFingerprint::parse(token.as_ref())
                    .map_err(|_| FingerprintError::Malformed)?,
            );
        }
        Self::from_validated(list)
    }

    /// Apply the set-level rules to an already grammar-validated list:
    /// non-empty, within the cap, duplicate-free, and canonically sorted.
    fn from_validated(mut list: Vec<SourceFingerprint>) -> Result<Self, FingerprintError> {
        if list.is_empty() {
            return Err(FingerprintError::Empty);
        }
        if list.len() > MAX_FINGERPRINTS {
            return Err(FingerprintError::TooMany);
        }
        list.sort_unstable();
        if list.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(FingerprintError::Duplicate);
        }
        Ok(Self { fingerprints: list })
    }

    /// The fail-closed admission decision: is `observed` on this
    /// allowlist?
    ///
    /// Every path that would read projected content passes here first;
    /// a denial must stop the read, not degrade it (plan `EC-08`).
    ///
    /// # Errors
    /// [`UnsupportedFingerprint`] carrying the observed token, so the
    /// unsupported state can be reported without reading anything else
    /// from the source.
    pub fn admit(&self, observed: &SourceFingerprint) -> Result<(), UnsupportedFingerprint> {
        if self.fingerprints.contains(observed) {
            Ok(())
        } else {
            Err(UnsupportedFingerprint {
                fingerprint: observed.clone(),
            })
        }
    }

    /// Whether `observed` is on the allowlist.
    #[must_use]
    pub fn contains(&self, observed: &SourceFingerprint) -> bool {
        self.fingerprints.contains(observed)
    }

    /// Iterate the supported fingerprints in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &SourceFingerprint> {
        self.fingerprints.iter()
    }

    /// The number of supported fingerprints.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fingerprints.len()
    }

    /// Whether no fingerprints are supported — always false for a
    /// constructed allowlist, which must be non-empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fingerprints.is_empty()
    }

    /// The compatibility-matrix row: the supported tokens as a sorted
    /// JSON array of fixed shape.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Array(
            self.fingerprints
                .iter()
                .map(|fingerprint| Value::Text(fingerprint.as_str().to_owned()))
                .collect(),
        )
    }
}

/// The `EC-08` denial: the observed fingerprint is not on the adapter's
/// allowlist. Carries the token and nothing else — the fingerprint is
/// content-free by grammar, and no projected content was read to produce
/// this denial.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedFingerprint {
    /// The observed, unsupported fingerprint token.
    pub fingerprint: SourceFingerprint,
}

impl UnsupportedFingerprint {
    /// The scan classification this denial forces: `unsupported`, with no
    /// measurement and no content read.
    #[must_use]
    pub fn classification(&self) -> ScanClassification {
        ScanClassification::FingerprintUnsupported
    }

    /// The coverage state this denial forces (requirement CAP-010's
    /// `unsupported`, distinct from `failed`).
    #[must_use]
    pub fn coverage(&self) -> crate::status::CoverageState {
        crate::status::CoverageState::Unsupported
    }
}

impl fmt::Display for UnsupportedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported source fingerprint {}", self.fingerprint)
    }
}

impl std::error::Error for UnsupportedFingerprint {}

/// The content-free summary object one denial contributes to a report:
/// the classification token plus the observed fingerprint token, and no
/// other field.
#[must_use]
pub fn unsupported_report(denial: &UnsupportedFingerprint) -> Value {
    let mut object = Object::new();
    object.set(
        "classification",
        Value::Text(denial.classification().token().to_owned()),
    );
    object.set(
        "observed_fingerprint",
        Value::Text(denial.fingerprint.as_str().to_owned()),
    );
    Value::Object(object)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprints_are_closed_vocabulary_tokens() {
        assert!(SourceFingerprint::parse("claude-jsonl-v1").is_ok());
        assert!(SourceFingerprint::parse("Schema.2026_09:b").is_ok());
        // Path syntax, whitespace, quotes, empty, leading separator.
        assert!(SourceFingerprint::parse("/etc/passwd").is_err());
        assert!(SourceFingerprint::parse("has space").is_err());
        assert!(SourceFingerprint::parse("\"quoted\"").is_err());
        assert!(SourceFingerprint::parse("").is_err());
        assert!(SourceFingerprint::parse("-leading").is_err());
        assert!(SourceFingerprint::parse(&"x".repeat(129)).is_err());
    }

    #[test]
    fn allowlists_are_non_empty_sorted_and_deduplicated() {
        assert_eq!(
            FingerprintAllowlist::parse([] as [&str; 0]),
            Err(FingerprintError::Empty)
        );
        assert_eq!(
            FingerprintAllowlist::parse(["a-v1", "a-v1"]),
            Err(FingerprintError::Duplicate)
        );
        assert_eq!(
            FingerprintAllowlist::parse([""; 0].iter().filter(|t| !t.is_empty())),
            Err(FingerprintError::Empty)
        );
        let too_many: Vec<String> = (0..=MAX_FINGERPRINTS).map(|i| format!("f{i}")).collect();
        assert_eq!(
            FingerprintAllowlist::parse(too_many),
            Err(FingerprintError::TooMany)
        );

        let list = FingerprintAllowlist::parse(["b-v2", "a-v1"]).expect("valid allowlist");
        let tokens: Vec<_> = list.iter().map(ToString::to_string).collect();
        assert_eq!(tokens, ["a-v1", "b-v2"]);
        assert_eq!(list.len(), 2);
        assert!(!list.is_empty());
        // The matrix row is byte-stable because the set is sorted at
        // construction, not at print time.
        assert_eq!(
            list.to_json().canonical_bytes(),
            br#"["a-v1","b-v2"]"#.to_vec()
        );
    }

    #[test]
    fn parse_rejects_a_malformed_token_without_admitting_anything() {
        // A malformed token is its own named refusal, distinct from the
        // set-level rules; the fingerprint grammar is the single place
        // tokens are checked.
        assert_eq!(
            FingerprintAllowlist::parse(["ok-v1", "bad token"]),
            Err(FingerprintError::Malformed)
        );
        assert_eq!(
            FingerprintAllowlist::parse(["/etc/passwd"]),
            Err(FingerprintError::Malformed)
        );
        // The set-level rules still govern well-formed token lists.
        assert_eq!(
            FingerprintAllowlist::parse(["a-v1", "a-v1"]),
            Err(FingerprintError::Duplicate)
        );
    }

    #[test]
    fn unknown_fingerprints_fail_closed_with_a_content_free_denial() {
        let list = FingerprintAllowlist::parse(["claude-jsonl-v1"]).expect("valid allowlist");
        let known = SourceFingerprint::parse("claude-jsonl-v1").expect("known");
        let unknown = SourceFingerprint::parse("claude-jsonl-v9").expect("parses, unsupported");
        assert!(list.admit(&known).is_ok());
        assert!(list.contains(&known));
        assert!(!list.contains(&unknown));

        let denial = list.admit(&unknown).expect_err("fails closed");
        assert_eq!(denial.fingerprint, unknown);
        assert_eq!(
            denial.classification(),
            ScanClassification::FingerprintUnsupported
        );
        assert_eq!(denial.coverage(), crate::status::CoverageState::Unsupported);
        // The denial report carries the token and the classification only.
        let report = unsupported_report(&denial);
        let text = String::from_utf8(report.canonical_bytes()).expect("utf8");
        assert!(text.contains("claude-jsonl-v9"));
        assert!(text.contains("fingerprint-unsupported"));
        assert_eq!(text.matches(':').count(), 2);
    }
}
