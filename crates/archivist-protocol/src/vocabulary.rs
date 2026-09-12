// SPDX-License-Identifier: Apache-2.0

//! The project-owned wire vocabulary: identifier grammars, digests, and the
//! closed v1 enum sets ([`schemas/v1/common.json`]).
//!
//! Every type here is owned by this crate — a validated newtype over text or
//! bytes, never a borrowed SDK shape — so the public protocol surface stays
//! replaceable-implementation-free (plan Section 4: "library selection is not
//! an excuse to expose SDK types across crate boundaries"). Construction
//! always validates the grammar from the pinned schemas; a value that
//! parsed is a value whose wire text is canonical, which is what the
//! derivation framing hashes ([`crate::derivation`]: identifiers hash as
//! their canonical wire text).
//!
//! The closed enums fail closed by construction: an unknown token has no
//! value of the enum to inhabit, so an unrecognized security- or
//! identity-bearing value is a parse failure, never a best-effort guess
//! (plan Section 7.1). Adding a token is a v1-compatible schema change that
//! lands here as a new variant plus its token mapping.
//!
//! [`schemas/v1/common.json`]: ../../../schemas/v1/common.json

use std::fmt;
use std::str::FromStr;

use crate::sha256::{decode_hex, encode_hex};

/// Why a candidate wire token is not a value of the target type.
///
/// The variants name the failed grammar; the record-level validation layer
/// wraps them with the field name to produce the wire error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrammarError {
    /// The token does not match the type's grammar (length, charset, shape).
    NotCanonical,
}

impl fmt::Display for GrammarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical => write!(f, "value does not match the canonical grammar"),
        }
    }
}

impl std::error::Error for GrammarError {}

fn is_lower_hex(c: u8) -> bool {
    c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
}

/// `^[0-9a-f]{8}-[0-9a-f]{4}-<v>[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
/// with `v` the UUID version nibble.
fn uuid_grammar(text: &str, version: u8) -> bool {
    let raw = text.as_bytes();
    if raw.len() != 36 {
        return false;
    }
    for (i, c) in raw.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            14 => {
                if *c != b'0' + version {
                    return false;
                }
            }
            19 => {
                if !matches!(c, b'8' | b'9' | b'a' | b'b') {
                    return false;
                }
            }
            _ => {
                if !is_lower_hex(*c) {
                    return false;
                }
            }
        }
    }
    true
}

/// Define a text-grammar newtype: stored wire text, validated at
/// construction, canonical by the grammar's construction.
macro_rules! text_newtype {
    ($(#[$doc:meta])* $name:ident, $validate:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Adopt `text` after verifying its grammar.
            ///
            /// # Errors
            /// [`GrammarError::NotCanonical`] when the grammar fails.
            pub fn parse(text: &str) -> Result<Self, GrammarError> {
                if ($validate)(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(GrammarError::NotCanonical)
                }
            }

            /// The canonical wire text (also what identity derivations hash).
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

text_newtype!(
    /// Issuer-created tenant identifier (`uuid-v4`; plan Section 7.4).
    TenantId,
    |t: &str| uuid_grammar(t, 4)
);
text_newtype!(
    /// Installation identifier (`uuid-v4`): both the origin client that
    /// captured a source and the uploader presenting a request carry this
    /// shape; origin scope contains cloned harness UUIDs (SID-002).
    ClientId,
    |t: &str| uuid_grammar(t, 4)
);
text_newtype!(
    /// Source-generation identifier (`uuid-v7`), minted when a source
    /// artifact is first observed or detected as replaced or rewritten
    /// (SID-003).
    GenerationId,
    |t: &str| uuid_grammar(t, 7)
);
text_newtype!(
    /// Frozen upload-request identifier (`uuid-v7`): generated when the
    /// spool entry is created, reused across every retry (ERR-025).
    RequestId,
    |t: &str| uuid_grammar(t, 7)
);
text_newtype!(
    /// Harness identifier (`short-token`: `^[a-z0-9][a-z0-9._-]{0,63}$`).
    HarnessId,
    |t: &str| short_token_grammar(t)
);
text_newtype!(
    /// Adapter identifier (`short-token`); an input to the artifact hash.
    AdapterId,
    |t: &str| short_token_grammar(t)
);
text_newtype!(
    /// Adapter projection version (`version-token`:
    /// `^[0-9A-Za-z._+-]{1,32}$`), preserved in provenance (plan Section
    /// 7.1).
    VersionToken,
    |t: &str| version_token_grammar(t)
);
text_newtype!(
    /// Opaque UTF-8 identifier (`opaque-id`): the harness's own session ID,
    /// the adapter's artifact ID, or a correlation ID. 1–1024 **bytes**,
    /// never case-folded, never Unicode-normalized, never trimmed — NFC and
    /// NFD lookalikes are distinct identifiers with distinct identities
    /// (plan Section 7.4).
    OpaqueId,
    |t: &str| !t.is_empty() && t.len() <= 1024
);
text_newtype!(
    /// UTC timestamp (`rfc3339-utc-timestamp`:
    /// `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$`).
    /// The wire text is stored verbatim — it is hashed as-is — and calendar
    /// validity is a separate semantic check
    /// ([`Timestamp::calendar_valid`], VAL-002).
    Timestamp,
    |t: &str| timestamp_grammar(t)
);
text_newtype!(
    /// The whole multipart `Content-Type` header value covered by the
    /// per-attempt signature (`^multipart/related; boundary=<token>$` with
    /// the boundary charset `[0-9A-Za-z'()+_,.:=?-]{1,70}`).
    ContentType,
    |t: &str| content_type_grammar(t)
);
text_newtype!(
    /// A stable two-segment error code (`domain.condition`,
    /// `^[a-z][a-z0-9_]{0,23}\.[a-z][a-z0-9_]{0,23}$`; ERR-007). Bounded by
    /// grammar rather than closed to the registry: codes are append-only
    /// within v1 and a well-formed unregistered code still parses (ERR-037).
    ErrorCode,
    |t: &str| error_code_grammar(t)
);
text_newtype!(
    /// A rendered safe message (`^[\\x20-\\x7a\\x7c\\x7e]+$`, at most 200
    /// characters, no braces — the placeholder delimiters): printable ASCII
    /// on one line, advisory only, never carrying transcript, path,
    /// provider, or identifier content (VAL-007, SEC-004).
    SafeMessage,
    |t: &str| t.chars().count() <= 200 && t.bytes().all(|b| matches!(b, 0x20..=0x7a | 0x7c | 0x7e))
);

fn short_token_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 64 {
        return false;
    }
    if !(raw[0].is_ascii_lowercase() || raw[0].is_ascii_digit()) {
        return false;
    }
    raw[1..]
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

fn version_token_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    !raw.is_empty()
        && raw.len() <= 32
        && raw
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'+' | b'-'))
}

fn timestamp_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.len() > 35 {
        return false;
    }
    let digits = |slice: &[u8]| slice.iter().all(u8::is_ascii_digit);
    // date 'T' time [ '.' fraction ] 'Z'
    if raw.len() < 20 {
        return false;
    }
    if raw[4] != b'-' || raw[7] != b'-' || raw[10] != b'T' || raw[13] != b':' || raw[16] != b':' {
        return false;
    }
    if !digits(&raw[0..4]) || !digits(&raw[5..7]) || !digits(&raw[8..10]) {
        return false;
    }
    if !digits(&raw[11..13]) || !digits(&raw[14..16]) || !digits(&raw[17..19]) {
        return false;
    }
    let tail = &raw[19..];
    match tail.last() {
        Some(b'Z') => {}
        _ => return false,
    }
    match tail.len() {
        1 => true,
        n if n >= 3 && tail[0] == b'.' => digits(&tail[1..n - 1]) && (2..=10).contains(&(n - 1)),
        _ => false,
    }
}

fn content_type_grammar(text: &str) -> bool {
    const PREFIX: &[u8] = b"multipart/related; boundary=";
    let raw = text.as_bytes();
    if raw.len() > 100 || !raw.starts_with(PREFIX) {
        return false;
    }
    let boundary = &raw[PREFIX.len()..];
    (1..=70).contains(&boundary.len())
        && boundary.iter().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'\'' | b'(' | b')' | b'+' | b'_' | b',' | b'.' | b':' | b'=' | b'?' | b'-'
                )
        })
}

fn error_code_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    let dot = match raw.iter().position(|c| *c == b'.') {
        Some(at) if at > 0 => at,
        _ => return false,
    };
    let segment = |slice: &[u8]| -> bool {
        if slice.is_empty() || slice.len() > 24 {
            return false;
        }
        if !(slice[0].is_ascii_lowercase()) {
            return false;
        }
        slice[1..]
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
    };
    segment(&raw[..dot]) && segment(&raw[dot + 1..])
}

impl Timestamp {
    /// Whether the stored timestamp is a real calendar instant (VAL-002
    /// semantic check; the grammar alone accepts `2026-13-45T99:99:99Z`).
    ///
    /// Leap years follow the Gregorian rule; the leap second `:60` is
    /// accepted because RFC 3339 permits it.
    #[must_use]
    pub fn calendar_valid(&self) -> bool {
        let raw = self.0.as_bytes();
        let number = |slice: &[u8]| {
            slice
                .iter()
                .fold(0u32, |acc, c| acc * 10 + u32::from(c - b'0'))
        };
        let year = number(&raw[0..4]);
        let month = number(&raw[5..7]);
        let day = number(&raw[8..10]);
        let hour = number(&raw[11..13]);
        let minute = number(&raw[14..16]);
        let second = number(&raw[17..19]);
        if !(1..=12).contains(&month) {
            return false;
        }
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let days_in_month = match month {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            2 if leap => 29,
            2 => 28,
            _ => return false,
        };
        (1..=days_in_month).contains(&day) && hour < 24 && minute < 60 && second <= 60
    }
}

/// Define a 32-byte digest newtype: parsed from 64 lowercase hex characters,
/// rendered back to the same, carried as raw bytes.
macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Adopt 32 raw digest bytes.
            #[must_use]
            pub fn from_raw(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Parse 64 lowercase hexadecimal characters.
            ///
            /// # Errors
            /// [`GrammarError::NotCanonical`] for anything but 64 lowercase
            /// hex characters naming 32 bytes.
            pub fn parse(text: &str) -> Result<Self, GrammarError> {
                if text.len() != 64 || !text.bytes().all(is_lower_hex) {
                    return Err(GrammarError::NotCanonical);
                }
                let bytes = decode_hex(text).ok_or(GrammarError::NotCanonical)?;
                let mut raw = [0u8; 32];
                raw.copy_from_slice(&bytes);
                Ok(Self(raw))
            }

            /// The 32 raw bytes.
            #[must_use]
            pub fn as_raw(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hexadecimal (the wire text and the identity-hash
            /// input encoding `text` never uses — digests hash as raw bytes).
            #[must_use]
            pub fn to_hex(&self) -> String {
                encode_hex(&self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

digest_newtype!(
    /// Session-namespace hash (`session-v1`; SID-001).
    SessionHash
);
digest_newtype!(
    /// Artifact-namespace hash (`artifact-v1`).
    ArtifactHash
);
digest_newtype!(
    /// Deterministic occurrence identity (`occurrence-v1`; SID-005).
    OccurrenceId
);
digest_newtype!(
    /// Deterministic upload-attestation identity (`attestation-v1`;
    /// STO-013).
    AttestationId
);
digest_newtype!(
    /// SHA-256 of the canonical uncompressed payload bytes — the one digest
    /// that names a blob (STO-001).
    BlobDigest
);
digest_newtype!(
    /// Checksum of the payload as transported (secondary integrity, never
    /// content identity; PI-02).
    IncomingChecksum
);
digest_newtype!(
    /// SHA-256 over the canonical envelope bytes (part one).
    EnvelopeDigest
);
digest_newtype!(
    /// SHA-256 over the whole multipart request body.
    RequestContentDigest
);
digest_newtype!(
    /// Canonical payload digest covered by the attempt signature (equals the
    /// envelope's [`BlobDigest`]).
    PayloadCanonicalDigest
);
digest_newtype!(
    /// Transported payload digest covered by the attempt signature (equals
    /// the envelope's [`IncomingChecksum`]).
    PayloadTransportDigest
);
digest_newtype!(
    /// Ed25519 key identifier: the lowercase-hex SHA-256 of the encoded
    /// public key (`common.json` `key-id`), pinned so key IDs are computable
    /// from any published public record.
    KeyId
);

impl KeyId {
    /// Derive the key ID of an Ed25519 public key (SHA-256 over the 32 raw
    /// key bytes; the derivation `tools/check-control-schemas.py` and the
    /// conformance corpus `keys.json` both pin).
    #[must_use]
    pub fn from_public_key(public: &Ed25519PublicKey) -> Self {
        Self(crate::sha256::digest(public.as_raw()))
    }
}

/// An Ed25519 public key in lowercase hex (`ed25519-public-key-hex`): 32 raw
/// bytes, public halves only — private material never appears in any schema,
/// file, or argument (SEC-006).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Adopt 32 raw key bytes.
    #[must_use]
    pub fn from_raw(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse 64 lowercase hexadecimal characters.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for anything but 64 lowercase hex
    /// characters.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        if text.len() != 64 || !text.bytes().all(is_lower_hex) {
            return Err(GrammarError::NotCanonical);
        }
        let bytes = decode_hex(text).ok_or(GrammarError::NotCanonical)?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&bytes);
        Ok(Self(raw))
    }

    /// The 32 raw key bytes.
    #[must_use]
    pub fn as_raw(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Ed25519PublicKey {
    type Err = GrammarError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// An Ed25519 signature in lowercase hex (`ed25519-signature-hex`): 64 raw
/// bytes. Verification lives in `archivist-auth`; this type only carries the
/// wire value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// Adopt 64 raw signature bytes.
    #[must_use]
    pub fn from_raw(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Parse 128 lowercase hexadecimal characters.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for anything but 128 lowercase hex
    /// characters.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        if text.len() != 128 || !text.bytes().all(is_lower_hex) {
            return Err(GrammarError::NotCanonical);
        }
        let bytes = decode_hex(text).ok_or(GrammarError::NotCanonical)?;
        let mut raw = [0u8; 64];
        raw.copy_from_slice(&bytes);
        Ok(Self(raw))
    }

    /// The 64 raw signature bytes.
    #[must_use]
    pub fn as_raw(&self) -> &[u8; 64] {
        &self.0
    }

    /// Lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for Ed25519Signature {
    type Err = GrammarError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// Define a fail-closed enum: known tokens become variants, anything else is
/// a grammar failure (plan Section 7.1 unknown-enum fail-closed).
macro_rules! closed_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $token:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
        }

        impl $name {
            /// Every known token, in schema order.
            #[must_use]
            pub fn tokens() -> &'static [&'static str] {
                &[$($token),+]
            }

            /// The canonical wire token.
            #[must_use]
            pub fn token(&self) -> &'static str {
                match self {
                    $(Self::$variant => $token,)+
                }
            }

            /// Parse one token, failing closed on anything unknown.
            ///
            /// # Errors
            /// [`GrammarError::NotCanonical`] for a token outside the closed
            /// v1 set.
            pub fn parse(text: &str) -> Result<Self, GrammarError> {
                match text {
                    $($token => Ok(Self::$variant),)+
                    _ => Err(GrammarError::NotCanonical),
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.token())
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

closed_enum!(
    /// Artifact kind (`artifact-kind`): an input to the artifact hash, so an
    /// unknown value fails closed.
    ArtifactKind {
        /// An exact complete-record byte slice of a file source.
        FileSlice => "file-slice",
        /// A versioned allowlisted projection of database events.
        DatabaseProjection => "database-projection",
    }
);
closed_enum!(
    /// Range coordinate kind (`range-kind`): an input to the occurrence
    /// hash, so an unknown value fails closed.
    RangeKind {
        /// Byte offsets into a source byte stream.
        Byte => "byte",
        /// Projected-event ordinals.
        Event => "event",
    }
);
closed_enum!(
    /// Origin of the upstream session identifier (`id-source`):
    /// identity-bearing, fail-closed.
    IdSource {
        /// Read from the harness.
        Upstream => "upstream",
        /// Adapter-minted `UUIDv4` stand-in for a missing harness session ID —
        /// never inferred from a path name.
        Synthetic => "synthetic",
    }
);
closed_enum!(
    /// Named canonical storage encoder (`storage-profile`): determines
    /// stored bytes and key prefixes, so an unknown value fails closed. A
    /// new canonical encoder is a new named profile and prefix (plan Section
    /// 7.5); it never rewrites the meaning of `zstd-v1`.
    StorageProfile {
        /// Zstandard level 3, single-threaded, no dictionary, content size
        /// and checksum enabled (plan Section 7.6).
        ZstdV1 => "zstd-v1",
    }
);
closed_enum!(
    /// Declared wire encoding of the payload part (`transport-encoding`): a
    /// misdeclared encoding changes what the server decodes, so an unknown
    /// value fails closed (PI-01).
    TransportEncoding {
        /// Canonical bytes transported unchanged.
        Identity => "identity",
        /// One Zstandard frame of the canonical bytes — a transport
        /// convenience, distinct from the `zstd-v1` storage profile.
        Zstd => "zstd",
    }
);
closed_enum!(
    /// Algorithm of the envelope's incoming representation checksum
    /// (`checksum-algorithm`): fail-closed rather than guessed.
    ChecksumAlgorithm {
        /// SHA-256, the only v1 algorithm.
        Sha256 => "sha256",
    }
);
closed_enum!(
    /// Per-object storage outcome (`storage-outcome`): exactly what the
    /// backend can establish, never stronger (RCPT-003).
    StorageOutcome {
        /// This request wrote the object.
        Created => "created",
        /// Readable compatible metadata established prior presence.
        AlreadyPresent => "already_present",
        /// Rewrote byte-equivalent canonical content.
        ReplacedEquivalent => "replaced_equivalent",
        /// The commit is logically done; a writer-only profile cannot prove
        /// the physical result (RCPT-004).
        LogicallyCommittedUnknownPhysicalResult => "logically_committed_unknown_physical_result",
    }
);
closed_enum!(
    /// Digital signature algorithm (`signature-algorithm`): Ed25519 only in
    /// v1; fail-closed.
    SignatureAlgorithm {
        /// Ed25519 (RFC 8032).
        Ed25519 => "ed25519",
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_grammars() {
        assert!(TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").is_ok());
        assert!(GenerationId::parse("1a07a111-7000-7000-8000-000000000001").is_ok());
        // Version nibble mismatch.
        assert!(TenantId::parse("1a07a111-7000-7000-8000-000000000001").is_err());
        assert!(GenerationId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").is_err());
        // Uppercase, bad variant, bad shape.
        assert!(TenantId::parse("0F1E2D3C-4B5A-4978-8A9B-0C1D2E3F4A5B").is_err());
        assert!(TenantId::parse("0f1e2d3c-4b5a-4978-ca9b-0c1d2e3f4a5b").is_err());
        assert!(TenantId::parse("0f1e2d3c4b5a49788a9b0c1d2e3f4a5b").is_err());
        // Synthetic session stand-ins are v4.
        assert!(ClientId::parse("aaaaaaaa-bbbb-4ccc-9ddd-1e2f3f4f5f6f").is_ok());
    }

    #[test]
    fn token_grammars() {
        assert!(HarnessId::parse("claude-code").is_ok());
        assert!(HarnessId::parse("a").is_ok());
        assert!(HarnessId::parse("0.x_y-9").is_ok());
        assert!(HarnessId::parse("").is_err());
        assert!(HarnessId::parse("A").is_err());
        assert!(HarnessId::parse("-a").is_err());
        assert!(HarnessId::parse(&"a".repeat(64)).is_ok());
        assert!(HarnessId::parse(&"a".repeat(65)).is_err());
        assert!(VersionToken::parse("1").is_ok());
        assert!(VersionToken::parse("1.0.0-rc.1+build").is_ok());
        assert!(VersionToken::parse("").is_err());
        assert!(VersionToken::parse(&"1".repeat(33)).is_err());
        assert!(VersionToken::parse("v1/beta").is_err());
    }

    #[test]
    fn opaque_id_bounds_are_bytes_not_chars() {
        // 1024 bytes exactly, in multibyte characters: accepted.
        let nfc = "é".repeat(512);
        assert_eq!(nfc.len(), 1024);
        assert!(OpaqueId::parse(&nfc).is_ok());
        let over = "é".repeat(513);
        assert!(OpaqueId::parse(&over).is_err());
        assert!(OpaqueId::parse("").is_err());
        // No normalization ever: NFC and NFD coexist as distinct values.
        let composed = "café";
        let decomposed = "cafe\u{301}";
        assert_ne!(
            OpaqueId::parse(composed).unwrap(),
            OpaqueId::parse(decomposed).unwrap()
        );
    }

    #[test]
    fn timestamp_grammar_and_calendar() {
        let ok = Timestamp::parse("2026-09-11T16:44:10Z").unwrap();
        assert!(ok.calendar_valid());
        assert!(Timestamp::parse("2026-09-11T16:44:10.123456789Z").is_ok());
        assert!(Timestamp::parse("2026-09-11T16:44:10.Z").is_err());
        assert!(Timestamp::parse("2026-09-11T16:44:10.1234567890Z").is_err());
        assert!(Timestamp::parse("2026-09-11 16:44:10Z").is_err());
        assert!(Timestamp::parse("2026-09-11T16:44:10+00:00").is_err());
        // Grammar-valid but calendar-invalid (VAL-002 is semantic).
        let bad = Timestamp::parse("2026-02-30T16:44:10Z").unwrap();
        assert!(!bad.calendar_valid());
        assert!(
            Timestamp::parse("2024-02-29T00:00:00Z")
                .unwrap()
                .calendar_valid()
        );
        assert!(
            !Timestamp::parse("2023-02-29T00:00:00Z")
                .unwrap()
                .calendar_valid()
        );
        assert!(
            Timestamp::parse("2026-12-31T23:59:60Z")
                .unwrap()
                .calendar_valid()
        );
        assert!(
            !Timestamp::parse("2026-12-31T23:59:61Z")
                .unwrap()
                .calendar_valid()
        );
    }

    #[test]
    fn content_type_grammar() {
        assert!(ContentType::parse("multipart/related; boundary=archivist-conformance-01").is_ok());
        assert!(ContentType::parse("multipart/related; boundary=a").is_ok());
        assert!(ContentType::parse("multipart/form-data; boundary=a").is_err());
        assert!(ContentType::parse("multipart/related; boundary=").is_err());
        assert!(ContentType::parse("multipart/related; boundary=a;b").is_err());
        assert!(
            ContentType::parse(&format!("multipart/related; boundary={}", "a".repeat(71))).is_err()
        );
        // Legal boundary charset members from the schema class.
        assert!(ContentType::parse("multipart/related; boundary=a'B+c_(d),.:=?-E").is_ok());
        assert!(ContentType::parse("multipart/related; boundary=a/b").is_err());
    }

    #[test]
    fn error_code_and_message_grammars() {
        assert!(ErrorCode::parse("envelope.schema_invalid").is_ok());
        assert!(ErrorCode::parse("auth.authorization_rejected").is_ok());
        assert!(ErrorCode::parse("a.b").is_ok());
        assert!(ErrorCode::parse("Envelope.schema_invalid").is_err());
        assert!(ErrorCode::parse("envelope").is_err());
        assert!(ErrorCode::parse("envelope.schema_invalid.x").is_err());
        assert!(ErrorCode::parse(&format!("{}.b", "a".repeat(25))).is_err());
        assert!(SafeMessage::parse("plain ascii text; ok").is_ok());
        assert!(SafeMessage::parse("brace { placeholder }").is_err());
        assert!(SafeMessage::parse("café").is_err());
        assert!(SafeMessage::parse(&"a".repeat(201)).is_err());
        assert!(SafeMessage::parse(&"a".repeat(200)).is_ok());
        // '|' and '~' are in the printable set the schema pins.
        assert!(SafeMessage::parse("a|b~c").is_ok());
    }

    #[test]
    fn closed_enums_fail_closed() {
        assert_eq!(StorageProfile::tokens(), &["zstd-v1"]);
        assert!(StorageProfile::parse("zstd-v1").is_ok());
        assert!(StorageProfile::parse("zstd-v2").is_err());
        assert!(TransportEncoding::parse("gzip").is_err());
        assert_eq!(
            TransportEncoding::parse("identity").unwrap().token(),
            "identity"
        );
        assert_eq!(
            StorageOutcome::parse("logically_committed_unknown_physical_result").unwrap(),
            StorageOutcome::LogicallyCommittedUnknownPhysicalResult
        );
        assert!(SignatureAlgorithm::parse("rsa").is_err());
    }

    #[test]
    fn digest_types_reject_mixed_case_and_short() {
        assert!(BlobDigest::parse(&"ab".repeat(32)).is_ok());
        assert!(BlobDigest::parse(&"AB".repeat(32)).is_err());
        assert!(BlobDigest::parse("short").is_err());
        assert!(Ed25519PublicKey::parse(&"cd".repeat(32)).is_ok());
        assert!(Ed25519Signature::parse(&"ef".repeat(64)).is_ok());
        assert!(Ed25519Signature::parse(&"ef".repeat(63)).is_err());
    }
}
