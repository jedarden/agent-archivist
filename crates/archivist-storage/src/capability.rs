// SPDX-License-Identifier: Apache-2.0

//! The storage capability model (plan Section 7.7):
//!
//! ```text
//! conditional_create: supported | unavailable
//! multipart_commit_abort: required
//! stored_checksum: sha256 | md5 | provider_specific | unavailable
//! versioning: enabled | disabled | unknown
//! server_side_encryption: verified | unavailable
//! ```
//!
//! `multipart_commit_abort` is deliberately absent from the reported set:
//! begin/write/commit/abort is the one primitive [`crate::raw_write::
//! RawWriteStore`] cannot degrade on — a backend without it is not a
//! supported profile, so there is nothing to report.
//!
//! Everything reported is **advisory**: it describes what a probe observed
//! about the backend at some point, cached only in the sense that a store
//! may refresh it between calls. A caller that needs a capability treats a
//! report of `unavailable` (or of `unknown`, where the model has such a
//! state) as final for the honest-mode choice and never as something to
//! route around — the failure class for acting on a missing capability is
//! [`crate::error::StorageErrorKind::CapabilityUnavailable`]. Capability
//! *probing* that produces these reports without mutating arbitrary keys is
//! its own Phase 2 deliverable and is not behavior of the traits.

use archivist_protocol::vocabulary::GrammarError;

/// Whether the backend can create an object only if the key is absent.
///
/// When [`ConditionalCreate::Supported`], the adapter uses it and treats
/// "already exists" as successful deduplication after validating compatible
/// metadata (STO-005). When unavailable, deterministic overwrite provides
/// logical idempotency and versioned stores may retain redundant noncurrent
/// physical versions (STO-006, STO-009) — reported honestly, never claimed
/// as deduplication (RCPT-004).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConditionalCreate {
    /// Atomic create-if-absent is available.
    Supported,
    /// No portable conditional-create guarantee; overwrite is the idempotency
    /// mechanism.
    Unavailable,
}

impl ConditionalCreate {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["supported", "unavailable"]
    }

    /// The model token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unavailable => "unavailable",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "supported" => Ok(Self::Supported),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// What stored checksum the backend maintains over stored bytes.
///
/// Secondary integrity only, never content identity — the one digest that
/// names a blob is the SHA-256 of the canonical uncompressed bytes (STO-001).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StoredChecksum {
    /// The backend verifies SHA-256 over stored bytes.
    Sha256,
    /// The backend verifies MD5 over stored bytes.
    Md5,
    /// The backend maintains some other provider-specific checksum.
    ProviderSpecific,
    /// The backend maintains no stored checksum.
    Unavailable,
}

impl StoredChecksum {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["sha256", "md5", "provider_specific", "unavailable"]
    }

    /// The model token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Md5 => "md5",
            Self::ProviderSpecific => "provider_specific",
            Self::Unavailable => "unavailable",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "sha256" => Ok(Self::Sha256),
            "md5" => Ok(Self::Md5),
            "provider_specific" => Ok(Self::ProviderSpecific),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// Whether the backend versions objects, as far as the deployment knows.
///
/// `unknown` is a first-class answer: "unknown version state never passes"
/// the backup and restore precondition (plan Section 7.10), so a probe that
/// could not establish versioning reports unknown rather than guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersioningState {
    /// Versioning is enabled on the bucket.
    Enabled,
    /// Versioning is disabled (never enabled, or explicitly suspended).
    Disabled,
    /// The deployment could not establish the versioning state.
    Unknown,
}

impl VersioningState {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["enabled", "disabled", "unknown"]
    }

    /// The model token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Unknown => "unknown",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            "unknown" => Ok(Self::Unknown),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// Whether writes land under server-side encryption that the deployment
/// verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EncryptionState {
    /// Server-side encryption is configured and its presence was verified.
    Verified,
    /// Server-side encryption is not configured, or was not verifiable.
    Unavailable,
}

impl EncryptionState {
    /// Every token, in model order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["verified", "unavailable"]
    }

    /// The model token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Unavailable => "unavailable",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "verified" => Ok(Self::Verified),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

/// The capability report a raw store hands its caller.
///
/// Every field is an observed, advisory answer (see the module docs); the
/// struct is `Copy` so a report can travel without ceremony. The fields are
/// public by design — the report is a value, not a capability grant, and no
/// method anywhere in this crate takes authority from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StoreCapabilities {
    /// Atomic create-if-absent availability.
    pub conditional_create: ConditionalCreate,
    /// Stored checksum the backend maintains.
    pub stored_checksum: StoredChecksum,
    /// Versioning state as far as the deployment knows.
    pub versioning: VersioningState,
    /// Server-side encryption state as far as the deployment knows.
    pub server_side_encryption: EncryptionState,
}

#[cfg(test)]
mod tests {
    use super::{
        ConditionalCreate, EncryptionState, StoreCapabilities, StoredChecksum, VersioningState,
    };

    #[test]
    fn tokens_round_trip_and_fail_closed() {
        fn check<E: Copy>(
            tokens: &[&str],
            token_of: impl Fn(E) -> &'static str,
            parse_of: impl Fn(&str) -> Result<E, archivist_protocol::vocabulary::GrammarError>,
        ) {
            for token in tokens {
                assert_eq!(token_of(parse_of(token).unwrap()), *token);
            }
            assert!(parse_of("").is_err());
            assert!(parse_of("SHA256").is_err());
            assert!(parse_of("gzip").is_err());
        }
        check(
            ConditionalCreate::tokens(),
            ConditionalCreate::token,
            ConditionalCreate::parse,
        );
        check(
            StoredChecksum::tokens(),
            StoredChecksum::token,
            StoredChecksum::parse,
        );
        check(
            VersioningState::tokens(),
            VersioningState::token,
            VersioningState::parse,
        );
        check(
            EncryptionState::tokens(),
            EncryptionState::token,
            EncryptionState::parse,
        );
    }

    #[test]
    fn report_is_a_plain_value() {
        let report = StoreCapabilities {
            conditional_create: ConditionalCreate::Unavailable,
            stored_checksum: StoredChecksum::Sha256,
            versioning: VersioningState::Unknown,
            server_side_encryption: EncryptionState::Verified,
        };
        let copied = report;
        assert_eq!(copied, report);
        assert_eq!(copied.conditional_create, ConditionalCreate::Unavailable);
    }
}
