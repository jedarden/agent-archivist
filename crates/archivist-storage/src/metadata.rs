// SPDX-License-Identifier: Apache-2.0

//! Observation metadata shared by every authority that looks at a stored
//! object: the backend commitment tag, the storage version when the backend
//! exposes one, and the time the observation was made.
//!
//! These are project-owned shapes, never the backend SDK's: an S3 `ETag`, a
//! B2 hash, or any future provider's commitment token arrives here only as a
//! validated opaque [`ObjectTag`], so the traits stay replaceable (plan
//! Section 4). The observation time is what bounds every consumer-side cache
//! — the 60-second trust-record bound (plan Section 5, `EC-09`) is computed
//! from it, never from the backend's own clock.

use std::fmt;
use std::str::FromStr;

use archivist_protocol::vocabulary::Timestamp;

/// Why a candidate metadata token is not a value of the target type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataError {
    /// The token does not match the type's grammar (length, charset, shape).
    NotCanonical,
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonical => write!(f, "value does not match the canonical grammar"),
        }
    }
}

impl std::error::Error for MetadataError {}

/// The backend's per-object commitment tag (an S3 `ETag`, a B2 checksum, a
/// provider-specific token): 1–128 printable, non-space ASCII characters.
///
/// Opaque by design — the storage contract never compares tags across
/// backends or parses their internals. Two observations of one object with
/// equal tags are *evidence* of stability, and the freeze contract treats a
/// tag disagreement as a fault, but the tag itself is never interpreted.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectTag(String);

impl ObjectTag {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`MetadataError::NotCanonical`] for anything but 1–128 printable,
    /// non-space ASCII characters.
    pub fn parse(text: &str) -> Result<Self, MetadataError> {
        if text.is_empty() || text.len() > 128 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(MetadataError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The tag exactly as the backend reported it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ObjectTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ObjectTag {
    type Err = MetadataError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The backend's storage version of one object, when versioning is exposed
/// (`versioning: enabled` in the capability model): 1–1024 printable,
/// non-space ASCII characters.
///
/// Absent means the backend did not expose a version for the observation —
/// which under the backup and restore contract is never evidence that no
/// version exists: "unknown version state never passes" (plan Section 7.10).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageVersionId(String);

impl StorageVersionId {
    /// Adopt `text` after verifying its grammar.
    ///
    /// # Errors
    /// [`MetadataError::NotCanonical`] for anything but 1–1024 printable,
    /// non-space ASCII characters.
    pub fn parse(text: &str) -> Result<Self, MetadataError> {
        if text.is_empty() || text.len() > 1024 || !text.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return Err(MetadataError::NotCanonical);
        }
        Ok(Self(text.to_owned()))
    }

    /// The version identifier exactly as the backend reported it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StorageVersionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StorageVersionId {
    type Err = MetadataError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// What a store observed about one object at one moment.
///
/// Every field is advisory evidence, not a guarantee: the tag and version are
/// the backend's own commitments at `observed_at`, and a consumer that needs
/// more than that (a freshness bound, a mutation detector) re-observes. The
/// observation time is this store's own clock reading in wire form, so cache
/// bounds such as the 60-second trust-record TTL are computable without
/// trusting any backend clock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    etag: Option<ObjectTag>,
    storage_version: Option<StorageVersionId>,
    observed_at: Timestamp,
}

impl Observation {
    /// Record an observation made at `observed_at`.
    #[must_use]
    pub fn new(
        etag: Option<ObjectTag>,
        storage_version: Option<StorageVersionId>,
        observed_at: Timestamp,
    ) -> Self {
        Self {
            etag,
            storage_version,
            observed_at,
        }
    }

    /// The backend's commitment tag, when it exposed one.
    #[must_use]
    pub fn etag(&self) -> Option<&ObjectTag> {
        self.etag.as_ref()
    }

    /// The backend's storage version, when it exposed one.
    #[must_use]
    pub fn storage_version(&self) -> Option<&StorageVersionId> {
        self.storage_version.as_ref()
    }

    /// When this store made the observation (wire text, this store's clock).
    #[must_use]
    pub fn observed_at(&self) -> &Timestamp {
        &self.observed_at
    }
}

#[cfg(test)]
mod tests {
    use super::{MetadataError, ObjectTag, Observation, StorageVersionId};

    const OBSERVED: &str = "2026-09-13T12:00:00Z";

    #[test]
    fn object_tag_grammar() {
        assert!(ObjectTag::parse("\"d41d8cd98f00b204e9800998ecf8427e\"").is_ok());
        assert!(ObjectTag::parse("b2sha1_abc-123").is_ok());
        assert!(ObjectTag::parse("").is_err());
        assert!(ObjectTag::parse(&"a".repeat(129)).is_err());
        assert!(ObjectTag::parse(&"a".repeat(128)).is_ok());
        assert!(ObjectTag::parse("has space").is_err());
        assert!(ObjectTag::parse("café").is_err());
        assert!(ObjectTag::parse("\ttabbed").is_err());
    }

    #[test]
    fn storage_version_grammar() {
        assert!(
            StorageVersionId::parse(
                "3sL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo"
            )
            .is_ok()
        );
        assert!(StorageVersionId::parse("").is_err());
        assert!(StorageVersionId::parse(&"v".repeat(1025)).is_err());
        assert!(StorageVersionId::parse(&"v".repeat(1024)).is_ok());
        assert!(StorageVersionId::parse("null byte \0").is_err());
    }

    #[test]
    fn grammar_errors_are_distinct() {
        assert_eq!(
            ObjectTag::parse(""),
            Err::<ObjectTag, _>(MetadataError::NotCanonical)
        );
    }

    #[test]
    fn observation_carries_optional_evidence() {
        let stamp = archivist_protocol::vocabulary::Timestamp::parse(OBSERVED).unwrap();
        let bare = Observation::new(None, None, stamp.clone());
        assert!(bare.etag().is_none());
        assert!(bare.storage_version().is_none());
        assert_eq!(bare.observed_at().as_str(), OBSERVED);

        let full = Observation::new(
            Some(ObjectTag::parse("\"abc\"").unwrap()),
            Some(StorageVersionId::parse("v1").unwrap()),
            stamp,
        );
        assert_eq!(full.etag().unwrap().as_str(), "\"abc\"");
        assert_eq!(full.storage_version().unwrap().as_str(), "v1");
    }
}
