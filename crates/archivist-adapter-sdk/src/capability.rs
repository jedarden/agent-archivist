// SPDX-License-Identifier: Apache-2.0

//! The adapter capability vocabulary and set (requirement CAP-002's
//! documented plugin interface, CAP-008's capability separation): what one
//! adapter supports, published as a closed, bounded set instead of
//! discovered by probing.
//!
//! A capability is a **content-free** token naming a capture behavior the
//! plan pins — file-slice chunking, database projection, generation
//! detection, and so on. The set is closed: a capability an adapter does
//! not declare is absent, and no adapter can invent a token the client
//! engine does not know. Consumers branch on [`CapabilitySet::supports`];
//! nothing parses capability text.

use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::GrammarError;

/// The number of capabilities in the closed vocabulary, and therefore the
/// most one adapter may declare: the set is one flag per member, so the
/// bound keeps the status JSON and the compatibility-matrix row
/// fixed-shape by construction. Growing the vocabulary grows this bound
/// in the same commit.
pub const MAX_CAPABILITIES: usize = 7;

/// One capture behavior an adapter can support, named by a wire-stable
/// token. Every variant traces to a plan requirement:
///
/// - `file-slice-capture`, `complete-record-boundaries`: CAP-003's
///   complete-record chunking of append-only transcripts (plan `EC-01`).
/// - `database-projection`: CAP-004's read-only allowlisted projection
///   (protocol `ArtifactKind::DatabaseProjection`).
/// - `generation-detection`: CAP-005 and `SID-003`'s replacement,
///   truncation, rewind, and rewrite detection.
/// - `sidecar-relationships`: plan Phase 6A's sidecars captured as
///   separate artifact kinds with explicit relationships.
/// - `coverage-gap-reporting`: CAP-009's detected-but-uncapturable modes
///   reported rather than silently skipped.
/// - `exact-provider-capture`: CAP-008's exact provider request/response
///   capture, declared separately from harness-semantic capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AdapterCapability {
    /// Chunk append-only file transcripts on complete record boundaries
    /// into byte-slice artifacts (CAP-003).
    FileSliceCapture,
    /// Emit a versioned, allowlisted projection of a database-backed
    /// harness instead of uploading the database (CAP-004).
    DatabaseProjection,
    /// Parse only on complete record boundaries; an incomplete tail waits
    /// for a later pass (CAP-003, plan `EC-01`).
    CompleteRecordBoundaries,
    /// Detect source replacement, truncation, rewind, and rewrite as new
    /// generations, preserving earlier ones (CAP-005, `SID-003`).
    GenerationDetection,
    /// Capture related sidecars as separate artifact kinds with explicit
    /// relationships (plan Phase 6A).
    SidecarRelationships,
    /// Report detected-but-uncapturable modes as coverage gaps instead of
    /// skipping them (CAP-009).
    CoverageGapReporting,
    /// Capture exact provider request/response traffic as a source distinct
    /// from harness-semantic capture (CAP-008).
    ExactProviderCapture,
}

impl AdapterCapability {
    /// Every capability, in declaration (canonical token) order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::FileSliceCapture,
            Self::DatabaseProjection,
            Self::CompleteRecordBoundaries,
            Self::GenerationDetection,
            Self::SidecarRelationships,
            Self::CoverageGapReporting,
            Self::ExactProviderCapture,
        ]
    }

    /// The canonical token for this capability: the spelling the status
    /// JSON and the compatibility matrix use.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::FileSliceCapture => "file-slice-capture",
            Self::DatabaseProjection => "database-projection",
            Self::CompleteRecordBoundaries => "complete-record-boundaries",
            Self::GenerationDetection => "generation-detection",
            Self::SidecarRelationships => "sidecar-relationships",
            Self::CoverageGapReporting => "coverage-gap-reporting",
            Self::ExactProviderCapture => "exact-provider-capture",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "file-slice-capture" => Ok(Self::FileSliceCapture),
            "database-projection" => Ok(Self::DatabaseProjection),
            "complete-record-boundaries" => Ok(Self::CompleteRecordBoundaries),
            "generation-detection" => Ok(Self::GenerationDetection),
            "sidecar-relationships" => Ok(Self::SidecarRelationships),
            "coverage-gap-reporting" => Ok(Self::CoverageGapReporting),
            "exact-provider-capture" => Ok(Self::ExactProviderCapture),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

impl std::fmt::Display for AdapterCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// The bounded capability set one adapter declares. Stored as one flag per
/// closed-vocabulary member, so the set cannot exceed
/// [`MAX_CAPABILITIES`], cannot hold a duplicate, and iterates in
/// canonical token order regardless of insertion order.
///
/// Constructed empty and filled by the adapter, or parsed from tokens; a
/// descriptor publishes only a non-empty set, because an adapter that
/// supports nothing is a configuration error, not an adapter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CapabilitySet {
    present: [bool; MAX_CAPABILITIES],
}

impl CapabilitySet {
    /// An empty set, filled by [`Self::insert`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the set from parsed tokens, failing closed on any unknown
    /// one.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse<I, S>(tokens: I) -> Result<Self, GrammarError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set = Self::new();
        for token in tokens {
            set.insert(AdapterCapability::parse(token.as_ref())?);
        }
        Ok(set)
    }

    /// Declare one capability. Insertion is idempotent.
    pub fn insert(&mut self, capability: AdapterCapability) -> &mut Self {
        let slot = Self::slot(capability);
        self.present[slot] = true;
        self
    }

    /// Whether the adapter declared `capability`.
    #[must_use]
    pub fn supports(&self, capability: AdapterCapability) -> bool {
        self.present[Self::slot(capability)]
    }

    /// The declared capabilities in canonical token order.
    pub fn iter(&self) -> impl Iterator<Item = AdapterCapability> + '_ {
        AdapterCapability::all()
            .iter()
            .copied()
            .filter(|capability| self.present[Self::slot(*capability)])
    }

    /// The number of declared capabilities.
    #[must_use]
    pub fn len(&self) -> usize {
        self.iter().count()
    }

    /// Whether nothing is declared — rejected at publication by
    /// [`crate::AdapterDescriptor::publish`].
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The compatibility-matrix row: the declared tokens as a sorted JSON
    /// array of fixed shape.
    #[must_use]
    pub fn to_json(&self) -> Value {
        Value::Array(
            self.iter()
                .map(|capability| Value::Text(capability.token().to_owned()))
                .collect(),
        )
    }

    /// The flag slot for one member. A `match`, not a lookup, so adding a
    /// vocabulary member without a slot is a compile error.
    fn slot(capability: AdapterCapability) -> usize {
        match capability {
            AdapterCapability::FileSliceCapture => 0,
            AdapterCapability::DatabaseProjection => 1,
            AdapterCapability::CompleteRecordBoundaries => 2,
            AdapterCapability::GenerationDetection => 3,
            AdapterCapability::SidecarRelationships => 4,
            AdapterCapability::CoverageGapReporting => 5,
            AdapterCapability::ExactProviderCapture => 6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_tokens_round_trip_and_fail_closed() {
        for capability in AdapterCapability::all() {
            assert_eq!(
                AdapterCapability::parse(capability.token()).as_ref(),
                Ok(capability)
            );
        }
        assert!(AdapterCapability::parse("file-slice").is_err());
        assert!(AdapterCapability::parse("").is_err());
        assert!(AdapterCapability::parse("FileSliceCapture").is_err());
    }

    #[test]
    fn sets_are_bounded_idempotent_and_canonically_ordered() {
        let mut set = CapabilitySet::new();
        assert!(set.is_empty());
        set.insert(AdapterCapability::FileSliceCapture)
            .insert(AdapterCapability::GenerationDetection)
            .insert(AdapterCapability::FileSliceCapture);
        assert_eq!(set.len(), 2);
        let tokens: Vec<_> = set
            .iter()
            .map(|capability| capability.to_string())
            .collect();
        // Canonical token order, not insertion order; the duplicate is
        // absorbed.
        assert_eq!(tokens, ["file-slice-capture", "generation-detection"]);
        assert!(set.supports(AdapterCapability::FileSliceCapture));
        assert!(!set.supports(AdapterCapability::DatabaseProjection));

        let parsed = CapabilitySet::parse(["generation-detection", "file-slice-capture"])
            .expect("valid tokens");
        assert_eq!(parsed, set);
        assert!(CapabilitySet::parse(["file-slice"]).is_err());

        // The matrix row is byte-stable because iteration is canonical.
        assert_eq!(
            set.to_json().canonical_bytes(),
            br#"["file-slice-capture","generation-detection"]"#.to_vec()
        );
    }

    #[test]
    fn the_vocabulary_fits_its_declared_bound() {
        // Every member has a slot inside the declared bound; growing the
        // vocabulary grows MAX_CAPABILITIES in the same commit.
        assert_eq!(AdapterCapability::all().len(), MAX_CAPABILITIES);
    }
}
