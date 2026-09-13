// SPDX-License-Identifier: Apache-2.0

//! The storage-layer error type: why a store call failed, classified by the
//! decision the caller must make next.
//!
//! This is an internal interface error, not a wire error: mapping onto the
//! HTTP classes of plan Section 7.8 (retryable `503`, `409`
//! `integrity_conflict`) is the server's job. What this type pins is the
//! *classification*: an integrity conflict is never retried into an
//! overwrite loop, a scope violation is never retried at all, and an
//! inventory fault always fails the whole freeze closed (plan Section 7.7).

use std::fmt;

/// The closed set of failure classes a store call can report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageErrorKind {
    /// The backend or network is unavailable; the call may be retried.
    Unavailable,
    /// The requested primitive is outside the reported capabilities; the
    /// caller must choose a different, honest mode rather than degrade
    /// silently (plan Section 7.7: conditional create is observed, never
    /// assumed).
    CapabilityUnavailable,
    /// The request names an object outside this identity's provisioned
    /// tenant or prefix; never retryable and never a policy bug to route
    /// around.
    ScopeViolation,
    /// Existing metadata or content at a derived key is incompatible with
    /// the identity the key claims (plan Section 7.11 `EC-06`); retrying
    /// with the same bytes is an overwrite loop, not a repair.
    IntegrityConflict,
    /// A typed input arrived malformed or out of bounds — an unknown
    /// multipart session, an oversized part, an empty part list.
    MalformedInput,
    /// A current-pointer replacement arrived with an epoch that does not
    /// strictly increase over the stored pointer (plan Section 5).
    StaleEpoch,
    /// The freeze contract failed: a page error, a repeated continuation
    /// token, a duplicate key, an out-of-prefix key, or a mutation detected
    /// while freezing. The whole inventory fails closed (plan Section 7.7).
    InventoryFault,
}

impl StorageErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Unavailable,
            Self::CapabilityUnavailable,
            Self::ScopeViolation,
            Self::IntegrityConflict,
            Self::MalformedInput,
            Self::StaleEpoch,
            Self::InventoryFault,
        ]
    }

    /// The content-free default detail shipped with this kind. Callers that
    /// have nothing more specific to say use these verbatim; the literals
    /// are pinned by a unit test to stay inside the project's safe-message
    /// grammar.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::Unavailable => "storage backend unavailable",
            Self::CapabilityUnavailable => "requested primitive is not an available capability",
            Self::ScopeViolation => "request is outside this identity authority",
            Self::IntegrityConflict => "stored object is incompatible with its derived key",
            Self::MalformedInput => "request input is malformed or out of bounds",
            Self::StaleEpoch => "pointer epoch does not strictly increase",
            Self::InventoryFault => "inventory freeze contract violated",
        }
    }
}

impl fmt::Display for StorageErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Unavailable => "unavailable",
            Self::CapabilityUnavailable => "capability-unavailable",
            Self::ScopeViolation => "scope-violation",
            Self::IntegrityConflict => "integrity-conflict",
            Self::MalformedInput => "malformed-input",
            Self::StaleEpoch => "stale-epoch",
            Self::InventoryFault => "inventory-fault",
        };
        f.write_str(text)
    }
}

/// Why a store call failed: a closed class plus one content-safe detail.
///
/// The detail is a static literal by construction — the type cannot carry
/// runtime text such as keys, tenants, or paths, so an error can never
/// become a content-bearing log line (plan Section 7.8: bounded error
/// codes, never messages derived from source content).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StorageError {
    kind: StorageErrorKind,
    detail: &'static str,
}

impl StorageError {
    /// Build an error from a kind and a static, content-safe detail
    /// (printable ASCII, no braces, at most 200 characters). The rule is
    /// enforced for every shipped literal by a unit test against the
    /// protocol's `SafeMessage` grammar.
    #[must_use]
    pub const fn new(kind: StorageErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: StorageErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> StorageErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "storage {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for StorageError {}

#[cfg(test)]
mod tests {
    use super::{StorageError, StorageErrorKind};
    use archivist_protocol::vocabulary::SafeMessage;

    #[test]
    fn kinds_are_distinct_and_display_distinctly() {
        let all = StorageErrorKind::all();
        assert_eq!(all.len(), 7);
        let displays: Vec<_> = all.iter().map(std::string::ToString::to_string).collect();
        let mut sorted = displays.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(displays.len(), sorted.len(), "display strings collide");
    }

    #[test]
    fn every_default_detail_is_a_safe_message() {
        for kind in StorageErrorKind::all() {
            let detail = kind.default_detail();
            let parsed = SafeMessage::parse(detail)
                .unwrap_or_else(|_| panic!("default detail of {kind} is not a safe message"));
            assert_eq!(parsed.as_str(), detail);
        }
    }

    #[test]
    fn display_carries_kind_and_detail_without_content() {
        let error = StorageError::of_kind(StorageErrorKind::InventoryFault);
        let rendered = error.to_string();
        assert!(
            rendered.starts_with("storage inventory-fault: "),
            "{rendered}"
        );
    }
}
