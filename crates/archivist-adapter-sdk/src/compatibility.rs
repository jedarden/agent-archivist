// SPDX-License-Identifier: Apache-2.0

//! The exact-capture compatibility matrix (plan Phase 9; threat
//! `EC-04`): the registry of provider-capture routes the project
//! actually claims.
//!
//! A route earns a row only by evidence: [`QualifiedRoute`] values are
//! minted exclusively by a passing
//! [`crate::openai_conformance::TransportConformance`] run — the
//! constructor is crate-private, so no caller outside this crate can
//! manufacture a compatibility claim, and no caller inside it mints one
//! except at the end of the conformance suite. The matrix therefore
//! cannot name an ambient-tracing integration, a package-detection
//! heuristic, or a third-party SDK version: a row that does not exist
//! is a claim the project does not make, and a row that exists carries
//! the conformance evidence digest that qualified it.
//!
//! Version 1 ships exactly one qualified route: the first-party
//! OpenAI-compatible Rust transport integration
//! ([`crate::openai_compat`]) around [`crate::openai_http1`]. A proxy
//! route, or a future third-party hook, enters the same way this one
//! did: by calling the versioned [`crate::inference_observer`]
//! lifecycle at its actual transport boundary and passing the same
//! conformance gate.

use std::fmt;

use crate::expected_inference::RoutePolicy;

/// The integration token of the one first-party qualified route: the
/// OpenAI-compatible client over the first-party HTTP/1.1 transport.
pub const FIRST_PARTY_OPENAI_HTTP1: &str = "archivist-openai-http1";

/// One route's conformance-backed compatibility claim.
///
/// Construction is crate-private on purpose: a [`QualifiedRoute`] is
/// evidence, and the only evidence producer is the conformance suite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedRoute {
    route: RoutePolicy,
    integration: &'static str,
    lifecycle_version: i64,
    evidence_digest: String,
}

impl QualifiedRoute {
    /// Mint a qualification from a passing conformance run. Crate-
    /// private: only the conformance suite calls this.
    pub(crate) fn new_sdk_hook(
        integration: &'static str,
        lifecycle_version: i64,
        evidence_digest: String,
    ) -> Self {
        Self {
            route: RoutePolicy::SdkHook,
            integration,
            lifecycle_version,
            evidence_digest,
        }
    }

    /// The route this qualification admits.
    #[must_use]
    pub const fn route(&self) -> RoutePolicy {
        self.route
    }

    /// The bounded integration token the row names.
    #[must_use]
    pub const fn integration(&self) -> &'static str {
        self.integration
    }

    /// The [`crate::inference_observer`] lifecycle version the
    /// integration was verified against.
    #[must_use]
    pub const fn lifecycle_version(&self) -> i64 {
        self.lifecycle_version
    }

    /// The SHA-256 hex digest of the canonical conformance evidence the
    /// claim is backed by.
    #[must_use]
    pub fn evidence_digest(&self) -> &str {
        &self.evidence_digest
    }
}

impl fmt::Display for QualifiedRoute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} integration={} lifecycle={} evidence={}",
            self.route, self.integration, self.lifecycle_version, self.evidence_digest
        )
    }
}

/// Why a conformance report contributed no matrix row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatrixError {
    /// The report's conformance run did not pass every scene, so it
    /// carries no qualification.
    Unqualified,
}

impl fmt::Display for MatrixError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("conformance report is not qualified; no matrix row exists for it")
    }
}

impl std::error::Error for MatrixError {}

/// The compatibility matrix: every route whose exact-capture claim the
/// project backs with conformance evidence.
///
/// Freshly constructed it is empty — absence of a row is the normal
/// state of an unqualified route, and the matrix grows only through
/// [`CompatibilityMatrix::record`] of a passing conformance report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompatibilityMatrix {
    routes: Vec<QualifiedRoute>,
}

impl CompatibilityMatrix {
    /// The empty matrix: no route is claimed.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a conformance report's qualification.
    ///
    /// # Errors
    /// [`MatrixError::Unqualified`] when the report carries no
    /// qualification because its conformance run did not pass every
    /// scene.
    pub fn record(
        &mut self,
        report: &crate::openai_conformance::ConformanceReport,
    ) -> Result<(), MatrixError> {
        let qualification = report
            .qualification()
            .ok_or(MatrixError::Unqualified)?
            .clone();
        if let Some(existing) = self
            .routes
            .iter()
            .find(|route| route.route == qualification.route)
        {
            // Re-recording the same evidence is idempotent; different
            // evidence for one route replaces the row, because the
            // matrix states the qualification, not its history.
            if existing == &qualification {
                return Ok(());
            }
            self.routes
                .retain(|route| route.route != qualification.route);
        }
        self.routes.push(qualification);
        self.routes.sort_by_key(|route| route.route);
        Ok(())
    }

    /// Every qualified route, in registry order.
    #[must_use]
    pub fn routes(&self) -> &[QualifiedRoute] {
        &self.routes
    }

    /// The qualification for `route`, when the matrix claims it.
    #[must_use]
    pub fn route(&self, route: RoutePolicy) -> Option<&QualifiedRoute> {
        self.routes.iter().find(|row| row.route == route)
    }

    /// Whether `route` is a claimed, conformance-backed integration.
    #[must_use]
    pub fn is_qualified(&self, route: RoutePolicy) -> bool {
        self.route(route).is_some()
    }

    /// How many routes the matrix claims.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the matrix claims no route.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

impl fmt::Display for CompatibilityMatrix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.routes.is_empty() {
            return formatter.write_str("compatibility matrix: (no qualified routes)");
        }
        formatter.write_str("compatibility matrix:")?;
        for route in &self.routes {
            formatter.write_str("\n  ")?;
            write!(formatter, "{route}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference_observer::INFERENCE_OBSERVER_VERSION;

    #[test]
    fn fresh_matrix_claims_nothing() {
        let matrix = CompatibilityMatrix::new();
        assert!(matrix.is_empty());
        assert!(!matrix.is_qualified(RoutePolicy::SdkHook));
        assert!(!matrix.is_qualified(RoutePolicy::Proxy));
    }

    #[test]
    fn qualification_is_version_pinned_by_construction() {
        let route = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            INFERENCE_OBSERVER_VERSION,
            "ab".repeat(32),
        );
        assert_eq!(route.route(), RoutePolicy::SdkHook);
        assert_eq!(route.integration(), FIRST_PARTY_OPENAI_HTTP1);
        assert_eq!(route.lifecycle_version(), INFERENCE_OBSERVER_VERSION);
        assert_eq!(route.evidence_digest().len(), 64);
    }
}
