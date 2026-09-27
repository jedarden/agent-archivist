// SPDX-License-Identifier: Apache-2.0

//! The exact-capture compatibility matrix (plan Phase 9; threat
//! `EC-04`): the registry of provider-capture routes the project
//! actually claims.
//!
//! A route earns a row only by evidence: [`QualifiedRoute`] values are
//! minted exclusively by a passing conformance run — the first-party
//! client's [`crate::openai_conformance::TransportConformance`] or the
//! proxy route's [`crate::openai_proxy_conformance::ProxyConformance`]
//! — the constructor is crate-private, so no caller outside this crate
//! can manufacture a compatibility claim, and no caller inside it mints
//! one except at the end of the conformance suite. The matrix therefore
//! cannot name an ambient-tracing integration, a package-detection
//! heuristic, or a third-party SDK version: a row that does not exist
//! is a claim the project does not make, and a row that exists carries
//! the conformance evidence digest that qualified it.
//!
//! Version 1 ships exactly two qualified routes, both first-party: the
//! OpenAI-compatible Rust transport integration
//! ([`crate::openai_compat`]) around [`crate::openai_http1`], and the
//! explicitly routed capture proxy ([`crate::openai_proxy`]). A future
//! third-party hook enters the same way these two did: by calling the
//! versioned [`crate::inference_observer`] lifecycle at its actual
//! transport boundary and passing the same conformance gate.
//!
//! ## The published registry
//!
//! [`PUBLISHED_REGISTRY`] is the published half of that matrix — the
//! separate provider-capture route registry the source-adapter matrix
//! ([`crate::fingerprint`], plan Phase 6) deliberately is not. One
//! [`ProviderCaptureRoute`] row per claimed route names its route
//! fingerprint (the boundary shape the claim covers, the analogue of a
//! source fingerprint), the exact-capture artifact schema version and
//! provider-boundary artifact kinds the route records, its support
//! state, the conformance suite that qualifies it, and the known gap —
//! the boundary the claim stops at. The rows are `const` data: the
//! release gate (`tools/check-provider-capture-registry.py`) parses
//! them out of this source and rejects any state of the registry, the
//! published note, and the conformance mint sites that disagrees with
//! the others, so a support claim here is pinned to the evidence that
//! earned it the same way the source-adapter matrix's claims are.
//!
//! The runtime half closes the loop:
//! [`CompatibilityMatrix::matches_published_registry`] is the release
//! check a publisher runs against a matrix built from live conformance
//! runs — the published rows must be exactly the claims the evidence
//! backs, or the publication fails closed.

use std::fmt;

use archivist_protocol::inference_artifact::INFERENCE_ARTIFACT_VERSION;

use crate::expected_inference::RoutePolicy;
use crate::inference_observer::INFERENCE_OBSERVER_VERSION;

/// The integration token of the one first-party qualified route: the
/// OpenAI-compatible client over the first-party HTTP/1.1 transport.
pub const FIRST_PARTY_OPENAI_HTTP1: &str = "archivist-openai-http1";

/// The integration token of the first-party proxy route: the explicitly
/// routed OpenAI-compatible capture proxy ([`crate::openai_proxy`])
/// over the same first-party transport.
pub const FIRST_PARTY_OPENAI_PROXY: &str = "archivist-openai-proxy";

/// The route fingerprint of the first-party SDK-hook route: the
/// OpenAI-compatible chat boundary the versioned
/// [`crate::inference_observer`] lifecycle wraps around the first-party
/// HTTP/1.1 transport. Like a source fingerprint, it names a boundary
/// shape — never a release, a package version, or a host — and the
/// grammar is the source-fingerprint grammar, so a route fingerprint
/// can never smuggle a coordinate into a report or the matrix.
pub const ROUTE_FINGERPRINT_OPENAI_HTTP1: &str = "openai-compat-observer-hook-v1";

/// The route fingerprint of the first-party proxy route: the explicitly
/// routed OpenAI-compatible capture-proxy boundary — faithful request
/// forwarding, ordered relay, and credential exclusion at the proxy,
/// never transparent interception.
pub const ROUTE_FINGERPRINT_OPENAI_PROXY: &str = "openai-compat-capture-proxy-v1";

/// Every provider-boundary artifact kind a qualified route captures, in
/// schema order — the closed [`crate::expected_inference::
/// InferenceArtifactKind`] set the
/// exact-capture artifact schema defines. A registry row claims the
/// whole set: a route that captured a subset would leave provider
/// attempts the coverage ledger counts as `partial`, which no supported
/// route may do.
pub const PROVIDER_CAPTURE_ARTIFACT_KINDS: &[&str] = &[
    "provider-request",
    "provider-response",
    "streaming-event",
    "retry",
    "usage",
    "transport-error",
];

/// One route's conformance-backed compatibility claim.
///
/// Construction is crate-private on purpose: a [`QualifiedRoute`] is
/// evidence, and the only evidence producer is the conformance suite.
/// The claim names the route fingerprint and the exact-capture artifact
/// schema version alongside the integration and lifecycle version, so a
/// qualification is checkable against its [`ProviderCaptureRoute`] row
/// field for field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualifiedRoute {
    route: RoutePolicy,
    integration: &'static str,
    fingerprint: &'static str,
    artifact_schema_version: i64,
    lifecycle_version: i64,
    evidence_digest: String,
}

impl QualifiedRoute {
    /// Mint a qualification from a passing conformance run. Crate-
    /// private: only the conformance suite calls this.
    pub(crate) fn new_sdk_hook(
        integration: &'static str,
        fingerprint: &'static str,
        artifact_schema_version: i64,
        lifecycle_version: i64,
        evidence_digest: String,
    ) -> Self {
        Self {
            route: RoutePolicy::SdkHook,
            integration,
            fingerprint,
            artifact_schema_version,
            lifecycle_version,
            evidence_digest,
        }
    }

    /// Mint the proxy route's qualification from a passing proxy
    /// conformance run. Crate-private, like the SDK-hook mint: only a
    /// conformance suite mints evidence.
    pub(crate) fn new_proxy(
        integration: &'static str,
        fingerprint: &'static str,
        artifact_schema_version: i64,
        lifecycle_version: i64,
        evidence_digest: String,
    ) -> Self {
        Self {
            route: RoutePolicy::Proxy,
            integration,
            fingerprint,
            artifact_schema_version,
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

    /// The route fingerprint — the capture-boundary shape the claim
    /// covers.
    #[must_use]
    pub const fn fingerprint(&self) -> &'static str {
        self.fingerprint
    }

    /// The exact-capture artifact schema major the route's records are
    /// written under.
    #[must_use]
    pub const fn artifact_schema_version(&self) -> i64 {
        self.artifact_schema_version
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
            "{} integration={} fingerprint={} schema={} lifecycle={} evidence={}",
            self.route,
            self.integration,
            self.fingerprint,
            self.artifact_schema_version,
            self.lifecycle_version,
            self.evidence_digest
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

/// The closed support-state vocabulary of the provider-capture route
/// registry: the same three verdicts the source-adapter matrix's
/// observed-fingerprint reconciliation uses, so the two matrices read
/// with one vocabulary without either subsuming the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RouteSupportState {
    /// The claim is published and conformance evidence backs it.
    Supported,
    /// The project explicitly declines the claim: the integration shape
    /// is named so nobody reads silence as support.
    Unsupported,
    /// The route shape is named but no conformance evidence exists
    /// either way — the honest third verdict, never folded into either
    /// of the others.
    Unobserved,
}

/// Why a support-state token could not be parsed. Closed and
/// content-free: only the offending token's existence is reportable,
/// never its text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteStateError {
    /// The token is not one of the three registry state tokens.
    Unknown,
}

impl fmt::Display for RouteStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown route support-state token")
    }
}

impl std::error::Error for RouteStateError {}

impl RouteSupportState {
    /// Every state, in vocabulary order.
    #[must_use]
    pub const fn all() -> [Self; 3] {
        [Self::Supported, Self::Unsupported, Self::Unobserved]
    }

    /// The bounded registry token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Unobserved => "unobserved",
        }
    }

    /// Parse a registry state token, failing closed.
    ///
    /// # Errors
    /// [`RouteStateError::Unknown`] when `text` is not one of the three
    /// state tokens.
    pub fn parse(text: &str) -> Result<Self, RouteStateError> {
        match text {
            "supported" => Ok(Self::Supported),
            "unsupported" => Ok(Self::Unsupported),
            "unobserved" => Ok(Self::Unobserved),
            _ => Err(RouteStateError::Unknown),
        }
    }
}

impl fmt::Display for RouteSupportState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

/// One published provider-capture route row: a claim the project makes
/// about an exact-capture route, the evidence that qualifies it, and
/// the boundary the claim stops at.
///
/// Rows are `const` data in [`PUBLISHED_REGISTRY`]; there is no
/// runtime constructor, so the published registry cannot grow except in
/// the same commit as its conformance evidence — the property the
/// release gate checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderCaptureRoute {
    route: RoutePolicy,
    integration: &'static str,
    fingerprint: &'static str,
    artifact_schema_version: i64,
    lifecycle_version: i64,
    artifact_kinds: &'static [&'static str],
    state: RouteSupportState,
    evidence_suite: &'static str,
    known_gap: &'static str,
}

impl ProviderCaptureRoute {
    /// The route policy this row claims.
    #[must_use]
    pub const fn route(&self) -> RoutePolicy {
        self.route
    }

    /// The bounded integration token the row names.
    #[must_use]
    pub const fn integration(&self) -> &'static str {
        self.integration
    }

    /// The route fingerprint — the capture-boundary shape the claim
    /// covers.
    #[must_use]
    pub const fn fingerprint(&self) -> &'static str {
        self.fingerprint
    }

    /// The exact-capture artifact schema major the route's records are
    /// written under.
    #[must_use]
    pub const fn artifact_schema_version(&self) -> i64 {
        self.artifact_schema_version
    }

    /// The [`crate::inference_observer`] lifecycle version the row was
    /// verified against.
    #[must_use]
    pub const fn lifecycle_version(&self) -> i64 {
        self.lifecycle_version
    }

    /// The provider-boundary artifact kinds the route captures.
    #[must_use]
    pub const fn artifact_kinds(&self) -> &'static [&'static str] {
        self.artifact_kinds
    }

    /// The row's support state.
    #[must_use]
    pub const fn state(&self) -> RouteSupportState {
        self.state
    }

    /// The conformance suite that qualifies the row — the module path
    /// of the only producer of the row's evidence.
    #[must_use]
    pub const fn evidence_suite(&self) -> &'static str {
        self.evidence_suite
    }

    /// The known gap: the boundary the claim stops at, in content-free
    /// prose.
    #[must_use]
    pub const fn known_gap(&self) -> &'static str {
        self.known_gap
    }

    /// Whether a conformance-minted qualification satisfies this row's
    /// published claim: the same integration, the same route
    /// fingerprint, the same artifact schema and lifecycle versions.
    /// Any drift is a mismatch the release gate fails on, never a
    /// best-effort match.
    ///
    /// # Errors
    /// [`RegistryMismatch`] naming the first field that disagrees.
    pub fn admits(&self, qualification: &QualifiedRoute) -> Result<(), RegistryMismatch> {
        if qualification.integration() != self.integration {
            return Err(RegistryMismatch::IntegrationMismatch {
                route: self.route,
                expected: self.integration,
                found: qualification.integration(),
            });
        }
        if qualification.fingerprint() != self.fingerprint {
            return Err(RegistryMismatch::FingerprintMismatch {
                route: self.route,
                expected: self.fingerprint,
                found: qualification.fingerprint(),
            });
        }
        if qualification.artifact_schema_version() != self.artifact_schema_version {
            return Err(RegistryMismatch::ArtifactSchemaVersionMismatch {
                route: self.route,
                expected: self.artifact_schema_version,
                found: qualification.artifact_schema_version(),
            });
        }
        if qualification.lifecycle_version() != self.lifecycle_version {
            return Err(RegistryMismatch::LifecycleVersionMismatch {
                route: self.route,
                expected: self.lifecycle_version,
                found: qualification.lifecycle_version(),
            });
        }
        Ok(())
    }
}

/// The published provider-capture route registry: every exact-capture
/// route the project claims, each with the conformance suite that
/// qualifies it (plan Phase 9; threat `EC-04`). A fingerprint absent
/// here is a claim the project does not make — the same rule the
/// source-adapter matrix states, for the provider-capture boundary.
///
/// Both routes claim the full [`PROVIDER_CAPTURE_ARTIFACT_KINDS`] set:
/// a route that captured a subset would leave provider attempts the
/// coverage ledger counts `partial`, which no supported route may do.
pub const PUBLISHED_REGISTRY: [ProviderCaptureRoute; 2] = [
    ProviderCaptureRoute {
        route: RoutePolicy::SdkHook,
        integration: FIRST_PARTY_OPENAI_HTTP1,
        fingerprint: ROUTE_FINGERPRINT_OPENAI_HTTP1,
        artifact_schema_version: INFERENCE_ARTIFACT_VERSION,
        lifecycle_version: INFERENCE_OBSERVER_VERSION,
        artifact_kinds: PROVIDER_CAPTURE_ARTIFACT_KINDS,
        state: RouteSupportState::Supported,
        evidence_suite: "crate::openai_conformance::TransportConformance",
        known_gap: "Claims the OpenAI-compatible chat boundary of the first-party HTTP/1.1 \
             transport driven through the versioned observer lifecycle: decoded request \
             bytes, ordered response and stream events, retries, usage, and transport \
             errors. Claims no ambient instrumentation of a third-party client, no other \
             wire protocol, and no non-OpenAI provider API. Evidence: the transport \
             conformance suite's full scene set over real loopback connections.",
    },
    ProviderCaptureRoute {
        route: RoutePolicy::Proxy,
        integration: FIRST_PARTY_OPENAI_PROXY,
        fingerprint: ROUTE_FINGERPRINT_OPENAI_PROXY,
        artifact_schema_version: INFERENCE_ARTIFACT_VERSION,
        lifecycle_version: INFERENCE_OBSERVER_VERSION,
        artifact_kinds: PROVIDER_CAPTURE_ARTIFACT_KINDS,
        state: RouteSupportState::Supported,
        evidence_suite: "crate::openai_proxy_conformance::ProxyConformance",
        known_gap: "Claims only traffic explicitly routed through the first-party capture \
             proxy: faithful request forwarding, ordered relay, ordered retries, \
             transport errors, usage, and credential exclusion at the proxy boundary. \
             Traffic that bypasses the proxy is unobserved, never claimed; no \
             transparent or intercepting deployment is claimed. Evidence: the proxy \
             conformance suite's full scene set over real loopback connections.",
    },
];

/// Borrow the published registry.
#[must_use]
pub const fn published_registry() -> &'static [ProviderCaptureRoute] {
    &PUBLISHED_REGISTRY
}

/// Why a compatibility claim and the published registry disagree.
/// Closed and content-free: tokens and integers only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryMismatch {
    /// The registry publishes a route no conformance-backed claim in the
    /// checked matrix backs: a published row without its evidence.
    UnbackedClaim(RoutePolicy),
    /// The claim names a different integration than the row publishes.
    IntegrationMismatch {
        /// The published row's route.
        route: RoutePolicy,
        /// The integration the row publishes.
        expected: &'static str,
        /// The integration the claim names.
        found: &'static str,
    },
    /// The claim's route fingerprint differs from the row's.
    FingerprintMismatch {
        /// The published row's route.
        route: RoutePolicy,
        /// The fingerprint the row publishes.
        expected: &'static str,
        /// The fingerprint the claim carries.
        found: &'static str,
    },
    /// The claim's exact-capture artifact schema version differs from
    /// the row's.
    ArtifactSchemaVersionMismatch {
        /// The published row's route.
        route: RoutePolicy,
        /// The schema version the row publishes.
        expected: i64,
        /// The schema version the claim carries.
        found: i64,
    },
    /// The claim's observer lifecycle version differs from the row's.
    LifecycleVersionMismatch {
        /// The published row's route.
        route: RoutePolicy,
        /// The lifecycle version the row publishes.
        expected: i64,
        /// The lifecycle version the claim carries.
        found: i64,
    },
}

impl fmt::Display for RegistryMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnbackedClaim(route) => {
                write!(
                    formatter,
                    "registry publishes {route} with no conformance-backed claim"
                )
            }
            Self::IntegrationMismatch {
                route,
                expected,
                found,
            } => {
                write!(
                    formatter,
                    "{route}: integration {found:?} != published {expected:?}"
                )
            }
            Self::FingerprintMismatch {
                route,
                expected,
                found,
            } => {
                write!(
                    formatter,
                    "{route}: fingerprint {found:?} != published {expected:?}"
                )
            }
            Self::ArtifactSchemaVersionMismatch {
                route,
                expected,
                found,
            } => {
                write!(
                    formatter,
                    "{route}: artifact schema v{found} != published v{expected}"
                )
            }
            Self::LifecycleVersionMismatch {
                route,
                expected,
                found,
            } => {
                write!(
                    formatter,
                    "{route}: lifecycle version {found} != published {expected}"
                )
            }
        }
    }
}

impl std::error::Error for RegistryMismatch {}

/// The compatibility matrix: every route whose exact-capture claim the
/// project backs with conformance evidence.
///
/// Freshly constructed it is empty — absence of a row is the normal
/// state of an unqualified route, and the matrix grows only through
/// [`CompatibilityMatrix::record`] and
/// [`CompatibilityMatrix::record_proxy`] of passing conformance
/// reports.
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
        self.upsert(qualification);
        Ok(())
    }

    /// Record the proxy conformance report's qualification.
    ///
    /// # Errors
    /// [`MatrixError::Unqualified`] when the report carries no
    /// qualification because its conformance run did not pass every
    /// scene.
    pub fn record_proxy(
        &mut self,
        report: &crate::openai_proxy_conformance::ProxyConformanceReport,
    ) -> Result<(), MatrixError> {
        let qualification = report
            .qualification()
            .ok_or(MatrixError::Unqualified)?
            .clone();
        self.upsert(qualification);
        Ok(())
    }

    /// Insert or replace one route's row; re-recording the same
    /// evidence is idempotent, and different evidence for one route
    /// replaces the row, because the matrix states the qualification,
    /// not its history.
    fn upsert(&mut self, qualification: QualifiedRoute) {
        if let Some(existing) = self
            .routes
            .iter()
            .find(|route| route.route == qualification.route)
        {
            if existing == &qualification {
                return;
            }
            self.routes
                .retain(|route| route.route != qualification.route);
        }
        self.routes.push(qualification);
        self.routes.sort_by_key(|route| route.route);
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

    /// The release check connecting the matrix to the published
    /// registry: every published row must be backed by a live
    /// conformance qualification it admits.
    ///
    /// The reverse direction holds structurally — the matrix cannot
    /// claim a route [`PUBLISHED_REGISTRY`] does not publish, because
    /// [`RoutePolicy`] is closed and the registry publishes a row for
    /// every route — and the unit tests pin that totality, so checking
    /// it here again would be dead code.
    ///
    /// # Errors
    /// [`RegistryMismatch::UnbackedClaim`] when a published row has no
    /// claim in this matrix, or the field mismatch that disqualified a
    /// present claim.
    pub fn matches_published_registry(&self) -> Result<(), RegistryMismatch> {
        for row in published_registry() {
            let qualification = self
                .route(row.route())
                .ok_or(RegistryMismatch::UnbackedClaim(row.route()))?;
            row.admits(qualification)?;
        }
        Ok(())
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
    use crate::expected_inference::InferenceArtifactKind;
    use crate::fingerprint::SourceFingerprint;

    fn mint_sdk_hook() -> QualifiedRoute {
        QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION,
            "ab".repeat(32),
        )
    }

    fn mint_proxy() -> QualifiedRoute {
        QualifiedRoute::new_proxy(
            FIRST_PARTY_OPENAI_PROXY,
            ROUTE_FINGERPRINT_OPENAI_PROXY,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION,
            "cd".repeat(32),
        )
    }

    #[test]
    fn fresh_matrix_claims_nothing() {
        let matrix = CompatibilityMatrix::new();
        assert!(matrix.is_empty());
        assert!(!matrix.is_qualified(RoutePolicy::SdkHook));
        assert!(!matrix.is_qualified(RoutePolicy::Proxy));
    }

    #[test]
    fn qualification_is_version_pinned_by_construction() {
        let route = mint_sdk_hook();
        assert_eq!(route.route(), RoutePolicy::SdkHook);
        assert_eq!(route.integration(), FIRST_PARTY_OPENAI_HTTP1);
        assert_eq!(route.fingerprint(), ROUTE_FINGERPRINT_OPENAI_HTTP1);
        assert_eq!(route.artifact_schema_version(), INFERENCE_ARTIFACT_VERSION);
        assert_eq!(route.lifecycle_version(), INFERENCE_OBSERVER_VERSION);
        assert_eq!(route.evidence_digest().len(), 64);
    }

    #[test]
    fn the_proxy_mint_pins_the_proxy_route() {
        let route = mint_proxy();
        assert_eq!(route.route(), RoutePolicy::Proxy);
        assert_eq!(route.integration(), FIRST_PARTY_OPENAI_PROXY);
        assert_eq!(route.fingerprint(), ROUTE_FINGERPRINT_OPENAI_PROXY);
        assert_eq!(route.artifact_schema_version(), INFERENCE_ARTIFACT_VERSION);
        assert_eq!(route.lifecycle_version(), INFERENCE_OBSERVER_VERSION);
        assert_eq!(route.evidence_digest().len(), 64);
    }

    #[test]
    fn the_published_registry_claims_exactly_both_first_party_routes() {
        let registry = published_registry();
        assert_eq!(registry.len(), 2);
        let sdk = registry
            .iter()
            .find(|row| row.route() == RoutePolicy::SdkHook)
            .expect("the SDK-hook row");
        assert_eq!(sdk.integration(), FIRST_PARTY_OPENAI_HTTP1);
        assert_eq!(sdk.fingerprint(), ROUTE_FINGERPRINT_OPENAI_HTTP1);
        assert_eq!(sdk.state(), RouteSupportState::Supported);
        assert_eq!(sdk.artifact_schema_version(), INFERENCE_ARTIFACT_VERSION);
        assert_eq!(sdk.lifecycle_version(), INFERENCE_OBSERVER_VERSION);
        assert_eq!(
            sdk.evidence_suite(),
            "crate::openai_conformance::TransportConformance"
        );
        assert!(!sdk.known_gap().is_empty());
        let proxy = registry
            .iter()
            .find(|row| row.route() == RoutePolicy::Proxy)
            .expect("the proxy row");
        assert_eq!(proxy.integration(), FIRST_PARTY_OPENAI_PROXY);
        assert_eq!(proxy.fingerprint(), ROUTE_FINGERPRINT_OPENAI_PROXY);
        assert_eq!(proxy.state(), RouteSupportState::Supported);
        assert_eq!(
            proxy.evidence_suite(),
            "crate::openai_proxy_conformance::ProxyConformance"
        );
        assert!(!proxy.known_gap().is_empty());
    }

    #[test]
    fn the_registry_is_total_over_the_route_vocabulary() {
        // Every route policy has a published row, so a matrix can never
        // claim a route the registry does not publish — the reverse
        // direction of the release check holds structurally.
        for route in RoutePolicy::all() {
            assert!(
                published_registry().iter().any(|row| row.route() == route),
                "no published row for route {route}"
            );
        }
    }

    #[test]
    fn route_fingerprints_satisfy_the_source_fingerprint_grammar() {
        // The route fingerprint shares the source-fingerprint grammar:
        // publishable, coordinate-free, safe to carry in a denial.
        for fingerprint in [
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_PROXY,
        ] {
            SourceFingerprint::parse(fingerprint)
                .unwrap_or_else(|error| panic!("route fingerprint {fingerprint}: {error}"));
        }
    }

    #[test]
    fn kinds_const_matches_the_closed_artifact_vocabulary() {
        let expected: Vec<&str> = InferenceArtifactKind::all()
            .iter()
            .map(|kind| kind.token())
            .collect();
        assert_eq!(PROVIDER_CAPTURE_ARTIFACT_KINDS, expected.as_slice());
        for row in published_registry() {
            assert_eq!(row.artifact_kinds(), PROVIDER_CAPTURE_ARTIFACT_KINDS);
        }
    }

    #[test]
    fn support_state_vocabulary_parses_fail_closed() {
        for state in RouteSupportState::all() {
            assert_eq!(RouteSupportState::parse(state.token()), Ok(state));
        }
        assert_eq!(
            RouteSupportState::parse("beta"),
            Err(RouteStateError::Unknown)
        );
        assert_eq!(RouteSupportState::parse(""), Err(RouteStateError::Unknown));
        assert_eq!(
            RouteSupportState::parse("Supported"),
            Err(RouteStateError::Unknown)
        );
    }

    #[test]
    fn a_registry_row_admits_its_own_mint() {
        for row in published_registry() {
            let qualification = match row.route() {
                RoutePolicy::SdkHook => mint_sdk_hook(),
                RoutePolicy::Proxy => mint_proxy(),
            };
            assert_eq!(row.admits(&qualification), Ok(()));
        }
    }

    #[test]
    fn a_row_rejects_each_drifted_field() {
        let row = published_registry()
            .iter()
            .find(|row| row.route() == RoutePolicy::SdkHook)
            .expect("the SDK-hook row");

        let wrong_integration = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_PROXY,
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION,
            "ab".repeat(32),
        );
        assert_eq!(
            row.admits(&wrong_integration),
            Err(RegistryMismatch::IntegrationMismatch {
                route: RoutePolicy::SdkHook,
                expected: FIRST_PARTY_OPENAI_HTTP1,
                found: FIRST_PARTY_OPENAI_PROXY,
            })
        );

        let wrong_fingerprint = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_PROXY,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION,
            "ab".repeat(32),
        );
        assert_eq!(
            row.admits(&wrong_fingerprint),
            Err(RegistryMismatch::FingerprintMismatch {
                route: RoutePolicy::SdkHook,
                expected: ROUTE_FINGERPRINT_OPENAI_HTTP1,
                found: ROUTE_FINGERPRINT_OPENAI_PROXY,
            })
        );

        let wrong_schema = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            INFERENCE_ARTIFACT_VERSION + 1,
            INFERENCE_OBSERVER_VERSION,
            "ab".repeat(32),
        );
        assert_eq!(
            row.admits(&wrong_schema),
            Err(RegistryMismatch::ArtifactSchemaVersionMismatch {
                route: RoutePolicy::SdkHook,
                expected: INFERENCE_ARTIFACT_VERSION,
                found: INFERENCE_ARTIFACT_VERSION + 1,
            })
        );

        let wrong_lifecycle = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION + 1,
            "ab".repeat(32),
        );
        assert_eq!(
            row.admits(&wrong_lifecycle),
            Err(RegistryMismatch::LifecycleVersionMismatch {
                route: RoutePolicy::SdkHook,
                expected: INFERENCE_OBSERVER_VERSION,
                found: INFERENCE_OBSERVER_VERSION + 1,
            })
        );
    }

    #[test]
    fn a_full_matrix_matches_the_published_registry() {
        let mut matrix = CompatibilityMatrix::new();
        matrix.upsert(mint_sdk_hook());
        matrix.upsert(mint_proxy());
        assert_eq!(matrix.matches_published_registry(), Ok(()));
    }

    #[test]
    fn a_partial_publication_fails_the_release_check() {
        let empty = CompatibilityMatrix::new();
        assert_eq!(
            empty.matches_published_registry(),
            Err(RegistryMismatch::UnbackedClaim(RoutePolicy::SdkHook))
        );

        let mut half = CompatibilityMatrix::new();
        half.upsert(mint_sdk_hook());
        assert_eq!(
            half.matches_published_registry(),
            Err(RegistryMismatch::UnbackedClaim(RoutePolicy::Proxy))
        );
    }

    #[test]
    fn fresh_evidence_replaces_a_row_without_stacking_claims() {
        let mut matrix = CompatibilityMatrix::new();
        matrix.upsert(mint_sdk_hook());
        let replaced = QualifiedRoute::new_sdk_hook(
            FIRST_PARTY_OPENAI_HTTP1,
            ROUTE_FINGERPRINT_OPENAI_HTTP1,
            INFERENCE_ARTIFACT_VERSION,
            INFERENCE_OBSERVER_VERSION,
            "ee".repeat(32),
        );
        matrix.upsert(replaced.clone());
        assert_eq!(matrix.len(), 1);
        assert_eq!(matrix.route(RoutePolicy::SdkHook), Some(&replaced));
        // The release check still demands the full registry: fresh
        // evidence replaces a row, it never shrinks what a publication
        // must back.
        matrix.upsert(mint_proxy());
        assert_eq!(matrix.len(), 2);
        assert_eq!(matrix.matches_published_registry(), Ok(()));
    }
}
