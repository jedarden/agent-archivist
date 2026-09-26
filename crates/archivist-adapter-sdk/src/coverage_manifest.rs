// SPDX-License-Identifier: Apache-2.0

//! The published inference-coverage manifest (plan Phase 9 exit gate: "the
//! coverage report separately states semantic session coverage and exact
//! inference coverage, including observed, partial, failed, and unobserved
//! counts for each instrumented client"; the 1.0 gate: exact capture and
//! its independent coverage report join the 1.0 compatibility matrix).
//!
//! One document joins four inputs the crate already owns, and it is the
//! only place they are published together:
//!
//! - the [`crate::compatibility::CompatibilityMatrix`] names the claimed
//!   routes — every integration whose exact-capture claim conformance
//!   evidence backs, with the lifecycle version and evidence digest each
//!   claim rests on;
//! - the [`ExpectedInferenceLedger`]'s route partition supplies the
//!   content-free exact counters — observed, partial, failed, unobserved —
//!   plus the open denominator, per instrumented client and per closed
//!   route, with explicit zeroes for a route nobody has sent traffic
//!   through (never a coverage claim by absence);
//! - the semantic session states ([`CoverageCounts`], requirement
//!   CAP-010's vocabulary) ride in their own subtree, side by side with the
//!   exact counters and never merged into them — the two dimensions stay
//!   independently readable, so a session that is semantically current and
//!   exactly unobserved reads as both (threat `EC-13`);
//! - the ephemeral flush report names the flush outcome explicitly
//!   (requirement CAP-007): `complete` only when the sink acknowledged
//!   every recorded teardown, so an unpublished completion claim cannot
//!   hide behind the counters.
//!
//! The manifest is bounded and content-free like every report in this
//! crate: a fixed key set of closed-vocabulary tokens, version integers,
//! and saturating counters — no session, host, path, prompt, provider, or
//! credential text can appear, because no member accepts it. Its canonical
//! bytes digest to the coverage evidence a verification run records: the
//! manifest is content-addressed exactly so a verification manifest can
//! name it (docs/notes/verification.md, the `coverage-report` evidence
//! kind) without carrying it.

use std::fmt;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256::{digest, encode_hex};

use crate::compatibility::CompatibilityMatrix;
use crate::ephemeral_flush::{
    EphemeralCapturePolicy, EphemeralCompletion, EphemeralFlushReport, FlushAbandonment,
};
use crate::expected_inference::{
    EXPECTATION_VERSION, ExpectedInferenceLedger, RouteCoverage, RoutePolicy,
};
use crate::inference_observer::FlushState;
use crate::status::CoverageCounts;

/// The schema token of the published manifest. Growth is a new token — a
/// fixed key set never grows in place.
pub const INFERENCE_COVERAGE_SCHEMA: &str = "archivist.inference-coverage/v1";

/// The integer version axis of the manifest schema, pinned by the token
/// above. A consumer branches on the integer; the token is the human
/// spelling of the same fact.
pub const INFERENCE_COVERAGE_SCHEMA_VERSION: i64 = 1;

/// One instrumented client's published row: the compatibility claim and
/// the exact-coverage counters of the route it was qualified through.
///
/// The row exists only for a claimed route — a [`QualifiedRoute`] the
/// conformance suite minted — so an integration token never appears
/// without its evidence. A claimed client through which no expectation ran
/// reports explicit zeroes in every bucket: absence of traffic stays
/// visible and never reads as complete coverage.
///
/// [`QualifiedRoute`]: crate::compatibility::QualifiedRoute
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientCoverage {
    /// The bounded integration token the matrix claims.
    pub integration: &'static str,
    /// The route policy the client was qualified through; the exact
    /// counters are its route's partition of the ledger.
    pub route: RoutePolicy,
    /// The [`crate::inference_observer`] lifecycle version the claim was
    /// verified against.
    pub lifecycle_version: i64,
    /// The SHA-256 hex digest of the canonical conformance evidence
    /// backing the claim.
    pub evidence: String,
    /// The route's exact-coverage counters: the four closed outcomes plus
    /// the open denominator, content-free.
    pub coverage: RouteCoverage,
}

impl ClientCoverage {
    /// The bounded report representation: one flat, fixed key set — the
    /// claim (integration, route, lifecycle version, evidence) beside its
    /// route's exact counters. Exact-only by construction: no semantic
    /// coverage token has a member here.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("evidence", Value::Text(self.evidence.clone()));
        object.set("integration", Value::Text(self.integration.to_owned()));
        object.set("lifecycle_version", Value::Int(self.lifecycle_version));
        match self.coverage.to_json() {
            Value::Object(coverage) => {
                for (name, value) in coverage.iter() {
                    if name != "route" {
                        object.set(name, value.clone());
                    }
                }
            }
            _ => unreachable!("RouteCoverage::to_json returns an object"),
        }
        object.set("route", Value::Text(self.route.token().to_owned()));
        Value::Object(object)
    }
}

/// The flush-outcome section of the manifest: the bounded projection of
/// an [`EphemeralFlushReport`] (requirement CAP-007).
///
/// `outcome` is always named — `complete` only when every recorded
/// teardown was acknowledged and nothing was abandoned — so a reader never
/// has to infer durability from the exact counters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlushOutcome {
    /// The completion claim the flush evidence supports.
    pub outcome: EphemeralCompletion,
    /// The aggregate flush state across recorded teardowns.
    pub flush_state: FlushState,
    /// The bounded cause the acknowledgement wait was abandoned, when one
    /// applied. Presence alone withholds completion.
    pub abandonment: Option<FlushAbandonment>,
    /// The capture policy the gate applied.
    pub policy: EphemeralCapturePolicy,
    /// How many logical inferences were torn down through the gate.
    pub logical_inferences: u64,
    /// How many of those teardowns the sink acknowledged.
    pub acknowledged: u64,
    /// Canonical artifacts the sinks accepted; their durability is not
    /// covered while the outcome is incomplete.
    pub emitted_artifacts: u64,
}

impl FlushOutcome {
    /// Project a teardown report. The projection only narrows: every
    /// member is copied from the report's own bounded vocabulary.
    #[must_use]
    pub fn of(report: &EphemeralFlushReport) -> Self {
        Self {
            outcome: report.outcome,
            flush_state: report.flush_state,
            abandonment: report.abandonment,
            policy: report.policy,
            logical_inferences: report.logical_inferences,
            acknowledged: report.acknowledged,
            emitted_artifacts: report.emitted_artifacts,
        }
    }

    /// The wire token of the completion claim, matching the metrics
    /// registry's closed `flush_outcome` vocabulary: `complete` or
    /// `incomplete`, never an unclassified value.
    #[must_use]
    pub const fn outcome_token(self) -> &'static str {
        match self.outcome {
            EphemeralCompletion::Complete => "complete",
            EphemeralCompletion::Incomplete => "incomplete",
        }
    }

    /// The bounded report representation. `abandonment` is present only
    /// when a cause was recorded.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        if let Some(cause) = self.abandonment {
            object.set("abandonment", Value::Text(cause.token().to_owned()));
        }
        object.set(
            "acknowledged",
            Value::Int(saturating_i64(self.acknowledged)),
        );
        object.set(
            "emitted_artifacts",
            Value::Int(saturating_i64(self.emitted_artifacts)),
        );
        object.set(
            "logical_inferences",
            Value::Int(saturating_i64(self.logical_inferences)),
        );
        object.set("outcome", Value::Text(self.outcome_token().to_owned()));
        object.set("policy", Value::Text(self.policy.token().to_owned()));
        object.set("state", Value::Text(self.flush_state.token().to_owned()));
        Value::Object(object)
    }
}

impl From<&EphemeralFlushReport> for FlushOutcome {
    fn from(report: &EphemeralFlushReport) -> Self {
        Self::of(report)
    }
}

/// The published inference-coverage manifest: the per-client exact
/// counters, the closed-route denominator, the semantic session states,
/// and the flush outcome — one bounded, content-free document.
///
/// Construct it through [`InferenceCoverageManifest::publish`]; the fields
/// are otherwise readable only, so a published manifest cannot be edited
/// after the fact. The type deliberately exposes **no** completeness
/// predicate: a manifest can carry observed and unobserved clients at the
/// same time, and both stay visible (plan Phase 9, threat `EC-13`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceCoverageManifest {
    /// One row per claimed integration, in matrix (registry) order.
    clients: Vec<ClientCoverage>,
    /// Every closed route's counters, in [`RoutePolicy::all`] order —
    /// including routes the matrix does not claim, whose activity stays
    /// visible here instead of vanishing for lack of a claim.
    routes: [RouteCoverage; 2],
    /// The semantic session states, carried side by side and never merged
    /// into the exact counters.
    semantic_sessions: CoverageCounts,
    /// The named flush outcome.
    flush: FlushOutcome,
}

impl InferenceCoverageManifest {
    /// Publish the manifest for one conformance-backed matrix, one
    /// ledger's exact partition, one semantic snapshot, and one teardown
    /// report.
    ///
    /// A route the matrix claims with no expectations reports explicit
    /// zeroes — the claim rests on the conformance evidence, never on the
    /// absence of traffic. A route with expectations but no claim appears
    /// only in [`Self::routes`], where its counts stay visible: no client
    /// row exists for it, so the manifest never promotes unevidenced
    /// activity to a coverage claim.
    #[must_use]
    pub fn publish(
        matrix: &CompatibilityMatrix,
        ledger: &ExpectedInferenceLedger,
        semantic_sessions: CoverageCounts,
        flush: &EphemeralFlushReport,
    ) -> Self {
        let clients = matrix
            .routes()
            .iter()
            .map(|route| ClientCoverage {
                integration: route.integration(),
                route: route.route(),
                lifecycle_version: route.lifecycle_version(),
                evidence: route.evidence_digest().to_owned(),
                coverage: ledger.route_coverage(route.route()),
            })
            .collect();
        Self {
            clients,
            routes: ledger.route_states(),
            semantic_sessions,
            flush: FlushOutcome::of(flush),
        }
    }

    /// Every claimed client's row, in matrix order.
    #[must_use]
    pub fn clients(&self) -> &[ClientCoverage] {
        &self.clients
    }

    /// Every closed route's counters, in [`RoutePolicy::all`] order.
    #[must_use]
    pub const fn routes(&self) -> &[RouteCoverage; 2] {
        &self.routes
    }

    /// The semantic session states: the independent CAP-010 dimension,
    /// stated separately from the exact counters.
    #[must_use]
    pub const fn semantic_sessions(&self) -> &CoverageCounts {
        &self.semantic_sessions
    }

    /// The named flush outcome.
    #[must_use]
    pub const fn flush(&self) -> &FlushOutcome {
        &self.flush
    }

    /// The known-bypass count per route, in [`RoutePolicy::all`] order: a
    /// closed expectation with no matching artifact on its declared route.
    /// The sum across routes equals the ledger's closed unobserved total,
    /// because a bypass is never dropped from the denominator it joined.
    #[must_use]
    pub fn known_bypasses(&self) -> [u64; 2] {
        self.routes.each_ref().map(|route| route.unobserved)
    }

    /// The known-bypass count across every route.
    #[must_use]
    pub fn known_bypass_total(&self) -> u64 {
        self.routes.iter().map(|route| route.unobserved).sum()
    }

    /// The bounded report representation: one fixed top-level key set.
    /// The exact counters live under `clients` and `routes`; the semantic
    /// session states live under `semantic_sessions` alone; the flush
    /// outcome lives under `flush` alone. No key mixes the dimensions.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set(
            "clients",
            Value::Array(self.clients.iter().map(ClientCoverage::to_json).collect()),
        );
        object.set("expectation_version", Value::Int(EXPECTATION_VERSION));
        object.set("flush", self.flush.to_json());
        let mut bypasses = Object::new();
        for route in &self.routes {
            bypasses.set(
                route.route.token(),
                Value::Int(saturating_i64(route.unobserved)),
            );
        }
        bypasses.set(
            "total",
            Value::Int(saturating_i64(self.known_bypass_total())),
        );
        object.set("known_bypasses", Value::Object(bypasses));
        object.set(
            "routes",
            Value::Array(self.routes.iter().map(RouteCoverage::to_json).collect()),
        );
        object.set("schema", Value::Text(INFERENCE_COVERAGE_SCHEMA.to_owned()));
        object.set(
            "schema_version",
            Value::Int(INFERENCE_COVERAGE_SCHEMA_VERSION),
        );
        object.set("semantic_sessions", self.semantic_sessions.to_json());
        Value::Object(object)
    }

    /// The canonical RFC 8785 bytes of the manifest.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_json().canonical_bytes()
    }

    /// The SHA-256 hex digest of the canonical bytes: the coverage
    /// evidence a verification run records, content-addressed so the
    /// manifest can be named without being carried.
    #[must_use]
    pub fn evidence_digest(&self) -> String {
        encode_hex(&digest(&self.canonical_bytes()))
    }
}

impl fmt::Display for InferenceCoverageManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "inference coverage: clients={} bypasses={} flush={} semantic_sources={}",
            self.clients.len(),
            self.known_bypass_total(),
            self.flush.outcome_token(),
            self.semantic_sessions.total(),
        )
    }
}

/// Clip a counter into the protocol's signed wire range: counters grow
/// without wrapping into negative wire integers.
fn saturating_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ephemeral_flush::EphemeralFlushGate;
    use crate::expected_inference::{
        ExactOutcome, ExpectedEvent, ExpectedInferenceRecord, InferenceArtifactKind,
        InferenceIdentity, IntegrationFailure, ObservedArtifact,
    };
    use crate::inference_observer::{
        AttemptOutcome, InferenceObserver, InferenceObserverV1, RecordingArtifactSink,
    };
    use archivist_protocol::vocabulary::{
        InferenceRequestId, OpaqueId, ProviderAttemptId, Timestamp, TraceId,
    };

    fn id(seed: u8) -> InferenceIdentity {
        InferenceIdentity::new(
            TraceId::parse(&format!("0000000{seed}-1111-7111-8111-000000000001")).expect("trace"),
            InferenceRequestId::parse(&format!("0000000{seed}-2222-7222-8222-000000000002"))
                .expect("inference"),
        )
    }

    fn session(seed: u8) -> OpaqueId {
        OpaqueId::parse(&format!("session-{seed}")).expect("session")
    }

    fn timestamp() -> Timestamp {
        Timestamp::parse("2026-09-20T12:00:00Z").expect("timestamp")
    }

    fn record_on(seed: u8, route: RoutePolicy) -> ExpectedInferenceRecord {
        ExpectedInferenceRecord::new(id(seed), session(seed), route, timestamp())
    }

    fn artifact(seed: u8, ordinal: u64, kind: InferenceArtifactKind) -> ObservedArtifact {
        ObservedArtifact::new(
            id(seed),
            session(seed),
            ProviderAttemptId::parse(&format!("0000000{seed}-3333-7333-8333-{ordinal:012x}"))
                .expect("attempt"),
            ordinal,
            kind,
        )
    }

    /// One acknowledged logical inference, closed through the gate.
    fn acknowledged_inference(gate: &mut EphemeralFlushGate) {
        let mut inference = observer();
        inference
            .start_logical_inference(None)
            .expect("logical start");
        inference.start_provider_attempt().expect("attempt");
        inference
            .attempt_outcome(AttemptOutcome::Completed, None)
            .expect("completed attempt");
        gate.teardown(&mut inference)
            .expect("teardown closes the logical inference");
    }

    fn observer() -> InferenceObserverV1<RecordingArtifactSink> {
        InferenceObserverV1::new(
            archivist_protocol::vocabulary::TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b")
                .expect("tenant"),
            archivist_protocol::vocabulary::ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f")
                .expect("origin"),
            RecordingArtifactSink::new(),
        )
    }

    fn complete_flush() -> EphemeralFlushReport {
        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::RequireCompleteCapture);
        acknowledged_inference(&mut gate);
        gate.finish()
    }

    fn abandoned_flush() -> EphemeralFlushReport {
        let gate = EphemeralFlushGate::new(EphemeralCapturePolicy::BestEffort);
        gate.abandon(FlushAbandonment::StorageOutage)
    }

    /// A ledger holding every closed outcome on both routes: the proxy
    /// route carries an observed exchange and a known bypass; the hook
    /// route carries a partial, a failure, an unobserved bypass, and an
    /// open expectation.
    fn mixed_ledger() -> ExpectedInferenceLedger {
        let mut ledger = ExpectedInferenceLedger::new();
        ledger
            .persist(record_on(1, RoutePolicy::Proxy))
            .expect("persist");
        ledger
            .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        ledger
            .record_artifact(artifact(1, 0, InferenceArtifactKind::ProviderResponse))
            .expect("response");
        assert_eq!(ledger.close_completed(&id(1)), Ok(ExactOutcome::Observed));

        ledger
            .persist(record_on(2, RoutePolicy::Proxy))
            .expect("persist");
        assert_eq!(ledger.close_completed(&id(2)), Ok(ExactOutcome::Unobserved));

        ledger
            .persist(record_on(3, RoutePolicy::SdkHook))
            .expect("persist");
        ledger
            .record_artifact(artifact(3, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        assert_eq!(ledger.close_completed(&id(3)), Ok(ExactOutcome::Partial));

        ledger
            .persist(record_on(4, RoutePolicy::SdkHook))
            .expect("persist");
        assert_eq!(
            ledger.close_failed(&id(4), IntegrationFailure::RouteSelectionFailed),
            Ok(ExactOutcome::Failed)
        );

        ledger
            .persist(record_on(5, RoutePolicy::SdkHook))
            .expect("persist");
        assert_eq!(ledger.close_completed(&id(5)), Ok(ExactOutcome::Unobserved));

        ledger
            .persist(record_on(6, RoutePolicy::SdkHook))
            .expect("persist");
        ledger
    }

    fn object_keys(value: &Value) -> Vec<&str> {
        match value {
            Value::Object(object) => object.iter().map(|(name, _)| name).collect(),
            _ => panic!("expected an object, got {value:?}"),
        }
    }

    #[test]
    fn flush_outcome_is_always_named_and_fails_closed() {
        let complete = FlushOutcome::of(&complete_flush());
        assert_eq!(complete.outcome_token(), "complete");
        assert_eq!(complete.flush_state, FlushState::Acknowledged);
        assert_eq!(complete.logical_inferences, 1);
        assert_eq!(complete.acknowledged, 1);

        // An abandoned wait withholds completion and names the cause.
        let abandoned = FlushOutcome::of(&abandoned_flush());
        assert_eq!(abandoned.outcome_token(), "incomplete");
        assert_eq!(abandoned.abandonment, Some(FlushAbandonment::StorageOutage));
        let json = abandoned.to_json();
        let text = String::from_utf8(json.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"abandonment\":\"storage_outage\""));
        assert!(text.contains("\"outcome\":\"incomplete\""));

        // A gate that never ran still names an outcome: not started is
        // incomplete, never an unclassified or absent value.
        let idle =
            FlushOutcome::of(&EphemeralFlushGate::new(EphemeralCapturePolicy::BestEffort).finish());
        assert_eq!(idle.outcome_token(), "incomplete");
        assert_eq!(idle.flush_state, FlushState::NotStarted);
    }

    #[test]
    fn publish_without_a_claim_keeps_every_route_visible_and_names_no_client() {
        // An empty matrix claims nothing, so no client row exists — but
        // the ledger's route partition still reports every counter,
        // including the unclaimed route's bypasses.
        let ledger = mixed_ledger();
        let manifest = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &ledger,
            CoverageCounts::default(),
            &complete_flush(),
        );
        assert!(manifest.clients().is_empty());
        assert_eq!(manifest.routes()[0].unobserved, 1);
        assert_eq!(manifest.routes()[1].partial, 1);
        assert_eq!(manifest.routes()[1].failed, 1);
        assert_eq!(manifest.routes()[1].unobserved, 1);
        assert_eq!(manifest.routes()[1].open_expectations, 1);
        assert_eq!(manifest.known_bypasses(), [1, 1]);
        assert_eq!(manifest.known_bypass_total(), 2);

        let text = String::from_utf8(manifest.canonical_bytes()).expect("utf8");
        assert!(
            text.contains("\"known_bypasses\":{\"proxy\":1,\"sdk_hook\":1,\"total\":2}"),
            "bypasses are named per route with the total: {text}"
        );
    }

    #[test]
    fn manifest_json_has_a_fixed_key_set_with_disjoint_dimensions() {
        let mut semantic = CoverageCounts::default();
        semantic.record(crate::status::CoverageState::Current);
        semantic.record(crate::status::CoverageState::Current);
        let ledger = mixed_ledger();
        let manifest = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &ledger,
            semantic,
            &complete_flush(),
        );

        let json = manifest.to_json();
        assert_eq!(
            object_keys(&json),
            vec![
                "clients",
                "expectation_version",
                "flush",
                "known_bypasses",
                "routes",
                "schema",
                "schema_version",
                "semantic_sessions",
            ]
        );

        // The semantic subtree carries exactly the CAP-010 vocabulary; the
        // exact sections carry exactly the exact counters. `failed` and
        // `partial` exist in both vocabularies, which is why the rule is
        // about disjoint objects: no object ever mixes the dimensions.
        let Value::Object(ref object) = json else {
            panic!("manifest is an object");
        };
        let semantic = object.get("semantic_sessions").expect("semantic section");
        assert_eq!(
            object_keys(semantic),
            vec![
                "backfilled",
                "current",
                "failed",
                "missing",
                "partial",
                "unsupported",
            ]
        );
        let flush = object.get("flush").expect("flush section");
        assert_eq!(
            object_keys(flush),
            vec![
                "acknowledged",
                "emitted_artifacts",
                "logical_inferences",
                "outcome",
                "policy",
                "state",
            ]
        );
        for client in manifest.clients() {
            assert_eq!(
                object_keys(&client.to_json()),
                vec![
                    "evidence",
                    "failed",
                    "integration",
                    "lifecycle_version",
                    "observed",
                    "open_expectations",
                    "partial",
                    "route",
                    "unobserved",
                ]
            );
        }

        // The manifest names its schema version on both axes.
        let text = String::from_utf8(json.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"schema\":\"archivist.inference-coverage/v1\""));
        assert!(text.contains("\"schema_version\":1"));
        assert!(text.contains("\"expectation_version\":1"));
    }

    #[test]
    fn semantic_and_exact_dimensions_diverge_without_merging() {
        // A scope that is semantically current and exactly unobserved
        // reads as both, each in its own subtree, neither overwriting the
        // other.
        let mut semantic = CoverageCounts::default();
        semantic.record(crate::status::CoverageState::Current);
        let mut ledger = ExpectedInferenceLedger::new();
        ledger
            .persist(record_on(7, RoutePolicy::Proxy))
            .expect("persist");
        assert_eq!(ledger.close_completed(&id(7)), Ok(ExactOutcome::Unobserved));

        let manifest = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &ledger,
            semantic,
            &complete_flush(),
        );
        assert_eq!(manifest.semantic_sessions().current, 1);
        assert_eq!(manifest.routes()[0].unobserved, 1);
        assert_eq!(manifest.routes()[0].observed, 0);

        let text = String::from_utf8(manifest.canonical_bytes()).expect("utf8");
        assert!(text.contains("\"semantic_sessions\":{\"backfilled\":0,\"current\":1"));
        assert!(text.contains("\"unobserved\":1"));
        // The exact `observed` counter stays zero — semantic currency never
        // leaks into it.
        assert!(text.contains("\"observed\":0"));
    }

    #[test]
    fn manifest_bytes_are_canonical_and_the_digest_tracks_the_content() {
        let ledger = ExpectedInferenceLedger::new();
        let manifest = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &ledger,
            CoverageCounts::default(),
            &complete_flush(),
        );
        let digest = manifest.evidence_digest();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, manifest.evidence_digest());
        assert_eq!(manifest.canonical_bytes(), manifest.canonical_bytes());

        // Any counter movement moves the evidence digest: the manifest
        // cannot be replayed against different coverage.
        let mut grown = ExpectedInferenceLedger::new();
        grown
            .persist(record_on(8, RoutePolicy::Proxy))
            .expect("persist");
        let moved = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &grown,
            CoverageCounts::default(),
            &complete_flush(),
        );
        assert_ne!(moved.evidence_digest(), digest);
    }

    #[test]
    fn display_is_a_bounded_summary_line() {
        let ledger = ExpectedInferenceLedger::new();
        let manifest = InferenceCoverageManifest::publish(
            &CompatibilityMatrix::new(),
            &ledger,
            CoverageCounts::default(),
            &complete_flush(),
        );
        assert_eq!(
            manifest.to_string(),
            "inference coverage: clients=0 bypasses=0 flush=complete semantic_sources=0",
        );
    }

    #[test]
    fn required_events_flow_through_the_partition_helpers() {
        // Guards the helper contract the ledger tests rely on: a default
        // record requires the request-plus-terminal contract, so a single
        // request alone stays partial.
        let record = record_on(9, RoutePolicy::Proxy).requiring(ExpectedEvent::Terminal);
        let mut ledger = ExpectedInferenceLedger::new();
        ledger.persist(record).expect("persist");
        ledger
            .record_artifact(artifact(9, 0, InferenceArtifactKind::ProviderRequest))
            .expect("request");
        assert_eq!(ledger.close_completed(&id(9)), Ok(ExactOutcome::Partial));
        assert_eq!(
            ledger.route_coverage(RoutePolicy::Proxy).partial,
            1,
            "the close outcome lands in the route's partition"
        );
    }

    #[test]
    fn an_unacknowledged_teardown_is_counted_and_never_claims_completion() {
        // The flush section's counters are copied from the close report,
        // not recomputed: an unacknowledged close is counted unacknowledged
        // and the outcome stays incomplete.
        let mut sink = RecordingArtifactSink::new();
        sink.set_flush_state(FlushState::Incomplete);
        let mut inference = InferenceObserverV1::new(
            archivist_protocol::vocabulary::TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b")
                .expect("tenant"),
            archivist_protocol::vocabulary::ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f")
                .expect("origin"),
            sink,
        );
        inference
            .start_logical_inference(None)
            .expect("logical start");
        inference.start_provider_attempt().expect("attempt");
        inference
            .attempt_outcome(AttemptOutcome::Completed, None)
            .expect("completed attempt");
        let close = inference.close_logical_inference().expect("close");
        assert_eq!(close.flush_state, FlushState::Incomplete);

        let mut gate = EphemeralFlushGate::new(EphemeralCapturePolicy::BestEffort);
        gate.record(&close);
        let report = gate.finish();
        assert_eq!(report.logical_inferences, 1);
        assert_eq!(report.acknowledged, 0);
        let outcome = FlushOutcome::of(&report);
        assert_eq!(outcome.outcome_token(), "incomplete");
        let text = String::from_utf8(outcome.to_json().canonical_bytes()).expect("utf8");
        assert!(text.contains("\"acknowledged\":0"));
        assert!(text.contains("\"outcome\":\"incomplete\""));
        assert!(text.contains("\"state\":\"incomplete\""));
    }
}
