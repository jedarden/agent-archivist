// SPDX-License-Identifier: Apache-2.0

//! The orchestrator-provenance correlation record and the relationship fold
//! over it (plan Phase 9: "Have orchestrators reference canonical occurrence
//! IDs rather than uploading a second canonical transcript").
//!
//! An orchestrator that drove harness sessions owns its own attempt records.
//! This module gives those records an archive-side join that is **content-
//! free**: one record names the orchestrator's attempt identity and the
//! canonical [`OccurrenceId`]s the harness adapters already captured, and
//! nothing else. The session bytes live exactly where the adapters put them,
//! once; the record multiplies references, never transcripts.
//!
//! # What the record deliberately cannot say
//!
//! The member set is closed (unknown members are rejected, not retained), so
//! an orchestrator log cannot smuggle in a completeness assertion: there is
//! no member that could carry one. Correlation is not coverage. The exact-
//! inference denominator stays the expected-inference ledger, and a session
//! whose occurrences are all referenced here is not thereby "semantically
//! complete" — semantic capture stays independent of this record in every
//! case, exactly as the plan requires of every orchestrator-side input.
//!
//! # Identity
//!
//! The record's own identity is construction `orchestrator-correlation-v1`:
//! SHA-256 over the canonical record bytes with the digest member removed,
//! the same self-verifying exclusion shape as the usage summary (VAL-005).
//! Because the occurrence references are canonicalized to a sorted,
//! duplicate-free set at construction, the digest is a pure function of the
//! relationship the record states — two reports of one relationship are one
//! record identity, not two.
//!
//! The correlation identifiers are join handles, not identity inputs
//! ([`crate::correlation`], plan Section 7.4): this record cites them and
//! cites occurrences, and neither citation enters any blob, occurrence, or
//! object-key derivation.
//!
//! [`OccurrenceId`]: crate::vocabulary::OccurrenceId

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::derivation::FrameBuilder;
use crate::json::{self, Object, Value};
use crate::sha256;
use crate::vocabulary::{InferenceRequestId, OccurrenceId, OpaqueId, TenantId, TraceId};

/// The record-shape version this module derives
/// (`orchestrator_correlation_version`; plan Section 7.1: the record-shape
/// axis. A changed member set is a new version, never a silent rewrite).
pub const ORCHESTRATOR_CORRELATION_VERSION: i64 = 1;

/// The digest construction's domain label: SHA-256 over the canonical
/// record bytes with the digest member removed, framed like every ingest
/// identifier.
const DIGEST_LABEL: &str = "orchestrator-correlation-v1";

/// The closed v1 member set. A record carrying any other member is
/// rejected — this is the mechanical half of the family's no-claim rule:
/// there is no spelling of a completeness assertion this record accepts.
const RECORD_FIELD_NAMES: [&str; 7] = [
    "correlation_digest",
    "inference_request_id",
    "occurrence_ids",
    "orchestrator_attempt_id",
    "orchestrator_correlation_version",
    "tenant_id",
    "trace_id",
];

/// Why a record was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrchestratorCorrelationError {
    /// The bytes are not a bounded JSON object at all.
    Malformed {
        /// What failed, at the reader's level.
        reason: &'static str,
        /// The parser's own error, when one exists.
        source: Option<json::ParseError>,
    },
    /// A member is missing, unknown, mistyped, or out of grammar.
    Invalid {
        /// The offending member name.
        field: String,
        /// Why it was refused.
        reason: String,
    },
    /// The carried `correlation_digest` does not match the record's own
    /// canonical bytes — the record was altered after it was constructed.
    DigestMismatch {
        /// The digest the record carried.
        carried: String,
        /// The digest its canonical bytes derive.
        derived: String,
    },
}

impl fmt::Display for OrchestratorCorrelationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { reason, .. } => f.write_str(reason),
            Self::Invalid { field, reason } => {
                write!(f, "invalid {field}: {reason}")
            }
            Self::DigestMismatch { carried, derived } => {
                write!(
                    f,
                    "correlation digest mismatch: carried {carried}, derived {derived}"
                )
            }
        }
    }
}

impl std::error::Error for OrchestratorCorrelationError {}

/// One orchestrator's content-free reference from its own provenance to the
/// canonical occurrences its harness sessions produced. Build one with
/// [`OrchestratorCorrelation::new`]; read one back with
/// [`OrchestratorCorrelation::parse`], which re-verifies the digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchestratorCorrelation {
    tenant_id: TenantId,
    trace_id: TraceId,
    orchestrator_attempt_id: OpaqueId,
    inference_request_id: Option<InferenceRequestId>,
    occurrence_ids: Vec<OccurrenceId>,
    record: Object,
    digest: String,
}

impl OrchestratorCorrelation {
    /// Construct, digest, and canonically serialize one record.
    ///
    /// The occurrence references are canonicalized to ascending order; a
    /// duplicate reference is refused rather than silently collapsed, because
    /// stating one reference twice in one record is a caller bug, not a set.
    ///
    /// # Errors
    /// [`OrchestratorCorrelationError::Invalid`] when `occurrence_ids` is
    /// empty or carries a duplicate.
    pub fn new(
        tenant_id: TenantId,
        trace_id: TraceId,
        orchestrator_attempt_id: OpaqueId,
        inference_request_id: Option<InferenceRequestId>,
        occurrence_ids: Vec<OccurrenceId>,
    ) -> Result<Self, OrchestratorCorrelationError> {
        if occurrence_ids.is_empty() {
            return Err(invalid(
                "occurrence_ids",
                "a correlation record references at least one occurrence",
            ));
        }
        let mut occurrence_ids = occurrence_ids;
        occurrence_ids.sort();
        let duplicated = occurrence_ids
            .windows(2)
            .find_map(|window| (window[0] == window[1]).then_some(window[0]));
        if let Some(duplicate) = duplicated {
            return Err(invalid(
                "occurrence_ids",
                format!("duplicate reference {}", duplicate.to_hex()),
            ));
        }

        let mut record = Object::new();
        record.set(
            "orchestrator_correlation_version",
            Value::Int(ORCHESTRATOR_CORRELATION_VERSION),
        );
        record.set("tenant_id", Value::Text(tenant_id.as_str().to_owned()));
        record.set("trace_id", Value::Text(trace_id.as_str().to_owned()));
        record.set(
            "orchestrator_attempt_id",
            Value::Text(orchestrator_attempt_id.as_str().to_owned()),
        );
        if let Some(inference_request_id) = &inference_request_id {
            record.set(
                "inference_request_id",
                Value::Text(inference_request_id.as_str().to_owned()),
            );
        }
        record.set(
            "occurrence_ids",
            Value::Array(
                occurrence_ids
                    .iter()
                    .map(|occurrence| Value::Text(occurrence.to_hex()))
                    .collect(),
            ),
        );

        // Construction `orchestrator-correlation-v1`: the labeled frame over
        // the record's canonical bytes with the digest member removed — the
        // exclusion shape that makes the record self-verifying (VAL-005).
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(record.clone()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        record.set("correlation_digest", Value::Text(digest.clone()));

        Ok(Self {
            tenant_id,
            trace_id,
            orchestrator_attempt_id,
            inference_request_id,
            occurrence_ids,
            record,
            digest,
        })
    }

    /// Parse and fully verify record bytes: the closed member set, the
    /// version axis, every identifier's grammar, the reference set's
    /// ascending duplicate-free order, and the self-verifying digest.
    ///
    /// # Errors
    /// [`OrchestratorCorrelationError`] naming the first failure in that
    /// order.
    pub fn parse(bytes: &[u8]) -> Result<Self, OrchestratorCorrelationError> {
        let value =
            json::parse(bytes).map_err(|source| OrchestratorCorrelationError::Malformed {
                reason: "bounded parse of the correlation record bytes failed",
                source: Some(source),
            })?;
        Self::from_value(value)
    }

    /// Validate an already-parsed JSON value as a correlation record.
    ///
    /// # Errors
    /// As [`OrchestratorCorrelation::parse`].
    pub fn from_value(value: Value) -> Result<Self, OrchestratorCorrelationError> {
        let Value::Object(object) = value else {
            return Err(OrchestratorCorrelationError::Malformed {
                reason: "orchestrator correlation record is not a JSON object",
                source: None,
            });
        };

        // The closed member set, checked before any field is read: an
        // unknown member is refused, never retained — there is no member
        // this family could grow without a new record-shape version.
        for (name, _) in object.iter() {
            if !RECORD_FIELD_NAMES.contains(&name) {
                return Err(invalid(
                    name,
                    "unknown member; the correlation record's member set is closed",
                ));
            }
        }

        match object.get("orchestrator_correlation_version") {
            Some(Value::Int(ORCHESTRATOR_CORRELATION_VERSION)) => {}
            _ => {
                return Err(invalid(
                    "orchestrator_correlation_version",
                    format!("must be the integer {ORCHESTRATOR_CORRELATION_VERSION}"),
                ));
            }
        }

        let tenant_id = text(&object, "tenant_id", TenantId::parse)?;
        let trace_id = text(&object, "trace_id", TraceId::parse)?;
        let orchestrator_attempt_id = text(&object, "orchestrator_attempt_id", OpaqueId::parse)?;
        let inference_request_id = match object.get("inference_request_id") {
            None => None,
            Some(Value::Text(raw)) => Some(InferenceRequestId::parse(raw).map_err(|_| {
                invalid("inference_request_id", "not a canonical UUIDv7 identifier")
            })?),
            Some(_) => {
                return Err(invalid(
                    "inference_request_id",
                    "must be a text identifier when present",
                ));
            }
        };

        let occurrence_ids = occurrence_set(&object)?;

        // The self-verifying digest over the received bytes, recomputed with
        // the digest member removed: any alteration — including reordering
        // the reference array — fails here before the record is returned.
        let carried = match object.get("correlation_digest") {
            Some(Value::Text(carried)) => carried.clone(),
            _ => {
                return Err(invalid(
                    "correlation_digest",
                    "must be the record's lowercase hex digest",
                ));
            }
        };
        let mut without_digest = object.clone();
        let _removed = without_digest.remove("correlation_digest");
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(without_digest).canonical_bytes());
        let derived = sha256::encode_hex(&frame.finish());
        if carried != derived {
            return Err(OrchestratorCorrelationError::DigestMismatch { carried, derived });
        }

        Ok(Self {
            tenant_id,
            trace_id,
            orchestrator_attempt_id,
            inference_request_id,
            occurrence_ids,
            record: object,
            digest: carried,
        })
    }

    /// The tenant whose archive the references point into.
    #[must_use]
    pub fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The orchestrator operation's `UUIDv7` trace identity.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace_id
    }

    /// The orchestrator attempt's correlation identifier, joined exactly,
    /// never inferred (EC-13).
    #[must_use]
    pub fn orchestrator_attempt_id(&self) -> &OpaqueId {
        &self.orchestrator_attempt_id
    }

    /// The logical inference this record narrows to, when the orchestrator
    /// stated one.
    #[must_use]
    pub fn inference_request_id(&self) -> Option<&InferenceRequestId> {
        self.inference_request_id.as_ref()
    }

    /// The referenced canonical occurrences, ascending and duplicate-free.
    #[must_use]
    pub fn occurrence_ids(&self) -> &[OccurrenceId] {
        &self.occurrence_ids
    }

    /// The record's `correlation_digest`, lowercase hex.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The complete canonical record, `correlation_digest` included.
    #[must_use]
    pub fn record(&self) -> &Object {
        &self.record
    }

    /// The stored object's bytes: the RFC 8785 canonical serialization plus
    /// exactly one trailing LF — the family-wide rendering. The canonical
    /// bytes are also the digest preimage, so this is not a presentation
    /// choice.
    #[must_use]
    pub fn serialized(&self) -> Vec<u8> {
        let mut bytes = Value::Object(self.record.clone()).canonical_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// The stored object's key: a pure function of the record's own bytes,
    /// sharded by the digest's first two hex — reconstructible from the
    /// stored record alone. The record is asserted raw provenance, so the
    /// family lives beside the attestations under `raw/`, not under the
    /// catalog rebuild's `derived/` namespace.
    #[must_use]
    pub fn object_key(&self) -> String {
        format!(
            "tenants/{}/v1/raw/correlations/{}/{}.json",
            self.tenant_id.as_str(),
            &self.digest[..2],
            self.digest
        )
    }
}

/// Read one grammar-validated text member.
fn text<T>(
    object: &Object,
    field: &'static str,
    parse: impl Fn(&str) -> Result<T, crate::vocabulary::GrammarError>,
) -> Result<T, OrchestratorCorrelationError> {
    match object.get(field) {
        Some(Value::Text(raw)) => parse(raw).map_err(|_| invalid_grammar(field)),
        _ => Err(invalid(field, "must be a text identifier")),
    }
}

/// Read and order-check the `occurrence_ids` array: at least one reference,
/// every one grammar-valid, ascending and duplicate-free as `new` wrote it.
fn occurrence_set(object: &Object) -> Result<Vec<OccurrenceId>, OrchestratorCorrelationError> {
    let Value::Array(values) = object
        .get("occurrence_ids")
        .ok_or_else(|| invalid("occurrence_ids", "member is required"))?
    else {
        return Err(invalid("occurrence_ids", "must be an array of digests"));
    };
    if values.is_empty() {
        return Err(invalid(
            "occurrence_ids",
            "a correlation record references at least one occurrence",
        ));
    }
    let mut references = Vec::with_capacity(values.len());
    for value in values {
        let Value::Text(raw) = value else {
            return Err(invalid("occurrence_ids", "every reference must be text"));
        };
        let occurrence = OccurrenceId::parse(raw)
            .map_err(|_| invalid("occurrence_ids", "a reference is not a sha256 digest"))?;
        references.push(occurrence);
    }
    let unordered = references
        .windows(2)
        .find_map(|window| (window[0] >= window[1]).then_some(window[1]));
    if let Some(out_of_order) = unordered {
        return Err(invalid(
            "occurrence_ids",
            format!(
                "references must be ascending and duplicate-free; {} is out of order",
                out_of_order.to_hex()
            ),
        ));
    }
    Ok(references)
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> OrchestratorCorrelationError {
    OrchestratorCorrelationError::Invalid {
        field: field.into(),
        reason: reason.into(),
    }
}

fn invalid_grammar(field: &'static str) -> OrchestratorCorrelationError {
    invalid(field, "not in the identifier's canonical grammar")
}

/// The relationship structure a set of correlation records reconstructs.
///
/// The fold is deliberately reference-only: it joins what the records state
/// and nothing more. An occurrence named here is not asserted to exist, to
/// be complete, or to have passed any capture gate — the fold fabricates no
/// such semantics, and repeated references to one occurrence collapse into
/// one entry, because reconstructing a relationship never multiplies it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OrchestratorCorrelationGraph {
    operations: BTreeMap<TraceId, OperationProvenance>,
    occurrence_references: BTreeMap<OccurrenceId, BTreeSet<OccurrenceReference>>,
}

/// One orchestrator operation's reconstructed provenance: its attempts and
/// what each referenced.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationProvenance {
    attempts: BTreeMap<OpaqueId, AttemptProvenance>,
}

/// One orchestrator attempt's reconstructed references, split by the logical
/// inference each record narrowed to. A record with no `inference_request_id`
/// references at the attempt's own scope; that is provenance about the
/// attempt as a whole, not an inference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttemptProvenance {
    inference_occurrences: BTreeMap<InferenceRequestId, BTreeSet<OccurrenceId>>,
    attempt_occurrences: BTreeSet<OccurrenceId>,
}

/// One direction of the fold's reverse index: the record-set provenance that
/// referenced one occurrence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct OccurrenceReference {
    trace: TraceId,
    orchestrator_attempt: OpaqueId,
    inference_request: Option<InferenceRequestId>,
}

impl OrchestratorCorrelationGraph {
    /// Fold correlation records into the relationship structure.
    ///
    /// Total: every record contributes exactly the references it states.
    /// Two records that state the same relationship contribute one entry;
    /// the fold is a set union, so re-reporting never multiplies.
    #[must_use]
    pub fn build<'a>(records: impl IntoIterator<Item = &'a OrchestratorCorrelation>) -> Self {
        let mut graph = Self::default();
        for record in records {
            let operation = graph.operations.entry(record.trace_id.clone()).or_default();
            let attempt = operation
                .attempts
                .entry(record.orchestrator_attempt_id.clone())
                .or_default();
            let reference = OccurrenceReference {
                trace: record.trace_id.clone(),
                orchestrator_attempt: record.orchestrator_attempt_id.clone(),
                inference_request: record.inference_request_id.clone(),
            };
            for occurrence in &record.occurrence_ids {
                match &record.inference_request_id {
                    Some(inference_request_id) => {
                        attempt
                            .inference_occurrences
                            .entry(inference_request_id.clone())
                            .or_default()
                            .insert(*occurrence);
                    }
                    None => {
                        attempt.attempt_occurrences.insert(*occurrence);
                    }
                }
                graph
                    .occurrence_references
                    .entry(*occurrence)
                    .or_default()
                    .insert(reference.clone());
            }
        }
        graph
    }

    /// The reconstructed operations, in trace order.
    pub fn operations(&self) -> impl Iterator<Item = (&TraceId, &OperationProvenance)> {
        self.operations.iter()
    }

    /// One operation's reconstructed provenance.
    #[must_use]
    pub fn operation(&self, trace_id: &TraceId) -> Option<&OperationProvenance> {
        self.operations.get(trace_id)
    }

    /// The record-set provenance that referenced one occurrence, in
    /// reference order — the reverse join an occurrence-side reader needs.
    pub fn referencing(
        &self,
        occurrence_id: &OccurrenceId,
    ) -> impl Iterator<Item = &OccurrenceReference> {
        self.occurrence_references
            .get(occurrence_id)
            .into_iter()
            .flatten()
    }
}

impl OperationProvenance {
    /// The operation's reconstructed attempts, in attempt-identifier order.
    pub fn attempts(&self) -> impl Iterator<Item = (&OpaqueId, &AttemptProvenance)> {
        self.attempts.iter()
    }

    /// One attempt's reconstructed references.
    #[must_use]
    pub fn attempt(&self, orchestrator_attempt_id: &OpaqueId) -> Option<&AttemptProvenance> {
        self.attempts.get(orchestrator_attempt_id)
    }
}

impl AttemptProvenance {
    /// The occurrences referenced per logical inference, in inference order.
    pub fn inference_occurrences(
        &self,
    ) -> impl Iterator<Item = (&InferenceRequestId, &BTreeSet<OccurrenceId>)> {
        self.inference_occurrences.iter()
    }

    /// The occurrences referenced at the attempt's own scope — records that
    /// named no inference — in digest order.
    pub fn attempt_occurrences(&self) -> impl Iterator<Item = &OccurrenceId> {
        self.attempt_occurrences.iter()
    }

    /// Every distinct occurrence this attempt's records referenced,
    /// deduplicated across both scopes, in digest order.
    pub fn occurrences(&self) -> impl Iterator<Item = &OccurrenceId> {
        self.inference_occurrences
            .values()
            .flatten()
            .chain(self.attempt_occurrences.iter())
            .collect::<BTreeSet<_>>()
            .into_iter()
    }
}

impl OccurrenceReference {
    /// The referencing record's operation trace.
    #[must_use]
    pub fn trace_id(&self) -> &TraceId {
        &self.trace
    }

    /// The referencing record's orchestrator attempt.
    #[must_use]
    pub fn orchestrator_attempt_id(&self) -> &OpaqueId {
        &self.orchestrator_attempt
    }

    /// The referencing record's logical inference, when it stated one.
    #[must_use]
    pub fn inference_request_id(&self) -> Option<&InferenceRequestId> {
        self.inference_request.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const TRACE: &str = "1a07a100-7000-7000-8000-000000000001";
    const TRACE_OTHER: &str = "1a07a100-7000-7000-8000-0000000000ff";
    const INFERENCE: &str = "1a07a200-7000-7000-8000-000000000010";
    const INFERENCE_OTHER: &str = "1a07a200-7000-7000-8000-000000000020";
    const OCC_A: &str = "aa00000000000000000000000000000000000000000000000000000000000001";
    const OCC_B: &str = "aa00000000000000000000000000000000000000000000000000000000000002";
    const OCC_C: &str = "aa00000000000000000000000000000000000000000000000000000000000003";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("grammatical tenant")
    }

    fn trace(text: &str) -> TraceId {
        TraceId::parse(text).expect("grammatical trace")
    }

    fn attempt(text: &str) -> OpaqueId {
        OpaqueId::parse(text).expect("grammatical attempt id")
    }

    fn inference(text: &str) -> InferenceRequestId {
        InferenceRequestId::parse(text).expect("grammatical inference id")
    }

    fn occurrence(text: &str) -> OccurrenceId {
        OccurrenceId::parse(text).expect("grammatical occurrence digest")
    }

    fn record_a() -> OrchestratorCorrelation {
        OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            Some(inference(INFERENCE)),
            vec![occurrence(OCC_B), occurrence(OCC_A)],
        )
        .expect("grammatical record")
    }

    #[test]
    fn references_canonicalize_to_ascending_and_digest_excludes_itself() {
        let record = record_a();
        assert_eq!(
            record.occurrence_ids(),
            &[occurrence(OCC_A), occurrence(OCC_B)],
            "construction sorts the reference set"
        );

        let mut without_digest = record.record().clone();
        let Some(Value::Text(carried)) = without_digest.remove("correlation_digest") else {
            panic!("the digest member must be present");
        };
        assert_eq!(carried, record.digest());
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(without_digest).canonical_bytes());
        assert_eq!(
            sha256::encode_hex(&frame.finish()),
            record.digest(),
            "the digest is over the canonical bytes minus the digest member"
        );
    }

    #[test]
    fn input_order_and_set_equality_decide_identity() {
        let forward = record_a();
        let reversed = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            Some(inference(INFERENCE)),
            vec![occurrence(OCC_A), occurrence(OCC_B)],
        )
        .expect("grammatical record");
        assert_eq!(forward, reversed, "one relationship is one identity");
        assert_eq!(forward.serialized(), reversed.serialized());
        assert_eq!(forward.object_key(), reversed.object_key());
        assert!(forward.object_key().contains("/raw/correlations/"));
    }

    #[test]
    fn empty_and_duplicate_reference_sets_are_refused() {
        let empty = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            None,
            Vec::new(),
        );
        assert_eq!(
            empty,
            Err(invalid(
                "occurrence_ids",
                "a correlation record references at least one occurrence"
            ))
        );

        let duplicated = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            None,
            vec![occurrence(OCC_A), occurrence(OCC_A)],
        );
        assert!(
            matches!(
                duplicated,
                Err(OrchestratorCorrelationError::Invalid { .. })
            ),
            "a stated-twice reference is a caller bug, not a set"
        );
    }

    #[test]
    fn parse_roundtrips_and_reverifies() {
        let record = record_a();
        let parsed = OrchestratorCorrelation::parse(&record.serialized())
            .expect("the family's own rendering re-parses");
        assert_eq!(parsed, record);

        // One flipped nibble in one reference is a different relationship:
        // the self-verifying digest must refuse it before the read returns.
        // The forged digest stays inside the ascending order (only OCC_A's
        // final nibble changes, downward), so the refusal is the digest's.
        let mut tampered = record.record().clone();
        let forged = format!("{}0", &OCC_A[..63]);
        if let Some(Value::Array(references)) = tampered.get("occurrence_ids") {
            let mut references = references.clone();
            references[0] = Value::Text(forged);
            tampered.set("occurrence_ids", Value::Array(references));
        }
        let mismatch = OrchestratorCorrelation::from_value(Value::Object(tampered));
        assert!(
            matches!(
                mismatch,
                Err(OrchestratorCorrelationError::DigestMismatch { .. })
            ),
            "an altered reference set cannot read back as verified"
        );
    }

    #[test]
    fn the_member_set_is_closed_and_optional_members_omit_never_null() {
        let with_inference = record_a();
        assert!(with_inference.record().contains("inference_request_id"));

        let without_inference = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            None,
            vec![occurrence(OCC_A)],
        )
        .expect("grammatical record");
        assert!(
            !without_inference.record().contains("inference_request_id"),
            "absent, never null"
        );
        let parsed = OrchestratorCorrelation::parse(&without_inference.serialized())
            .expect("an attempt-scoped record re-parses");
        assert!(parsed.inference_request_id().is_none());

        let mut claiming = without_inference.record().clone();
        claiming.set("semantic_complete", Value::Bool(true));
        let refused = OrchestratorCorrelation::from_value(Value::Object(claiming));
        assert_eq!(
            refused,
            Err(invalid(
                "semantic_complete",
                "unknown member; the correlation record's member set is closed",
            )),
            "no completeness assertion has a spelling this family accepts"
        );
    }

    #[test]
    fn version_and_grammar_failures_name_the_member() {
        let mut wrong_version = record_a().record().clone();
        wrong_version.set("orchestrator_correlation_version", Value::Int(2));
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Object(wrong_version)),
            Err(invalid(
                "orchestrator_correlation_version",
                "must be the integer 1",
            ))
        );

        let mut bad_trace = record_a().record().clone();
        bad_trace.set("trace_id", Value::Text("not-a-uuid".to_owned()));
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Object(bad_trace)),
            Err(invalid_grammar("trace_id")),
        );

        let mut unordered = record_a().record().clone();
        if let Some(Value::Array(references)) = unordered.get("occurrence_ids") {
            let mut swapped = references.clone();
            swapped.swap(0, 1);
            unordered.set("occurrence_ids", Value::Array(swapped));
        }
        // The reordered array also fails the digest, but the order check is
        // independent of the digest: it runs first and names the member.
        assert!(
            matches!(
                OrchestratorCorrelation::from_value(Value::Object(unordered)),
                Err(OrchestratorCorrelationError::Invalid { field, .. })
                    if field == "occurrence_ids",
            ),
            "the reference order is checked on its own"
        );
    }

    #[test]
    fn the_fold_reconstructs_operations_attempts_and_inferences() {
        let first = record_a();
        let second = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            Some(inference(INFERENCE_OTHER)),
            vec![occurrence(OCC_C)],
        )
        .expect("grammatical record");
        let attempt_scoped = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-2"),
            None,
            vec![occurrence(OCC_A)],
        )
        .expect("grammatical record");
        let other_operation = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE_OTHER),
            attempt("orchestrator-attempt-1"),
            None,
            vec![occurrence(OCC_B)],
        )
        .expect("grammatical record");

        let graph = OrchestratorCorrelationGraph::build([
            &first,
            &second,
            &attempt_scoped,
            &other_operation,
        ]);

        let operation = graph
            .operation(&trace(TRACE))
            .expect("the first operation reconstructed");
        assert_eq!(graph.operations().count(), 2, "traces never merge");

        let attempt_one = operation
            .attempt(&attempt("orchestrator-attempt-1"))
            .expect("the first attempt reconstructed");
        let mut inference_views: Vec<_> = attempt_one
            .inference_occurrences()
            .map(|(inference, occurrences)| (inference.as_str(), occurrences.len()))
            .collect();
        inference_views.sort_unstable();
        assert_eq!(
            inference_views,
            vec![(INFERENCE, 2_usize), (INFERENCE_OTHER, 1_usize)],
            "each logical inference keeps its own references"
        );

        let attempt_two = operation
            .attempt(&attempt("orchestrator-attempt-2"))
            .expect("the attempt-scoped record reconstructed");
        assert_eq!(
            attempt_two.attempt_occurrences().collect::<Vec<_>>(),
            vec![&occurrence(OCC_A)],
        );
        assert_eq!(
            attempt_two.occurrences().collect::<Vec<_>>(),
            vec![&occurrence(OCC_A)],
        );

        // OCC_A: referenced by two records under one trace — the fold keeps
        // one set entry per distinct relationship, and the reverse join
        // answers "what references this occurrence" without duplication.
        let references: Vec<_> = graph.referencing(&occurrence(OCC_A)).collect();
        assert_eq!(references.len(), 2, "two distinct relationships");
        assert!(
            references
                .iter()
                .all(|reference| reference.trace_id() == &trace(TRACE))
        );

        // OCC_B: named by both operations; the reverse join shows both,
        // and neither operation's fold saw the other's records.
        let shared: Vec<_> = graph.referencing(&occurrence(OCC_B)).collect();
        assert_eq!(shared.len(), 2, "references from both traces survive");
        let other = graph
            .operation(&trace(TRACE_OTHER))
            .expect("the second operation reconstructed");
        assert_eq!(other.attempts().count(), 1);
        assert!(
            other
                .attempt(&attempt("orchestrator-attempt-1"))
                .expect("the shared attempt id is per-operation")
                .occurrences()
                .eq(std::iter::once(&occurrence(OCC_B))),
        );
    }

    #[test]
    fn re_reports_collapse_in_the_fold() {
        let first = record_a();
        let re_report = OrchestratorCorrelation::new(
            tenant(),
            trace(TRACE),
            attempt("orchestrator-attempt-1"),
            Some(inference(INFERENCE)),
            vec![occurrence(OCC_A), occurrence(OCC_B)],
        )
        .expect("grammatical record — same relationship, restated");
        assert_eq!(first, re_report, "one relationship is one record identity");

        let graph = OrchestratorCorrelationGraph::build([&first, &re_report]);
        assert_eq!(
            graph.referencing(&occurrence(OCC_A)).count(),
            1,
            "re-reporting a relationship never multiplies it"
        );
    }

    #[test]
    fn malformed_bytes_and_shapes_are_refused() {
        assert!(
            matches!(
                OrchestratorCorrelation::parse(b"{"),
                Err(OrchestratorCorrelationError::Malformed {
                    reason: "bounded parse of the correlation record bytes failed",
                    source: Some(_),
                })
            ),
            "truncated bytes refuse with the parser's own error attached"
        );
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Null),
            Err(OrchestratorCorrelationError::Malformed {
                reason: "orchestrator correlation record is not a JSON object",
                source: None,
            }),
        );

        let mut array_references = record_a().record().clone();
        array_references.set("occurrence_ids", Value::Text(OCC_A.to_owned()));
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Object(array_references)),
            Err(invalid("occurrence_ids", "must be an array of digests")),
        );

        let mut bad_reference = record_a().record().clone();
        bad_reference.set(
            "occurrence_ids",
            Value::Array(vec![Value::Text("zz".to_owned())]),
        );
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Object(bad_reference)),
            Err(invalid(
                "occurrence_ids",
                "a reference is not a sha256 digest",
            )),
        );

        let mut empty_array = record_a().record().clone();
        empty_array.set("occurrence_ids", Value::Array(Vec::new()));
        assert_eq!(
            OrchestratorCorrelation::from_value(Value::Object(empty_array)),
            Err(invalid(
                "occurrence_ids",
                "a correlation record references at least one occurrence",
            )),
        );
    }
}
