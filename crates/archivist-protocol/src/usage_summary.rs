// SPDX-License-Identifier: Apache-2.0

//! The usage-summary derivation (plan Phase 10, token accounting;
//! [docs/notes/usage-summary-schema.md]): the deterministic mapping from an
//! adapter projection's normalized reading of one raw occurrence's captured
//! inference records to the derived record
//! [`schemas/v1/usage-summary.json`] governs.
//!
//! Ownership sits here by the layering rules
//! ([docs/notes/crate-ownership.md], boundary rule 8): the record's types
//! and digest construction are layer-0 wire material, so the derivation
//! core — member assembly, the two-state `harness_usage` contract, the
//! digest, canonical serialization, and the object key — is a pure function
//! of this crate. Reading usage regions out of harness-specific raw bytes
//! is the adapter projections' job: they hand this module [`MessageUsage`]
//! inputs. The deterministic `archivist catalog rebuild` composes storage
//! read → projection → derivation, and holds no derivation logic of its own
//! (boundary rule 7).
//!
//! # The derivation contract
//!
//! The input is the projection's per-assistant-message reading of the
//! occurrence's captured inference records: which model identity and
//! service tier the source named on the message, and which of the four
//! bounded region states its usage region is in. Every output member is a
//! function of these inputs, the occurrence's provenance, and the pinned
//! pipeline identity — no wall-clock, producer, or run input exists (the
//! schema's derivation-stability rule), so identical inputs re-derive
//! byte-identical records and digests, which is what makes the Phase 10
//! rebuild gate possible. The five committed corpus vectors
//! (`schemas/v1/examples/usage-summaries`) are re-derived byte-for-byte
//! from pinned inputs by `tests/usage_summary_derivation.rs`.
//!
//! ## The denominator (`harness_usage.state`)
//!
//! 1. **Any [`UsageRegion::Unsupported`] region → `unsupported`.** A
//!    parseable shape the pinned projection cannot vouch refuses the whole
//!    denominator: a sum that silently excluded it would read as complete
//!    to every downstream reader. The identity members are omitted — a
//!    projection that cannot produce the denominator also cannot vouch
//!    identity.
//! 2. **Else any [`UsageRegion::Malformed`] region → `malformed`.** Never
//!    a partial sum over whatever happened to parse.
//! 3. **Else any [`UsageRegion::Measured`] region → `measured`**, summed
//!    over exactly the measured messages; `assistant_message_count` is
//!    that count, the disclosure of partial coverage when other messages
//!    carry no usage region at all — absence is never padded with invented
//!    zeros. Two fault classes fold into `unsupported` here: summed
//!    messages that disagree on model identity or service tier (a sum
//!    without a single model is exactly the number the query-time cost
//!    path cannot use), and a sum that overflows the record's
//!    representable count domain.
//! 4. **Else → `absent`.** No message carried any usage region — including
//!    an occurrence with no assistant messages at all: a session without
//!    evidence keeps its unknown denominator, never zeros.
//!
//! ## The identity members (`model_id`, `service_tier`)
//!
//! A reported identity is carried only when it survives its wire grammar
//! (`model-id`, `short-token`): a value the record cannot carry is treated
//! as unreported, because omission is the honest state and an invented
//! replacement is worse. On the `measured` branch the distinct grammar-
//! valid identities of the summed messages decide: exactly one → named,
//! none → omitted, more than one → the `unsupported` fold above. On the
//! `absent` and `malformed` branches the distinct identities of all
//! messages decide the same way — absent usage does not erase the identity
//! the source did report. The `unsupported` branch names neither.
//!
//! [`schemas/v1/usage-summary.json`]: ../../../schemas/v1/usage-summary.json
//! [docs/notes/usage-summary-schema.md]: ../../../docs/notes/usage-summary-schema.md
//! [docs/notes/crate-ownership.md]: ../../../docs/notes/crate-ownership.md

use crate::derivation::FrameBuilder;
use crate::json::{Object, Value};
use crate::sha256;
use crate::vocabulary::{AdapterId, OccurrenceId, TenantId, VersionToken};

/// The record-shape version this module derives (`usage_summary_version`;
/// plan Section 7.1: the record-shape axis, independent of the pipeline
/// axis below).
pub const USAGE_SUMMARY_VERSION: i64 = 1;

/// The one derived pipeline v1 ships (`pipeline_id`): the deterministic
/// `usage` projection of the catalog rebuild.
pub const PIPELINE_ID: &str = "usage";

/// The immutable pipeline version of the v1 `usage` projection
/// (`pipeline_version`): the mapping rules are frozen inside it; a changed
/// mapping is a new version, never a silent rewrite.
pub const PIPELINE_VERSION: &str = "1";

/// The digest construction's domain label
/// (`x-archivist.derivations[0].label` in the family schema): SHA-256 over
/// the canonical record bytes with the digest member removed, framed like
/// every ingest identifier.
const DIGEST_LABEL: &str = "usage-summary-v1";

/// The token counts one assistant message's usage region reported, in the
/// source's own accounting. Cache-read and cache-creation tokens are
/// stated separately and never folded into `input_tokens`; the projection
/// normalizes each axis to a non-negative count or refuses the region, so
/// no field here can encode "unreported".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceUsageCounts {
    /// Input tokens, excluding the cache axes stated below.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Cache-read tokens (zero is a real observation).
    pub cache_read_tokens: u64,
    /// Cache-creation tokens written to the 5-minute ephemeral class.
    pub cache_creation_5m: u64,
    /// Cache-creation tokens written to the 1-hour ephemeral class.
    pub cache_creation_1h: u64,
    /// Reasoning tokens (an axis the source lacks is a measured zero).
    pub reasoning_tokens: u64,
}

/// What the projection read in one assistant message's usage region. The
/// four states are the projection's classification of the raw bytes — the
/// bounded refusal states exist so an incomplete source can never read as
/// free — and they are the derivation's whole view of parseability: this
/// crate never parses harness-specific usage dialects itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageRegion {
    /// A complete, well-formed usage object under the source's own
    /// declared shape, with every axis normalized to a count.
    Measured(SourceUsageCounts),
    /// The message carried no usage region at all.
    Absent,
    /// A usage region is present but not parseable under the source's own
    /// declared shape — wrong types, negative or non-integer counts,
    /// incoherent nesting, a missing required axis.
    Malformed,
    /// The region parses but the pinned projection does not support its
    /// shape — an unknown usage dialect, or cache creation with no
    /// ephemeral-class split (the projection never distributes an
    /// unclassifiable total across classes).
    Unsupported,
}

/// One assistant message's captured inference record as the projection
/// normalized it: the identity the source named on the message, and the
/// state of its usage region.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageUsage {
    /// The model identity the message reported, verbatim, or `None` when
    /// the source named no model. A value that fails the record's
    /// `model-id` grammar is carried nowhere (see the module identity
    /// rules) but is still reported here verbatim — the projection's view
    /// is never pre-censored.
    pub model_id: Option<String>,
    /// The service tier the message reported, verbatim, or `None`.
    pub service_tier: Option<String>,
    /// The projection's classification of the message's usage region.
    pub region: UsageRegion,
}

/// The cited raw occurrence's provenance, exactly as its occurrence
/// manifest pins it (STO-012: derived artifacts retain raw occurrence
/// references). Every field is a validated wire type, so a derived record
/// can only ever carry grammar-correct provenance.
#[derive(Clone, Debug)]
pub struct OccurrenceProvenance {
    /// The tenant whose archive the occurrence lives in.
    pub tenant_id: TenantId,
    /// The adapter whose projection read the usage region.
    pub adapter_id: AdapterId,
    /// The immutable version of that projection's usage reader.
    pub adapter_projection_version: VersionToken,
    /// The occurrence's `occurrence-v1` identity digest.
    pub occurrence_id: OccurrenceId,
}

/// Why no honest count exists, the closed v1 refusal set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    /// No usage region exists for the occurrence's assistant messages.
    Absent,
    /// A region is present but not parseable under the source's own
    /// declared shape.
    Malformed,
    /// Regions parse but the pinned projection does not support their
    /// shape, or the summed messages span more than one model identity or
    /// service tier.
    Unsupported,
}

impl UnknownReason {
    /// The wire token the record carries.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Malformed => "malformed",
            Self::Unsupported => "unsupported",
        }
    }
}

/// The derived denominator's state, the two-state `harness_usage`
/// contract as a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HarnessUsageState {
    /// Counts were summed from at least one assistant message.
    Measured,
    /// No honest count exists; the refusal reason is carried beside the
    /// state.
    Unknown(UnknownReason),
}

/// One derived usage-summary record: the complete canonical object, its
/// digest, and the denominator state as a value. Build one with
/// [`UsageSummary::derive`]; identical inputs derive identical values,
/// byte for byte.
#[derive(Clone, Debug)]
pub struct UsageSummary {
    record: Object,
    digest: String,
    state: HarnessUsageState,
}

impl UsageSummary {
    /// Derive the usage summary of one raw occurrence from the adapter
    /// projection's normalized reading of its captured inference records.
    ///
    /// Total: every input yields a record. Where no honest count exists
    /// the record carries the bounded `unknown` state instead of numbers,
    /// never zeros — an incomplete source can never read as free.
    #[must_use]
    pub fn derive(provenance: &OccurrenceProvenance, messages: &[MessageUsage]) -> Self {
        let mut any_malformed = false;
        let mut any_unsupported = false;
        let mut measured: Vec<&MessageUsage> = Vec::new();
        for message in messages {
            match message.region {
                UsageRegion::Measured(_) => measured.push(message),
                UsageRegion::Absent => {}
                UsageRegion::Malformed => any_malformed = true,
                UsageRegion::Unsupported => any_unsupported = true,
            }
        }

        let (usage, state, model, tier) = if any_unsupported {
            // An unvouchable shape refuses the whole denominator and names
            // no identity.
            let reason = UnknownReason::Unsupported;
            (unknown_usage_object(reason), state_of(reason), None, None)
        } else if any_malformed {
            // Never a partial sum over whatever happened to parse; the
            // identity the source did report stays named.
            let reason = UnknownReason::Malformed;
            let identities = observed_identities(messages);
            (
                unknown_usage_object(reason),
                state_of(reason),
                single_of(&identities.0),
                single_of(&identities.1),
            )
        } else if !measured.is_empty() {
            if let Some((usage, model, tier)) = measured_denominator(&measured) {
                (usage, HarnessUsageState::Measured, model, tier)
            } else {
                // Identity disagreement or an unrepresentable sum folds
                // to `unsupported`, identities omitted.
                let reason = UnknownReason::Unsupported;
                (unknown_usage_object(reason), state_of(reason), None, None)
            }
        } else {
            // Nothing reported any usage region (possibly no assistant
            // messages at all): the unknown denominator, never zeros.
            let reason = UnknownReason::Absent;
            let identities = observed_identities(messages);
            (
                unknown_usage_object(reason),
                state_of(reason),
                single_of(&identities.0),
                single_of(&identities.1),
            )
        };

        Self::assemble(provenance, model.as_deref(), tier.as_deref(), usage, state)
    }

    /// The complete derived record, `usage_summary_digest` included.
    #[must_use]
    pub fn record(&self) -> &Object {
        &self.record
    }

    /// The record's `usage_summary_digest`, lowercase hex.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The derived denominator's state as a value.
    #[must_use]
    pub fn harness_usage_state(&self) -> HarnessUsageState {
        self.state
    }

    /// The derived object key: a pure function of the record's own bytes
    /// (plan Section 7.5), sharded by the digest's first two hex —
    /// reconstructible from the stored record alone.
    #[must_use]
    pub fn object_key(&self) -> String {
        let tenant = match self.record.get("tenant_id") {
            Some(Value::Text(tenant)) => tenant.as_str(),
            _ => "",
        };
        format!(
            "tenants/{tenant}/v1/derived/{PIPELINE_ID}/{PIPELINE_VERSION}/\
             usage-summaries/{}/{}.json",
            &self.digest[..2],
            self.digest
        )
    }

    /// The stored object's bytes: the RFC 8785 canonical serialization
    /// plus exactly one trailing LF — the family-wide rendering. The
    /// canonical bytes are also the digest preimage, so this is not a
    /// presentation choice: two byte-serializations of one record would be
    /// two identities.
    #[must_use]
    pub fn serialized(&self) -> Vec<u8> {
        let mut bytes = Value::Object(self.record.clone()).canonical_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// Assemble, digest, and store the record.
    fn assemble(
        provenance: &OccurrenceProvenance,
        model: Option<&str>,
        tier: Option<&str>,
        usage: Object,
        state: HarnessUsageState,
    ) -> Self {
        let mut record = Object::new();
        record.set(
            "adapter_id",
            Value::Text(provenance.adapter_id.as_str().to_owned()),
        );
        record.set(
            "adapter_projection_version",
            Value::Text(provenance.adapter_projection_version.as_str().to_owned()),
        );
        record.set(
            "occurrence_id",
            Value::Text(provenance.occurrence_id.to_hex()),
        );
        record.set("pipeline_id", Value::Text(PIPELINE_ID.to_owned()));
        record.set("pipeline_version", Value::Text(PIPELINE_VERSION.to_owned()));
        record.set(
            "tenant_id",
            Value::Text(provenance.tenant_id.as_str().to_owned()),
        );
        record.set("usage_summary_version", Value::Int(USAGE_SUMMARY_VERSION));
        if let Some(model) = model {
            record.set("model_id", Value::Text(model.to_owned()));
        }
        if let Some(tier) = tier {
            record.set("service_tier", Value::Text(tier.to_owned()));
        }
        record.set("harness_usage", Value::Object(usage));

        // Construction `usage-summary-v1`: the labeled frame over the
        // record's canonical bytes with the digest member removed — the
        // exclusion shape that makes the record self-verifying (VAL-005).
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(record.clone()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        record.set("usage_summary_digest", Value::Text(digest.clone()));

        Self {
            record,
            digest,
            state,
        }
    }
}

/// The `measured` denominator: the summed counts object plus the summed
/// messages' single identities, or `None` when the branch folds to
/// `unsupported` (identity disagreement, or a sum outside the record's
/// representable count domain).
fn measured_denominator(
    measured: &[&MessageUsage],
) -> Option<(Object, Option<String>, Option<String>)> {
    let models = distinct_reported(
        measured.iter().map(|m| m.model_id.as_deref()),
        model_id_valid,
    );
    let tiers = distinct_reported(
        measured.iter().map(|m| m.service_tier.as_deref()),
        short_token_valid,
    );
    if models.len() > 1 || tiers.len() > 1 {
        return None;
    }

    let mut sum = SourceUsageCounts {
        input_tokens: 0,
        output_tokens: 0,
        cache_read_tokens: 0,
        cache_creation_5m: 0,
        cache_creation_1h: 0,
        reasoning_tokens: 0,
    };
    for message in measured {
        let UsageRegion::Measured(counts) = message.region else {
            continue; // partitioned by the caller
        };
        sum.input_tokens = sum.input_tokens.checked_add(counts.input_tokens)?;
        sum.output_tokens = sum.output_tokens.checked_add(counts.output_tokens)?;
        sum.cache_read_tokens = sum
            .cache_read_tokens
            .checked_add(counts.cache_read_tokens)?;
        sum.cache_creation_5m = sum
            .cache_creation_5m
            .checked_add(counts.cache_creation_5m)?;
        sum.cache_creation_1h = sum
            .cache_creation_1h
            .checked_add(counts.cache_creation_1h)?;
        sum.reasoning_tokens = sum.reasoning_tokens.checked_add(counts.reasoning_tokens)?;
    }
    // The wire domain for every count is `u63` (`common.json`); a total
    // outside it cannot be stated honestly, so the denominator folds to
    // `unsupported` rather than wrapping into a lie.
    for total in [
        sum.input_tokens,
        sum.output_tokens,
        sum.cache_read_tokens,
        sum.cache_creation_5m,
        sum.cache_creation_1h,
        sum.reasoning_tokens,
    ] {
        if i64::try_from(total).is_err() {
            return None;
        }
    }
    let message_count = measured.len().try_into().ok()?;

    let mut usage = Object::new();
    usage.set("state", Value::Text("measured".to_owned()));
    usage.set(
        "input_tokens",
        Value::Int(sum.input_tokens.try_into().ok()?),
    );
    usage.set(
        "output_tokens",
        Value::Int(sum.output_tokens.try_into().ok()?),
    );
    usage.set(
        "cache_read_tokens",
        Value::Int(sum.cache_read_tokens.try_into().ok()?),
    );
    let mut cache_creation = Object::new();
    cache_creation.set(
        "ephemeral_5m",
        Value::Int(sum.cache_creation_5m.try_into().ok()?),
    );
    cache_creation.set(
        "ephemeral_1h",
        Value::Int(sum.cache_creation_1h.try_into().ok()?),
    );
    usage.set("cache_creation", Value::Object(cache_creation));
    usage.set(
        "reasoning_tokens",
        Value::Int(sum.reasoning_tokens.try_into().ok()?),
    );
    usage.set("assistant_message_count", Value::Int(message_count));

    Some((
        usage,
        models.first().map(|model| (*model).to_owned()),
        tiers.first().map(|tier| (*tier).to_owned()),
    ))
}

/// The bounded-refusal denominator object: exactly `{state, reason}` and
/// nothing else — no count may ever sit beside an `unknown`.
fn unknown_usage_object(reason: UnknownReason) -> Object {
    let mut usage = Object::new();
    usage.set("state", Value::Text("unknown".to_owned()));
    usage.set("reason", Value::Text(reason.token().to_owned()));
    usage
}

/// The state wrapped for the record value.
fn state_of(reason: UnknownReason) -> HarnessUsageState {
    HarnessUsageState::Unknown(reason)
}

/// The distinct grammar-valid identities all messages reported, for the
/// unknown branches' identity decision.
fn observed_identities(messages: &[MessageUsage]) -> (Vec<String>, Vec<String>) {
    (
        distinct_owned(
            messages.iter().filter_map(|m| m.model_id.as_deref()),
            model_id_valid,
        ),
        distinct_owned(
            messages.iter().filter_map(|m| m.service_tier.as_deref()),
            short_token_valid,
        ),
    )
}

/// The one distinct value when exactly one was reported; `None` when none
/// or several were (several cannot be vouched as a single identity).
fn single_of(distinct: &[String]) -> Option<String> {
    if distinct.len() == 1 {
        Some(distinct[0].clone())
    } else {
        None
    }
}

/// Distinct reported values that survive `valid`, in first-seen order.
fn distinct_owned<'a>(
    values: impl Iterator<Item = &'a str>,
    valid: fn(&str) -> bool,
) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for value in values {
        if valid(value) && !seen.iter().any(|seen| seen == value) {
            seen.push(value.to_owned());
        }
    }
    seen
}

/// Distinct reported values that survive `valid` (borrowing variant for
/// the measured branch, whose identity is decided before the record is
/// assembled).
fn distinct_reported<'a>(
    values: impl Iterator<Item = Option<&'a str>>,
    valid: fn(&str) -> bool,
) -> Vec<&'a str> {
    let mut seen: Vec<&str> = Vec::new();
    for value in values.flatten() {
        if valid(value) && !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

/// The family schema's `model-id` grammar: a bounded ASCII token that
/// cannot carry prose — alphanumeric first character, then the namespace
/// separators, at most 128 bytes, no whitespace, no control characters.
fn model_id_valid(text: &str) -> bool {
    let mut chars = text.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric()) {
        return false;
    }
    text.len() <= 128
        && chars
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '+' | '-'))
}

/// The shared `short-token` grammar (`common.json`), which `service_tier`
/// carries: lowercase alphanumeric first character, then `a-z 0-9 . _ -`,
/// at most 64 bytes.
fn short_token_valid(text: &str) -> bool {
    let mut chars = text.chars();
    if !matches!(chars.next(), Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit())
    {
        return false;
    }
    text.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> OccurrenceProvenance {
        OccurrenceProvenance {
            tenant_id: TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap(),
            adapter_id: AdapterId::parse("claude-jsonl").unwrap(),
            adapter_projection_version: VersionToken::parse("1").unwrap(),
            occurrence_id: OccurrenceId::parse(
                "e107d1532d571127e2bf8bb1f4b02ec8057b074e527ef8d550975011e1399cde",
            )
            .unwrap(),
        }
    }

    fn message(model: &str, tier: &str, region: UsageRegion) -> MessageUsage {
        MessageUsage {
            model_id: Some(model.to_owned()),
            service_tier: Some(tier.to_owned()),
            region,
        }
    }

    fn counts(input: u64) -> SourceUsageCounts {
        SourceUsageCounts {
            input_tokens: input,
            output_tokens: 1,
            cache_read_tokens: 0,
            cache_creation_5m: 0,
            cache_creation_1h: 0,
            reasoning_tokens: 0,
        }
    }

    #[test]
    fn unknown_states_never_carry_counts() {
        for region in [
            UsageRegion::Absent,
            UsageRegion::Malformed,
            UsageRegion::Unsupported,
        ] {
            let summary = UsageSummary::derive(
                &provenance(),
                &[message("claude-opus-4-6", "standard", region)],
            );
            let Some(Value::Object(usage)) = summary.record().get("harness_usage") else {
                panic!("harness_usage must be an object");
            };
            assert_eq!(usage.len(), 2, "{region:?}: state and reason only");
            assert!(matches!(
                summary.harness_usage_state(),
                HarnessUsageState::Unknown(_)
            ));
        }
    }

    #[test]
    fn unsupported_outranks_malformed_outranks_absent() {
        let absent = message("m", "standard", UsageRegion::Absent);
        let malformed = message("m", "standard", UsageRegion::Malformed);
        let unsupported = message("m", "standard", UsageRegion::Unsupported);
        let measured = message("m", "standard", UsageRegion::Measured(counts(1)));

        let state = |messages: &[MessageUsage]| UsageSummary::derive(&provenance(), messages);
        assert_eq!(
            state(&[absent.clone(), malformed.clone()]).harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Malformed)
        );
        assert_eq!(
            state(&[absent.clone(), malformed, unsupported]).harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Unsupported)
        );
        assert_eq!(
            state(&[absent, measured]).harness_usage_state(),
            HarnessUsageState::Measured
        );
    }

    #[test]
    fn partial_coverage_is_disclosed_not_padded() {
        let messages = [
            message("m", "standard", UsageRegion::Measured(counts(10))),
            message("m", "standard", UsageRegion::Absent),
            message("m", "standard", UsageRegion::Absent),
        ];
        let summary = UsageSummary::derive(&provenance(), &messages);
        let Some(Value::Object(usage)) = summary.record().get("harness_usage") else {
            panic!("harness_usage must be an object");
        };
        assert_eq!(usage.get("assistant_message_count"), Some(&Value::Int(1)));
        assert_eq!(usage.get("input_tokens"), Some(&Value::Int(10)));
    }

    #[test]
    fn identity_disagreement_folds_to_unsupported() {
        let messages = [
            message("model-a", "standard", UsageRegion::Measured(counts(1))),
            message("model-b", "standard", UsageRegion::Measured(counts(2))),
        ];
        let summary = UsageSummary::derive(&provenance(), &messages);
        assert_eq!(
            summary.harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Unsupported)
        );
        assert!(summary.record().get("model_id").is_none());
        assert!(summary.record().get("service_tier").is_none());
    }

    #[test]
    fn tier_disagreement_folds_to_unsupported() {
        let messages = [
            message("m", "standard", UsageRegion::Measured(counts(1))),
            message("m", "priority", UsageRegion::Measured(counts(2))),
        ];
        assert_eq!(
            UsageSummary::derive(&provenance(), &messages).harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Unsupported)
        );
    }

    #[test]
    fn a_sum_outside_the_wire_count_domain_folds_to_unsupported() {
        const I63_MAX: u64 = 9_223_372_036_854_775_807; // the u63 wire cap
        let big = counts(I63_MAX);
        let messages = [
            message("m", "standard", UsageRegion::Measured(big)),
            message("m", "standard", UsageRegion::Measured(counts(1))),
        ];
        assert_eq!(
            UsageSummary::derive(&provenance(), &messages).harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Unsupported)
        );
    }

    #[test]
    fn an_identity_outside_its_wire_grammar_is_unreportable() {
        let messages = [message(
            "a model with spaces",
            "standard",
            UsageRegion::Measured(counts(1)),
        )];
        let summary = UsageSummary::derive(&provenance(), &messages);
        assert!(summary.record().get("model_id").is_none());
        // A prose-shaped model string cannot enter the record anywhere.
        let serialized = String::from_utf8(summary.serialized()).unwrap();
        assert!(!serialized.contains("with spaces"));
    }

    #[test]
    fn derivation_is_total_and_order_independent() {
        let a = message("model-a", "standard", UsageRegion::Measured(counts(3)));
        let b = message("model-a", "standard", UsageRegion::Absent);
        let c = message("model-a", "standard", UsageRegion::Measured(counts(4)));
        let forward = UsageSummary::derive(&provenance(), &[a.clone(), b.clone(), c.clone()]);
        let reversed = UsageSummary::derive(&provenance(), &[c, b, a]);
        assert_eq!(forward.serialized(), reversed.serialized());
    }

    #[test]
    fn digest_excludes_itself_and_the_key_shards_by_it() {
        let messages = [message(
            "model-a",
            "standard",
            UsageRegion::Measured(counts(7)),
        )];
        let summary = UsageSummary::derive(&provenance(), &messages);

        let mut without_digest = summary.record().clone();
        let Some(Value::Text(carried)) = without_digest.remove("usage_summary_digest") else {
            panic!("the digest member must be present");
        };
        assert_eq!(carried, summary.digest());
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(without_digest).canonical_bytes());
        assert_eq!(sha256::encode_hex(&frame.finish()), summary.digest());

        let key = summary.object_key();
        assert!(key.starts_with(
            "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/derived/usage/1/usage-summaries/"
        ));
        assert!(key.contains(&format!("/{}/", &summary.digest()[..2])));
        assert!(key.ends_with(&format!("/{}.json", summary.digest())));
    }

    #[test]
    fn a_different_projection_version_is_a_different_derivation() {
        let messages = [message(
            "model-a",
            "standard",
            UsageRegion::Measured(counts(7)),
        )];
        let a = UsageSummary::derive(&provenance(), &messages);
        let mut other_provenance = provenance();
        other_provenance.adapter_projection_version = VersionToken::parse("2").unwrap();
        let b = UsageSummary::derive(&other_provenance, &messages);
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn serialized_output_is_canonical_plus_one_lf() {
        let messages = [message(
            "model-a",
            "standard",
            UsageRegion::Measured(counts(7)),
        )];
        let summary = UsageSummary::derive(&provenance(), &messages);
        let bytes = summary.serialized();
        assert_eq!(bytes.last(), Some(&b'\n'));
        let reparsed = crate::json::parse(&bytes).unwrap();
        let mut canonical = reparsed.canonical_bytes();
        canonical.push(b'\n');
        assert_eq!(canonical, bytes);
    }
}
