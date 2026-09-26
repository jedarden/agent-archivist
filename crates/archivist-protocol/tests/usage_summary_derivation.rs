// SPDX-License-Identifier: Apache-2.0

//! Derivation replay of the usage-summary example corpus
//! (`schemas/v1/examples/usage-summaries`; plan Phase 10, token
//! accounting).
//!
//! `usage_summary_corpus.rs` validates the committed bytes against the
//! schema's own rules; this file makes the committed corpus vectors double
//! as implementation tests of the *producer*: each of the five harness
//! scenarios is re-derived through the real derivation
//! ([`UsageSummary::derive`]) from pinned projection inputs, and the
//! output must be byte-identical to the committed record — digest,
//! canonical serialization, object key, and identity members included.
//! The projection inputs are the normalized per-message readings the
//! adapter projections will hand the `archivist catalog rebuild`; only
//! their sums are pinned by the generator, so each axis is split across
//! the summed messages deterministically. The provenance inputs are read
//! from the raw-provenance bundle's occurrence manifests, the same source
//! the generator cites, so the replay exercises the exact traceability
//! path the governed family pins.
//!
//! The corpus's three provider-observed scenarios (`provider-observed`,
//! `provider-only`, `provider-unreconciled`) are generator-pinned only:
//! `provider_usage` is the reserved second denominator, and no producer
//! API emits it here — it reconciles the exact-inference artifact family
//! (`provider_usage_reconciles_with_the_inference_artifact_schema` and
//! `the_two_denominators_are_separate_members` in
//! `usage_summary_corpus.rs` check that structurally) and stays reserved
//! until the Phase 9 join that aggregates usage reports per occurrence
//! exists to derive it from.

use std::fs;
use std::path::{Path, PathBuf};

use archivist_protocol::json::{self, Value};
use archivist_protocol::usage_summary::{
    HarnessUsageState, MessageUsage, OccurrenceProvenance, SourceUsageCounts, UnknownReason,
    UsageRegion, UsageSummary,
};
use archivist_protocol::vocabulary::{AdapterId, OccurrenceId, TenantId, VersionToken};

/// The repository root, relative to this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The committed usage-summary corpus.
fn corpus_root() -> PathBuf {
    repo_root().join("schemas/v1/examples/usage-summaries")
}

/// The raw-provenance bundle whose occurrence manifests pin the
/// provenance inputs.
fn provenance_root() -> PathBuf {
    repo_root().join("schemas/v1/examples/provenance/occurrences")
}

/// Parse one JSON file into an object.
fn load_object(path: impl AsRef<Path>) -> json::Object {
    let raw = fs::read(path.as_ref()).expect("the committed bundle is present");
    match json::parse(&raw).expect("the committed bundle parses") {
        Value::Object(object) => object,
        _ => panic!("{} must be an object", path.as_ref().display()),
    }
}

fn text<'a>(object: &'a json::Object, member: &str) -> &'a str {
    match object.get(member) {
        Some(Value::Text(text)) => text,
        other => panic!("{member} must be text, got {other:?}"),
    }
}

/// The provenance inputs for one cited occurrence, read from its
/// occurrence manifest in the raw-provenance bundle.
fn provenance(manifest: &str) -> OccurrenceProvenance {
    let manifest = load_object(provenance_root().join(manifest));
    OccurrenceProvenance {
        tenant_id: TenantId::parse(text(&manifest, "tenant_id")).expect("tenant parses"),
        adapter_id: AdapterId::parse(text(&manifest, "adapter_id")).expect("adapter parses"),
        adapter_projection_version: VersionToken::parse(text(
            &manifest,
            "adapter_projection_version",
        ))
        .expect("projection version parses"),
        occurrence_id: OccurrenceId::parse(text(&manifest, "occurrence_id"))
            .expect("occurrence id parses"),
    }
}

/// Split `total` into `parts` deterministic per-message counts summing
/// exactly to it: the generator pins only the totals, so any
/// order-independent distribution works.
fn split(total: u64, parts: usize) -> Vec<u64> {
    let parts = u64::try_from(parts).expect("a sane message count");
    let base = total / parts;
    let remainder = usize::try_from(total % parts).expect("remainder below the part count");
    (0..usize::try_from(parts).expect("a sane message count"))
        .map(|index| base + u64::from(index < remainder))
        .collect()
}

/// One measured message carrying the `index`-th share of each pinned
/// axis total.
fn measured_share(model: &str, tier: &str, shares: &[Vec<u64>], index: usize) -> MessageUsage {
    MessageUsage {
        model_id: Some(model.to_owned()),
        service_tier: Some(tier.to_owned()),
        region: UsageRegion::Measured(SourceUsageCounts {
            input_tokens: shares[0][index],
            output_tokens: shares[1][index],
            cache_read_tokens: shares[2][index],
            cache_creation_5m: shares[3][index],
            cache_creation_1h: shares[4][index],
            reasoning_tokens: shares[5][index],
        }),
    }
}

fn counts_over(model: &str, tier: &str, messages: usize, totals: [u64; 6]) -> Vec<MessageUsage> {
    let shares: Vec<Vec<u64>> = totals.iter().map(|total| split(*total, messages)).collect();
    (0..messages)
        .map(|index| measured_share(model, tier, &shares, index))
        .collect()
}

fn absent_over(model: &str, tier: Option<&str>, messages: usize) -> Vec<MessageUsage> {
    (0..messages)
        .map(|_| MessageUsage {
            model_id: Some(model.to_owned()),
            service_tier: tier.map(str::to_owned),
            region: UsageRegion::Absent,
        })
        .collect()
}

fn malformed_over(model: &str, tier: Option<&str>, messages: usize) -> Vec<MessageUsage> {
    (0..messages)
        .map(|_| MessageUsage {
            model_id: Some(model.to_owned()),
            service_tier: tier.map(str::to_owned),
            region: UsageRegion::Malformed,
        })
        .collect()
}

/// The full-coverage inputs: twelve measured messages under one model
/// identity and tier, whose counts sum to the pinned full-coverage
/// totals (`usagegen.py` `build_full_coverage`).
fn full_coverage_inputs() -> (OccurrenceProvenance, Vec<MessageUsage>) {
    let messages = counts_over(
        "claude-opus-4-6",
        "standard",
        12,
        [4127, 986, 15230, 152_304, 40_960, 512],
    );
    (provenance("direct-upload-and-relay-source.json"), messages)
}

/// The observed-zero inputs: three measured messages whose cache and
/// reasoning axes are explicit zeros (`build_observed_zero`).
fn observed_zero_inputs() -> (OccurrenceProvenance, Vec<MessageUsage>) {
    let messages = counts_over("openai/gpt-5.3-mini", "priority", 3, [903, 221, 0, 0, 0, 0]);
    (provenance("identical-bytes-second-origin.json"), messages)
}

/// The usage-absent inputs: twelve messages, none carrying any usage
/// region, all naming one model identity and tier (`build_usage_absent`).
fn usage_absent_inputs() -> (OccurrenceProvenance, Vec<MessageUsage>) {
    (
        provenance("direct-upload-and-relay-source.json"),
        absent_over("claude-opus-4-6", Some("standard"), 12),
    )
}

/// The usage-malformed inputs: three messages whose usage regions are
/// present but unparseable, one model named, no tier
/// (`build_usage_malformed`).
fn usage_malformed_inputs() -> (OccurrenceProvenance, Vec<MessageUsage>) {
    (
        provenance("identical-bytes-second-origin.json"),
        malformed_over("openai/gpt-5.3-mini", None, 3),
    )
}

/// The usage-unsupported inputs: measured messages whose identities span
/// two models, so the denominator folds to `unsupported` with both
/// identity members omitted (`build_usage_unsupported`).
fn usage_unsupported_inputs() -> (OccurrenceProvenance, Vec<MessageUsage>) {
    let mut messages = counts_over("claude-opus-4-6", "standard", 4, [12, 12, 0, 0, 0, 0]);
    messages.extend(counts_over(
        "openai/gpt-5.3-mini",
        "standard",
        4,
        [12, 12, 0, 0, 0, 0],
    ));
    (provenance("direct-upload-and-relay-source.json"), messages)
}

/// Every committed corpus vector re-derives byte-for-byte through the
/// real implementation, and the derived object key agrees with the
/// manifest's pinned identity.
#[test]
fn corpus_vectors_rederive_byte_for_byte() {
    let scenarios: [(&str, (OccurrenceProvenance, Vec<MessageUsage>)); 5] = [
        ("full-coverage", full_coverage_inputs()),
        ("observed-zero", observed_zero_inputs()),
        ("usage-absent", usage_absent_inputs()),
        ("usage-malformed", usage_malformed_inputs()),
        ("usage-unsupported", usage_unsupported_inputs()),
    ];
    let manifest = load_object(corpus_root().join("manifest.json"));
    let Some(Value::Array(files)) = manifest.get("files") else {
        panic!("manifest files must be an array");
    };
    let identities: std::collections::BTreeMap<String, json::Object> = files
        .iter()
        .map(|entry| {
            let Value::Object(entry) = entry else {
                panic!("manifest entries must be objects");
            };
            let path = text(entry, "path").to_owned();
            let identity = match entry.get("identity") {
                Some(Value::Object(identity)) => identity.clone(),
                _ => panic!("manifest entries must carry identities"),
            };
            (path, identity)
        })
        .collect();

    for (scenario, (provenance, messages)) in scenarios {
        let rel = format!("usage-summaries/{scenario}.json");
        let committed = fs::read(corpus_root().join(&rel)).expect("the corpus file is committed");

        let derived = UsageSummary::derive(&provenance, &messages);
        assert_eq!(
            derived.serialized(),
            committed,
            "{scenario}: the real derivation must reproduce the committed record byte for byte"
        );

        // The manifest's identity pins the digest and the object key; the
        // derived record must agree with both from its own bytes.
        let identity = &identities[&rel];
        assert_eq!(
            text(derived.record(), "usage_summary_digest"),
            text(identity, "usage_summary_digest"),
            "{scenario}: derived digest disagrees with the manifest identity"
        );
        assert_eq!(
            derived.object_key(),
            text(identity, "object_key"),
            "{scenario}: derived object key disagrees with the manifest identity"
        );

        // And the committed bytes re-parse to the same record.
        let reparsed = load_object(corpus_root().join(&rel));
        assert_eq!(
            &reparsed,
            derived.record(),
            "{scenario}: record round-trips"
        );
    }
}

/// A route the projection could not observe never asserts coverage: no
/// messages (or no usage regions on any message) derive the bounded
/// `unknown`/`absent` state — never a zero-filled measured encoding.
#[test]
fn unobserved_usage_never_reads_as_free() {
    for (label, messages) in [
        ("no assistant messages at all", Vec::new()),
        ("messages without usage regions", absent_over("m", None, 4)),
    ] {
        let derived = UsageSummary::derive(
            &provenance("direct-upload-and-relay-source.json"),
            &messages,
        );
        assert_eq!(
            derived.harness_usage_state(),
            HarnessUsageState::Unknown(UnknownReason::Absent),
            "{label}: the denominator must be the bounded refusal"
        );
        let Some(Value::Object(usage)) = derived.record().get("harness_usage") else {
            panic!("harness_usage must be an object");
        };
        assert_eq!(
            usage.get("state").map(text_value),
            Some("unknown".to_owned()),
            "{label}: unknown state"
        );
        assert_eq!(
            usage.get("reason").map(text_value),
            Some("absent".to_owned()),
            "{label}: absent reason"
        );
        assert_eq!(
            usage.len(),
            2,
            "{label}: no count may sit beside an unknown"
        );
    }
}

/// A measured subset discloses its partial coverage through
/// `assistant_message_count` — the sum names exactly what went into it,
/// never padded with invented zeros.
#[test]
fn partial_coverage_is_disclosed_by_the_message_count() {
    let mut messages = counts_over("m", "standard", 1, [30, 30, 30, 30, 30, 30]);
    messages.extend(absent_over("m", Some("standard"), 5));
    let derived = UsageSummary::derive(
        &provenance("direct-upload-and-relay-source.json"),
        &messages,
    );
    assert_eq!(derived.harness_usage_state(), HarnessUsageState::Measured);
    let Some(Value::Object(usage)) = derived.record().get("harness_usage") else {
        panic!("harness_usage must be an object");
    };
    assert_eq!(usage.get("assistant_message_count"), Some(&Value::Int(1)));
    assert_eq!(usage.get("input_tokens"), Some(&Value::Int(30)));
}

/// Identical inputs derive byte-identical records — the derivation has no
/// entropy to make two rebuilds diverge — and the message order the
/// projection hands in cannot change the derived bytes.
#[test]
fn derivation_is_byte_stable_and_order_independent() {
    let (provenance, messages) = full_coverage_inputs();
    let first = UsageSummary::derive(&provenance, &messages);
    let second = UsageSummary::derive(&provenance, &messages);
    assert_eq!(first.serialized(), second.serialized());

    let mut reversed = messages.clone();
    reversed.reverse();
    let reordered = UsageSummary::derive(&provenance, &reversed);
    assert_eq!(
        first.serialized(),
        reordered.serialized(),
        "the derivation is a fold over a set: message order must not matter"
    );
}

/// The same raw reading under a different projection version is a
/// different derivation and a different digest — never a silent
/// reinterpretation of an old row.
#[test]
fn a_changed_projection_version_moves_the_digest() {
    let (_, messages) = observed_zero_inputs();
    let mut changed = provenance("identical-bytes-second-origin.json");
    changed.adapter_projection_version = VersionToken::parse("2").expect("version parses");
    let a = UsageSummary::derive(&provenance("identical-bytes-second-origin.json"), &messages);
    let b = UsageSummary::derive(&changed, &messages);
    assert_ne!(a.digest(), b.digest());
    assert_ne!(a.object_key(), b.object_key());
}

fn text_value(value: &Value) -> String {
    match value {
        Value::Text(text) => text.clone(),
        other => panic!("expected text, got {other:?}"),
    }
}
