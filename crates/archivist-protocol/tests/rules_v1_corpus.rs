// SPDX-License-Identifier: Apache-2.0

//! Corpus replay for immutable `rules-v1` assessment evidence.

use archivist_protocol::episode_derivation::{DerivedEpisode, OccurrenceInput, PseudonymKey};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::risk_assessment::{AssessmentOutcome, RiskAssessment};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{OccurrenceId, TenantId, Timestamp};

const CORPUS: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/synthetic/rules-v1/corpus.json"
));
const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const ASSESSED_AT: &str = "2026-10-07T20:00:00Z";
const KEY: [u8; 32] = [
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

fn object<'a>(value: &'a Value, context: &str) -> &'a Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("{context}: expected object"),
    }
}

fn text<'a>(value: &'a Value, context: &str) -> &'a str {
    match value {
        Value::Text(text) => text,
        _ => panic!("{context}: expected text"),
    }
}

fn array<'a>(value: &'a Value, context: &str) -> &'a [Value] {
    match value {
        Value::Array(values) => values,
        _ => panic!("{context}: expected array"),
    }
}

fn fixture_cases() -> Vec<(String, String, String, String)> {
    let document = json::parse(CORPUS).expect("rules corpus parses");
    let root = object(&document, "root");
    assert_eq!(
        root.get("classifier"),
        Some(&Value::Text("rules-v1".to_owned()))
    );
    array(root.get("cases").expect("cases"), "cases")
        .iter()
        .map(|case| {
            let case = object(case, "case");
            (
                text(case.get("id").expect("id"), "id").to_owned(),
                text(case.get("label").expect("label"), "label").to_owned(),
                text(case.get("kind").expect("kind"), "kind").to_owned(),
                text(case.get("content").expect("content"), "content").to_owned(),
            )
        })
        .collect()
}

fn episode(content: &str) -> DerivedEpisode {
    let tenant = TenantId::parse(TENANT).expect("tenant");
    let record = archivist_protocol::occurrence_redaction::SourceRecord {
        role: "user",
        ordinal: 0,
        source_time: None,
        parent_ordinals: &[],
        content,
    };
    let occurrence = OccurrenceInput {
        occurrence_id: OccurrenceId::from_raw([0x11; 32]),
        records: std::slice::from_ref(&record),
    };
    DerivedEpisode::derive(&tenant, &PseudonymKey::new(&KEY), &[occurrence])
        .expect("fixture episode derives")
}

fn field<'a>(record: &'a Object, name: &str) -> &'a Value {
    record.get(name).unwrap_or_else(|| panic!("missing {name}"))
}

#[test]
fn every_label_has_all_five_fixture_classes() {
    let cases = fixture_cases();
    for label in [
        "prompt_injection",
        "instruction_hijack",
        "secret_or_credential",
        "data_exfiltration",
        "unsafe_tool_request",
    ] {
        for kind in ["positive", "negative", "unicode", "obfuscation", "boundary"] {
            assert!(
                cases.iter().any(|(_, case_label, case_kind, _)| {
                    case_label == label && case_kind == kind
                }),
                "missing {label} {kind} fixture"
            );
        }
    }
}

#[test]
fn corpus_classifies_positive_and_negative_cases() {
    let assessed_at = Timestamp::parse(ASSESSED_AT).expect("timestamp");
    let cases = fixture_cases();
    assert_eq!(cases.len(), 25);
    for (id, label, kind, content) in cases {
        let assessment = RiskAssessment::assess(&episode(&content), &assessed_at);
        let record = assessment.record();
        if kind == "positive" || kind == "unicode" || kind == "obfuscation" {
            assert_eq!(assessment.outcome(), AssessmentOutcome::Positive, "{id}");
            assert!(
                array(field(record, "labels"), "labels")
                    .iter()
                    .any(|value| value == &Value::Text(label.clone())),
                "{id}: expected {label}"
            );
        } else {
            assert_eq!(
                assessment.outcome(),
                AssessmentOutcome::NoneDetected,
                "{id}"
            );
            assert_eq!(
                field(record, "labels"),
                &Value::Array(vec![Value::Text("none_detected".to_owned())])
            );
        }
    }
}

#[test]
fn outcomes_provenance_references_and_digest_are_serialized_without_governance() {
    let assessed_at = Timestamp::parse(ASSESSED_AT).expect("timestamp");
    let episode = episode("A clean status question.");
    let assessment = RiskAssessment::assess(&episode, &assessed_at);
    let record = assessment.record();
    assert_eq!(
        field(record, "episode_digest"),
        &Value::Text(episode.digest().to_owned())
    );
    assert_eq!(
        field(record, "rule_set_digest"),
        &Value::Text(RiskAssessment::rule_set_digest())
    );
    assert_eq!(
        field(record, "occurrence_ids"),
        episode.record().get("occurrence_ids").unwrap()
    );
    assert_eq!(
        field(record, "outcome"),
        &Value::Text("none_detected".to_owned())
    );
    assert!(!record.contains("policy"));
    assert!(!record.contains("authorization"));
    assert!(!record.contains("use_approval"));
    assert_eq!(assessment.serialized().last(), Some(&b'\n'));

    let mut without_digest = record.clone();
    let _ = without_digest.remove("assessment_digest");
    let mut frame = archivist_protocol::derivation::FrameBuilder::new("risk-assessment-v1");
    frame.push_bytes(&Value::Object(without_digest).canonical_bytes());
    assert_eq!(assessment.digest(), &sha256::encode_hex(&frame.finish()));
}

#[test]
fn unknown_and_resource_failure_are_distinct_serializable_evidence() {
    let assessed_at = Timestamp::parse(ASSESSED_AT).expect("timestamp");
    let episode = episode("A clean status question.");
    let unknown = RiskAssessment::failure(
        &episode,
        &assessed_at,
        archivist_protocol::risk_assessment::ClassificationFailure::AmbiguousDecode,
    );
    assert_eq!(unknown.outcome(), AssessmentOutcome::Unknown);
    assert_eq!(
        unknown.record().get("failure_reason"),
        Some(&Value::Text("ambiguous_decode".to_owned()))
    );

    let resource = RiskAssessment::failure(
        &episode,
        &assessed_at,
        archivist_protocol::risk_assessment::ClassificationFailure::ResourceLimit,
    );
    assert_eq!(resource.outcome(), AssessmentOutcome::ResourceFailure);
    assert_eq!(
        resource.record().get("outcome"),
        Some(&Value::Text("resource_failure".to_owned()))
    );
    assert!(!resource.serialized().is_empty());
}

#[test]
fn classifier_resource_bound_emits_resource_failure() {
    let tenant = TenantId::parse(TENANT).expect("tenant");
    let assessed_at = Timestamp::parse(ASSESSED_AT).expect("timestamp");
    let contents: Vec<String> = (0..5).map(|_| "x".repeat(900_000)).collect();
    let records: Vec<_> = contents
        .iter()
        .enumerate()
        .map(
            |(ordinal, content)| archivist_protocol::occurrence_redaction::SourceRecord {
                role: "user",
                ordinal: u64::try_from(ordinal).expect("ordinal"),
                source_time: None,
                parent_ordinals: &[],
                content,
            },
        )
        .collect();
    let occurrence = OccurrenceInput {
        occurrence_id: OccurrenceId::from_raw([0x22; 32]),
        records: &records,
    };
    let episode = DerivedEpisode::derive(&tenant, &PseudonymKey::new(&KEY), &[occurrence])
        .expect("large fixture episode derives");
    let assessment = RiskAssessment::assess(&episode, &assessed_at);
    assert_eq!(assessment.outcome(), AssessmentOutcome::ResourceFailure);
    assert_eq!(
        assessment.record().get("failure_reason"),
        Some(&Value::Text("resource_limit".to_owned()))
    );
}
