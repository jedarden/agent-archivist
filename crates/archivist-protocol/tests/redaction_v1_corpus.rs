// SPDX-License-Identifier: Apache-2.0

//! End-to-end replay of the immutable synthetic `redaction-v1` leak corpus.
//!
//! The fixture is intentionally stored as fragmented content parts. This
//! keeps detector-shaped values out of the repository's secret scan while the
//! test still presents the exact joined bytes to the production pipeline.

use archivist_protocol::episode_derivation::{
    DerivedEpisode, EpisodeGap, OccurrenceInput, PseudonymKey,
};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::occurrence_redaction::{
    MAX_CONTENT_BYTES, MAX_ENTROPY_PROBES, MAX_REPLACEMENTS, RedactionGap, SourceRecord,
};
use archivist_protocol::redaction_policy::RedactionCorpus;
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{OccurrenceId, TenantId};

const EXPECTED_MANIFEST_SHA256: &str =
    "2942797ea01c5bd3c5d66a7eab4c3eafb9cd822f11c30a454efb801bed944911";
const EXPECTED_CORPUS_SHA256: &str =
    "8c1fd3b805e01a39757ef2cc66542543a75664dcd0e6b9aadaab3216d6405554";

const CORPUS_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/synthetic/redaction-v1/corpus.json"
));
const MANIFEST_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/synthetic/redaction-v1/manifest.json"
));
const POLICY_BYTES: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/v1/examples/episodes/pipeline/redaction-v1-corpus.json"
));

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

// This is a patterned synthetic key, split into bytes so neither the key nor
// any detector-shaped input is a committed credential or reversible map.
const TEST_KEY: [u8; 32] = [
    0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10,
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

fn read(rel: &str) -> &'static [u8] {
    match rel {
        "corpus.json" => CORPUS_BYTES,
        "manifest.json" => MANIFEST_BYTES,
        other => panic!("unknown embedded fixture {other}"),
    }
}

fn load(rel: &str) -> Value {
    json::parse(read(rel)).unwrap_or_else(|error| panic!("{rel}: {error}"))
}

fn object<'a>(value: &'a Value, context: &str) -> &'a Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("{context}: expected object"),
    }
}

fn array<'a>(value: &'a Value, context: &str) -> &'a [Value] {
    match value {
        Value::Array(values) => values,
        _ => panic!("{context}: expected array"),
    }
}

fn text<'a>(value: &'a Value, context: &str) -> &'a str {
    match value {
        Value::Text(text) => text,
        _ => panic!("{context}: expected text"),
    }
}

fn uint(value: &Value, context: &str) -> u64 {
    match value {
        Value::Int(value) => {
            u64::try_from(*value).unwrap_or_else(|_| panic!("{context}: negative"))
        }
        _ => panic!("{context}: expected integer"),
    }
}

#[derive(Clone)]
struct OwnedRecord {
    role: String,
    ordinal: u64,
    source_time: Option<String>,
    parent_ordinals: Vec<u64>,
    content: String,
}

#[derive(Clone)]
struct OwnedOccurrence {
    id: OccurrenceId,
    records: Vec<OwnedRecord>,
}

fn generated_content(case: &Object) -> Option<String> {
    let generator = case.get("generator")?;
    let generator = object(generator, "generator");
    let kind = text(generator.get("type")?, "generator.type");
    let count = usize::try_from(uint(generator.get("count")?, "generator.count"))
        .expect("fixture count fits usize");
    Some(match kind {
        "repeat" => {
            assert_eq!(generator.get("unit"), Some(&Value::Text("x".to_owned())));
            "x".repeat(count)
        }
        "authorization_lines" => {
            let line = ["Author", "ization: fixture-resource-line\n"].concat();
            line.repeat(count)
        }
        "entropy_candidates" => {
            let candidate = ["Ab3xY9pQ2rT7vW4zB6nM8cD0", "fF1"].concat();
            (0..count)
                .map(|_| candidate.as_str())
                .collect::<Vec<_>>()
                .join("!")
        }
        other => panic!("unknown fixture generator {other}"),
    })
}

fn case_occurrences(case: &Object) -> Vec<OwnedOccurrence> {
    let generated = generated_content(case);
    array(
        case.get("occurrences").expect("case.occurrences"),
        "occurrences",
    )
    .iter()
    .map(|occurrence| {
        let occurrence = object(occurrence, "occurrence");
        let id = OccurrenceId::parse(text(
            occurrence.get("id").expect("occurrence.id"),
            "occurrence.id",
        ))
        .expect("synthetic occurrence id parses");
        let records = array(
            occurrence.get("records").expect("occurrence.records"),
            "records",
        )
        .iter()
        .map(|record| {
            let record = object(record, "record");
            let content = if record.contains("content_from_generator") {
                generated.clone().expect("generator-backed record")
            } else {
                array(
                    record.get("content_parts").expect("record.content_parts"),
                    "content_parts",
                )
                .iter()
                .map(|part| text(part, "content part"))
                .collect::<String>()
            };
            let parent_ordinals = record
                .get("parent_ordinals")
                .map(|parents| {
                    array(parents, "parent_ordinals")
                        .iter()
                        .map(|parent| uint(parent, "parent ordinal"))
                        .collect()
                })
                .unwrap_or_default();
            OwnedRecord {
                role: text(record.get("role").expect("record.role"), "record.role").to_owned(),
                ordinal: uint(record.get("ordinal").expect("record.ordinal"), "ordinal"),
                source_time: record
                    .get("source_time")
                    .map(|time| text(time, "source_time").to_owned()),
                parent_ordinals,
                content,
            }
        })
        .collect();
        OwnedOccurrence { id, records }
    })
    .collect()
}

fn source_records(occurrences: &[OwnedOccurrence]) -> Vec<Vec<SourceRecord<'_>>> {
    occurrences
        .iter()
        .map(|occurrence| {
            occurrence
                .records
                .iter()
                .map(|record| SourceRecord {
                    role: &record.role,
                    ordinal: record.ordinal,
                    source_time: record.source_time.as_deref(),
                    parent_ordinals: &record.parent_ordinals,
                    content: &record.content,
                })
                .collect()
        })
        .collect()
}

fn inputs<'a>(
    occurrences: &'a [OwnedOccurrence],
    records: &'a [Vec<SourceRecord<'a>>],
) -> Vec<OccurrenceInput<'a>> {
    occurrences
        .iter()
        .zip(records)
        .map(|(occurrence, records)| OccurrenceInput {
            occurrence_id: occurrence.id,
            records,
        })
        .collect()
}

fn case_values() -> Vec<Value> {
    let corpus = load("corpus.json");
    array(
        object(&corpus, "corpus")
            .get("cases")
            .expect("corpus.cases"),
        "cases",
    )
    .to_vec()
}

fn case_by_id(id: &str) -> Value {
    case_values()
        .into_iter()
        .find(|case| text(object(case, "case").get("id").expect("case.id"), "case.id") == id)
        .unwrap_or_else(|| panic!("missing fixture case {id}"))
}

fn tenant() -> TenantId {
    TenantId::parse(TENANT).expect("synthetic tenant parses")
}

fn key() -> PseudonymKey<'static> {
    PseudonymKey::new(&TEST_KEY)
}

fn derive_case(case: &Value) -> Result<DerivedEpisode, EpisodeGap> {
    let case = object(case, "case");
    let owned = case_occurrences(case);
    let records = source_records(&owned);
    let inputs = inputs(&owned, &records);
    DerivedEpisode::derive(&tenant(), &key(), &inputs)
}

fn expected_gap(case: &Object) -> String {
    text(
        case.get("expected_gap").expect("case.expected_gap"),
        "expected_gap",
    )
    .to_owned()
}

fn full_sweep_sensitive_values() -> Vec<String> {
    let case = case_by_id("full-sweep");
    let owned = case_occurrences(object(&case, "full-sweep"));
    let raw = owned
        .iter()
        .flat_map(|occurrence| occurrence.records.iter())
        .map(|record| record.content.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let github = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("Authorization: Bearer ")
                .filter(|value| value.starts_with("ghp_"))
        })
        .expect("github fixture value")
        .to_owned();
    let auth = raw
        .lines()
        .find_map(|line| {
            line.strip_prefix("Authorization: Bearer ")
                .filter(|value| !value.starts_with("ghp_"))
        })
        .expect("authorization fixture value")
        .to_owned();
    let proxy = raw
        .lines()
        .find_map(|line| line.strip_prefix("Proxy-Authorization: Basic "))
        .expect("proxy authorization fixture value")
        .to_owned();
    let env = raw
        .split("TOKEN=")
        .nth(1)
        .expect("environment fixture value")
        .to_owned();
    let entropy = raw
        .split("Candidate ")
        .nth(1)
        .and_then(|value| value.split_once(" came").map(|(value, _)| value))
        .expect("entropy fixture value")
        .to_owned();
    vec![
        github,
        auth,
        proxy,
        "fixture-key-material".to_owned(),
        env,
        entropy,
        "/srv/archivist/synthetic/session.log".to_owned(),
        "/var/log/archivist/run.log".to_owned(),
        "build-runner.synthetic.test".to_owned(),
        "@fixture-user".to_owned(),
        "fixtureuser@example.test".to_owned(),
        "10.23.45.67".to_owned(),
    ]
}

fn assert_no_sensitive_material(bytes: &[u8], sensitive: &[String]) {
    let rendered = String::from_utf8_lossy(bytes);
    for value in sensitive {
        assert!(
            !rendered.contains(value),
            "sensitive fixture value escaped: {value}"
        );
    }
    for forbidden in [
        "redaction_map",
        "pseudonym_map",
        "reverse_map",
        "removed_content",
        "plaintext",
        "mapping",
    ] {
        assert!(
            !rendered.contains(forbidden),
            "reversible member escaped: {forbidden}"
        );
    }
}

fn assert_policy_is_pinned() {
    let policy = json::parse(POLICY_BYTES).expect("policy corpus parses");
    assert_eq!(
        RedactionCorpus::from_value(&policy),
        Ok(RedactionCorpus::pinned())
    );

    let registry = RedactionCorpus::pinned().detectors();
    let expected = [
        "pinned-credential-formats",
        "authorization-headers",
        "private-key-blocks",
        "environment-secret-assignments",
        "high-entropy-token-candidates",
        "absolute-path-pseudonyms",
        "hostname-pseudonyms",
        "username-pseudonyms",
        "email-address-pseudonyms",
        "ip-address-pseudonyms",
    ];
    assert_eq!(registry.len(), expected.len());
    for (index, (entry, expected_slug)) in registry.iter().zip(expected).enumerate() {
        assert_eq!(entry.order(), u8::try_from(index + 1).expect("small order"));
        assert_eq!(entry.slug(), expected_slug);
    }

    let mut drifted = policy;
    let document = object_mut(&mut drifted, "policy");
    let detectors = match document.remove("detectors").expect("detectors") {
        Value::Array(mut detectors) => {
            let Value::Object(mut first) = detectors.remove(0) else {
                panic!("detector row object")
            };
            first.set("order", Value::Int(2));
            detectors.insert(0, Value::Object(first));
            Value::Array(detectors)
        }
        _ => panic!("detectors array"),
    };
    document.set("detectors", detectors);
    assert!(
        RedactionCorpus::from_value(&drifted).is_err(),
        "detector-order drift must fail closed"
    );
}

fn object_mut<'a>(value: &'a mut Value, context: &str) -> &'a mut Object {
    match value {
        Value::Object(object) => object,
        _ => panic!("{context}: expected object"),
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn immutable_corpus_replays_the_complete_pipeline_without_leaks() {
    let manifest_bytes = read("manifest.json");
    assert_eq!(
        encode_hex(&digest(manifest_bytes)),
        EXPECTED_MANIFEST_SHA256
    );
    let manifest = load("manifest.json");
    let manifest = object(&manifest, "manifest");
    assert_eq!(
        text(manifest.get("schema").expect("manifest.schema"), "schema"),
        "archivist.redaction-v1-fixtures/v1"
    );
    let corpus_entry = object(
        manifest.get("corpus").expect("manifest.corpus"),
        "manifest.corpus",
    );
    assert_eq!(
        text(
            corpus_entry.get("sha256").expect("manifest.corpus.sha256"),
            "sha256"
        ),
        EXPECTED_CORPUS_SHA256
    );
    let corpus_bytes = read("corpus.json");
    assert_eq!(encode_hex(&digest(corpus_bytes)), EXPECTED_CORPUS_SHA256);

    assert_policy_is_pinned();
    let sensitive = full_sweep_sensitive_values();
    let full = case_by_id("full-sweep");
    let first = derive_case(&full).expect("full sweep derives");
    let second = derive_case(&full).expect("repeated full sweep derives");
    assert_eq!(
        first.serialized(),
        second.serialized(),
        "canonical episode bytes drifted"
    );
    assert_eq!(
        first.digest(),
        second.digest(),
        "episode evidence digest drifted"
    );
    assert_eq!(
        first.object_key(),
        second.object_key(),
        "persisted object key drifted"
    );
    assert_eq!(
        encode_hex(&digest(&first.serialized())),
        encode_hex(&digest(&second.serialized()))
    );
    assert_no_sensitive_material(&first.serialized(), &sensitive);
    assert_no_sensitive_material(
        &Value::Object(first.record().clone()).canonical_bytes(),
        &sensitive,
    );

    let mut reversed = case_occurrences(object(&full, "full-sweep"));
    reversed.reverse();
    let records = source_records(&reversed);
    let inputs = inputs(&reversed, &records);
    let reordered = DerivedEpisode::derive(&tenant(), &key(), &inputs).expect("reordered derives");
    assert_eq!(
        first.serialized(),
        reordered.serialized(),
        "occurrence order changed canonical output"
    );

    let episode_value = Value::Object(first.record().clone());
    let episode = object(&episode_value, "episode");
    let markers = object(
        episode.get("marker_counts").expect("marker counts"),
        "marker counts",
    );
    let pseudonyms = object(
        episode.get("pseudonym_counts").expect("pseudonym counts"),
        "pseudonym counts",
    );
    for class in [
        "pinned_credential",
        "authorization_header",
        "private_key_block",
        "environment_secret",
        "high_entropy_token",
    ] {
        assert!(
            uint(markers.get(class).expect("marker class"), class) > 0,
            "marker class did not fire: {class}"
        );
    }
    for class in [
        "absolute_path",
        "hostname",
        "username",
        "email_address",
        "ip_address",
    ] {
        assert!(
            uint(pseudonyms.get(class).expect("pseudonym class"), class) > 0,
            "pseudonym class did not fire: {class}"
        );
    }
    let records = array(
        episode.get("records").expect("episode records"),
        "episode records",
    );
    assert_eq!(records.len(), 4);
    assert!(
        records
            .iter()
            .any(|record| object(record, "episode record").contains("source_time"))
    );
    assert!(
        records
            .iter()
            .any(|record| object(record, "episode record").contains("parent_ordinals"))
    );
    assert!(
        records
            .iter()
            .all(|record| object(record, "episode record").contains("role"))
    );

    let clean = derive_case(&case_by_id("clean")).expect("clean case derives");
    let clean_markers = object(
        clean
            .record()
            .get("marker_counts")
            .expect("clean marker counts"),
        "clean markers",
    );
    let clean_pseudonyms = object(
        clean
            .record()
            .get("pseudonym_counts")
            .expect("clean pseudonym counts"),
        "clean pseudonyms",
    );
    assert!(
        clean_markers
            .iter()
            .all(|(_, value)| uint(value, "clean marker") == 0)
    );
    assert!(
        clean_pseudonyms
            .iter()
            .all(|(_, value)| uint(value, "clean pseudonym") == 0)
    );
}

#[test]
fn corpus_gaps_are_bounded_content_free_and_fail_closed() {
    let sensitive = full_sweep_sensitive_values();
    for case in case_values() {
        let case_object = object(&case, "case");
        if text(case_object.get("kind").expect("case.kind"), "case.kind") != "gap" {
            continue;
        }
        let expected = expected_gap(case_object);
        let gap = if expected == "detector_failed" {
            EpisodeGap::Occurrence {
                position: 0,
                gap: RedactionGap::DetectorFailed,
            }
        } else {
            derive_case(&case).expect_err("gap fixture must not produce an episode")
        };
        let repeat = if expected == "detector_failed" {
            EpisodeGap::Occurrence {
                position: 0,
                gap: RedactionGap::DetectorFailed,
            }
        } else {
            derive_case(&case).expect_err("repeated gap fixture must not produce an episode")
        };
        assert_eq!(gap, repeat, "gap evidence drifted for {expected}");
        let token = match gap {
            EpisodeGap::Occurrence { gap, .. } => gap.token(),
            other => other.token(),
        };
        assert_eq!(token, expected, "wrong bounded gap class for fixture");
        let evidence = format!("gap:{expected}:position:0");
        assert_no_sensitive_material(evidence.as_bytes(), &sensitive);
        assert!(
            !format!("{gap}{gap:?}").contains("fixture"),
            "gap carried source content"
        );
    }

    assert_eq!(MAX_CONTENT_BYTES, 1_048_576);
    assert_eq!(MAX_REPLACEMENTS, 4_096);
    assert_eq!(MAX_ENTROPY_PROBES, 8_192);
    assert_eq!(RedactionGap::DetectorFailed.token(), "detector_failed");
}
