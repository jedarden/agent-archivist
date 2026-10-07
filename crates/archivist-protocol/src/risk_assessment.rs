// SPDX-License-Identifier: Apache-2.0

//! Immutable `rules-v1` classification evidence for completed `redaction-v1`
//! episodes (plan Phase 10).
//!
//! This module is deliberately downstream of [`crate::episode_derivation`].
//! It reads only the completed episode's redacted content and provenance, and
//! emits a digest-addressed evidence record. It does not read a policy, ask an
//! authorization question, or claim that any result authorizes use. A policy
//! evaluator and a human `use-approval-v1` record remain separate consumers.
//!
//! The rule table below is the complete v1 classifier artifact. Rule order is
//! frozen in the table and is included in `rule_set_digest`; a changed rule,
//! matcher, severity, or order therefore produces a different immutable
//! classifier provenance value. Match evidence never copies matched content.
//!
//! [`crate::episode_derivation`]: crate::episode_derivation

use crate::derivation::FrameBuilder;
use crate::episode_derivation::DerivedEpisode;
use crate::json::{Object, Value};
use crate::sha256;
use crate::vocabulary::Timestamp;

const ASSESSMENT_VERSION: i64 = 1;
const CLASSIFIER_KIND: &str = "rules";
const CLASSIFIER_VERSION: &str = "1";
const DIGEST_LABEL: &str = "risk-assessment-v1";
const RULE_SET_DIGEST_LABEL: &str = "rules-v1";

/// Digest of the checked-in ordered rules-v1 artifact. This is the value a
/// tenant policy may allowlist; the classifier still recomputes it from the
/// table and tests pin the two values together.
pub const RULE_SET_DIGEST: &str =
    "9b7100cf73896b3c92a5ac299991ffd328f4b1f202ea7b201848691660448150";

// A classifier must fail closed before spending unbounded work over an
// otherwise valid episode. The episode producer has a larger per-record bound;
// this smaller aggregate bound is the classifier's own resource contract.
const MAX_CLASSIFIER_CONTENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CLASSIFIER_RECORDS: usize = 65_536;
const MAX_CLASSIFIER_MATCHES: usize = 4_096;

const LABELS: [&str; 5] = [
    "prompt_injection",
    "instruction_hijack",
    "secret_or_credential",
    "data_exfiltration",
    "unsafe_tool_request",
];

const PROMPT_INJECTION: [&str; 3] = [
    "ignore previous instructions",
    "ignore all prior instructions",
    "disregard previous instructions",
];
const INSTRUCTION_HIJACK: [&str; 3] = [
    "override system instructions",
    "you are now",
    "new system instructions",
];
const SECRET_OR_CREDENTIAL: [&str; 4] = ["password", "api key", "secret token", "credential"];
const DATA_EXFILTRATION: [&str; 4] = ["exfiltrate", "send data", "upload data", "send transcript"];
const UNSAFE_TOOL_REQUEST: [&str; 4] = [
    "rm -rf",
    "delete all files",
    "execute shell",
    "disable safety checks",
];

#[derive(Clone, Copy)]
struct Rule {
    id: &'static str,
    label: &'static str,
    severity: &'static str,
    matcher: Matcher,
}

#[derive(Clone, Copy)]
enum Matcher {
    Phrases(&'static [&'static str]),
    RedactionMarker,
}

// This is an ordered table, not a set. Keep the order stable: it is both the
// first-match ordering used in evidence and part of the rule-set digest.
const RULES: [Rule; 17] = [
    Rule {
        id: "pi-ignore-previous",
        label: "prompt_injection",
        severity: "high",
        matcher: Matcher::Phrases(&PROMPT_INJECTION),
    },
    Rule {
        id: "ih-override-system",
        label: "instruction_hijack",
        severity: "high",
        matcher: Matcher::Phrases(&INSTRUCTION_HIJACK),
    },
    Rule {
        id: "secret-redaction-marker",
        label: "secret_or_credential",
        severity: "high",
        matcher: Matcher::RedactionMarker,
    },
    Rule {
        id: "secret-credential-language",
        label: "secret_or_credential",
        severity: "high",
        matcher: Matcher::Phrases(&SECRET_OR_CREDENTIAL),
    },
    Rule {
        id: "exfiltration-language",
        label: "data_exfiltration",
        severity: "high",
        matcher: Matcher::Phrases(&DATA_EXFILTRATION),
    },
    Rule {
        id: "unsafe-tool-language",
        label: "unsafe_tool_request",
        severity: "high",
        matcher: Matcher::Phrases(&UNSAFE_TOOL_REQUEST),
    },
    // These additional ordered entries make the corpus explicit about the
    // classifier's supported vocabulary without broadening a phrase match.
    Rule {
        id: "pi-jailbreak",
        label: "prompt_injection",
        severity: "high",
        matcher: Matcher::Phrases(&["jailbreak", "bypass safeguards"]),
    },
    Rule {
        id: "ih-follow-new-instructions",
        label: "instruction_hijack",
        severity: "high",
        matcher: Matcher::Phrases(&["follow my instructions", "follow these instructions"]),
    },
    Rule {
        id: "secret-access-token",
        label: "secret_or_credential",
        severity: "high",
        matcher: Matcher::Phrases(&["access token", "private key"]),
    },
    Rule {
        id: "exfiltration-network",
        label: "data_exfiltration",
        severity: "high",
        matcher: Matcher::Phrases(&["post the data", "email the data", "copy the transcript"]),
    },
    Rule {
        id: "unsafe-tool-network",
        label: "unsafe_tool_request",
        severity: "high",
        matcher: Matcher::Phrases(&["run command", "execute command"]),
    },
    Rule {
        id: "pi-disregard-policy",
        label: "prompt_injection",
        severity: "high",
        matcher: Matcher::Phrases(&["disregard the policy", "ignore the policy"]),
    },
    Rule {
        id: "ih-system-prompt",
        label: "instruction_hijack",
        severity: "high",
        matcher: Matcher::Phrases(&["replace the system prompt", "rewrite the system prompt"]),
    },
    Rule {
        id: "secret-auth-header",
        label: "secret_or_credential",
        severity: "high",
        matcher: Matcher::Phrases(&["authorization header", "bearer token"]),
    },
    Rule {
        id: "exfiltration-external",
        label: "data_exfiltration",
        severity: "high",
        matcher: Matcher::Phrases(&["send the transcript", "upload externally"]),
    },
    Rule {
        id: "unsafe-tool-permission",
        label: "unsafe_tool_request",
        severity: "high",
        matcher: Matcher::Phrases(&["grant shell access", "disable the sandbox"]),
    },
    Rule {
        id: "unsafe-tool-rm",
        label: "unsafe_tool_request",
        severity: "high",
        matcher: Matcher::Phrases(&["remove all files"]),
    },
];

/// The classifier's evidence outcome. `Positive` is a finding, while
/// `NoneDetected` means every supported rule completed without a match.
/// `Unknown` and `ResourceFailure` are refusal states, never clean results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssessmentOutcome {
    /// At least one checked-in rule matched.
    Positive,
    /// All checked-in rules completed and none matched.
    NoneDetected,
    /// Classification could not establish a supported result.
    Unknown,
    /// Classification stopped at its explicit resource bound.
    ResourceFailure,
}

impl AssessmentOutcome {
    /// The closed wire token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Positive => "positive",
            Self::NoneDetected => "none_detected",
            Self::Unknown => "unknown",
            Self::ResourceFailure => "resource_failure",
        }
    }
}

/// A content-free reason for an unknown classification. The reason is
/// bounded and carries no parser detail or source bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassificationFailure {
    /// The episode schema or redaction pipeline version is not supported.
    UnsupportedSchema,
    /// The supplied episode representation was truncated.
    Truncated,
    /// The supplied episode could not be decoded unambiguously.
    AmbiguousDecode,
    /// A checked-in rule could not complete its bounded evaluation.
    RuleFailure,
    /// The classifier's resource budget was exhausted.
    ResourceLimit,
}

impl ClassificationFailure {
    /// The closed wire token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "unsupported_schema",
            Self::Truncated => "truncated",
            Self::AmbiguousDecode => "ambiguous_decode",
            Self::RuleFailure => "rule_failure",
            Self::ResourceLimit => "resource_limit",
        }
    }

    fn outcome(self) -> AssessmentOutcome {
        if matches!(self, Self::ResourceLimit) {
            AssessmentOutcome::ResourceFailure
        } else {
            AssessmentOutcome::Unknown
        }
    }
}

/// One immutable, content-free `risk-assessment-v1` evidence record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RiskAssessment {
    record: Object,
    digest: String,
    outcome: AssessmentOutcome,
}

impl RiskAssessment {
    /// Run the checked-in ordered `rules-v1` classifier over a completed
    /// `redaction-v1` episode. The assessment time is supplied by the caller
    /// as evidence metadata; it is not used by classification and no current
    /// policy or authorization state is consulted.
    #[must_use]
    pub fn assess(episode: &DerivedEpisode, assessed_at: &Timestamp) -> Self {
        let metadata = episode_metadata(episode);
        let supported = matches!(episode.record().get("episode_version"), Some(Value::Int(1)))
            && matches!(
                episode.record().get("pipeline_id"),
                Some(Value::Text(value)) if value == "redaction"
            )
            && matches!(
                episode.record().get("pipeline_version"),
                Some(Value::Text(value)) if value == "1"
            );
        if !supported {
            return Self::failure_from_metadata(
                metadata,
                assessed_at,
                ClassificationFailure::UnsupportedSchema,
            );
        }
        let Some(Value::Array(records)) = episode.record().get("records") else {
            return Self::failure_from_metadata(
                metadata,
                assessed_at,
                ClassificationFailure::UnsupportedSchema,
            );
        };
        if records.len() > MAX_CLASSIFIER_RECORDS {
            return Self::failure_from_metadata(
                metadata,
                assessed_at,
                ClassificationFailure::ResourceLimit,
            );
        }

        let mut content_bytes = 0usize;
        for record in records {
            let Some(content) = record_object_content(record) else {
                return Self::failure_from_metadata(
                    metadata,
                    assessed_at,
                    ClassificationFailure::AmbiguousDecode,
                );
            };
            content_bytes = match content_bytes.checked_add(content.len()) {
                Some(total) if total <= MAX_CLASSIFIER_CONTENT_BYTES => total,
                _ => {
                    return Self::failure_from_metadata(
                        metadata,
                        assessed_at,
                        ClassificationFailure::ResourceLimit,
                    );
                }
            };
        }

        let mut matches = Vec::new();
        for rule in RULES {
            for record in records {
                let Some((content, ordinal)) = record_object_content_and_ordinal(record) else {
                    return Self::failure_from_metadata(
                        metadata,
                        assessed_at,
                        ClassificationFailure::RuleFailure,
                    );
                };
                if rule.matches(content) {
                    if matches.len() >= MAX_CLASSIFIER_MATCHES {
                        return Self::failure_from_metadata(
                            metadata,
                            assessed_at,
                            ClassificationFailure::ResourceLimit,
                        );
                    }
                    matches.push(MatchEvidence { rule, ordinal });
                }
            }
        }

        let outcome = if matches.is_empty() {
            AssessmentOutcome::NoneDetected
        } else {
            AssessmentOutcome::Positive
        };
        Self::assemble(metadata, assessed_at, outcome, None, &matches)
    }

    /// Emit an explicit refusal evidence record for a completed episode when
    /// a caller has a bounded decoder or rule failure to report. This records
    /// evidence of non-classification and never turns the failure into a
    /// clean or authorized result.
    #[must_use]
    pub fn failure(
        episode: &DerivedEpisode,
        assessed_at: &Timestamp,
        failure: ClassificationFailure,
    ) -> Self {
        Self::failure_from_metadata(episode_metadata(episode), assessed_at, failure)
    }

    /// The complete canonical assessment object, including its digest.
    #[must_use]
    pub fn record(&self) -> &Object {
        &self.record
    }

    /// The self-verifying `assessment_digest`.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The evidence outcome.
    #[must_use]
    pub fn outcome(&self) -> AssessmentOutcome {
        self.outcome
    }

    /// The checked-in classifier artifact digest carried in every result.
    #[must_use]
    pub fn rule_set_digest() -> String {
        let mut frame = FrameBuilder::new(RULE_SET_DIGEST_LABEL);
        frame.push_bytes(&Value::Object(rule_set_record()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        debug_assert_eq!(digest, RULE_SET_DIGEST);
        digest
    }

    /// The derived object key, re-derived from the record's tenant and digest.
    #[must_use]
    pub fn object_key(&self) -> String {
        let tenant = match self.record.get("tenant_id") {
            Some(Value::Text(tenant)) => tenant.as_str(),
            _ => "",
        };
        format!(
            "tenants/{tenant}/v1/derived/{CLASSIFIER_KIND}/{CLASSIFIER_VERSION}/\
             risk-assessments/{}/{}.json",
            &self.digest[..2],
            self.digest
        )
    }

    /// RFC 8785 canonical bytes plus the family-wide trailing LF.
    #[must_use]
    pub fn serialized(&self) -> Vec<u8> {
        let mut bytes = Value::Object(self.record.clone()).canonical_bytes();
        bytes.push(b'\n');
        bytes
    }

    fn failure_from_metadata(
        metadata: EpisodeMetadata,
        assessed_at: &Timestamp,
        failure: ClassificationFailure,
    ) -> Self {
        Self::assemble(metadata, assessed_at, failure.outcome(), Some(failure), &[])
    }

    fn assemble(
        metadata: EpisodeMetadata,
        assessed_at: &Timestamp,
        outcome: AssessmentOutcome,
        failure: Option<ClassificationFailure>,
        matches: &[MatchEvidence],
    ) -> Self {
        let mut labels = Vec::new();
        if outcome == AssessmentOutcome::Positive {
            for label in LABELS {
                if matches.iter().any(|matched| matched.rule.label == label) {
                    labels.push(Value::Text(label.to_owned()));
                }
            }
        } else if outcome == AssessmentOutcome::NoneDetected {
            labels.push(Value::Text("none_detected".to_owned()));
        } else {
            labels.push(Value::Text("unknown".to_owned()));
        }

        let highest_severity = if outcome == AssessmentOutcome::Positive {
            "high"
        } else if outcome == AssessmentOutcome::NoneDetected {
            "none"
        } else {
            "unknown"
        };

        let mut record = Object::new();
        record.set("assessment_version", Value::Int(ASSESSMENT_VERSION));
        record.set("assessed_at", Value::Text(assessed_at.as_str().to_owned()));
        record.set("classifier_kind", Value::Text(CLASSIFIER_KIND.to_owned()));
        record.set(
            "classifier_version",
            Value::Text(CLASSIFIER_VERSION.to_owned()),
        );
        record.set("episode_digest", Value::Text(metadata.episode_digest));
        record.set("episode_version", Value::Int(metadata.episode_version));
        record.set("labels", Value::Array(labels));
        record.set(
            "matches",
            Value::Array(matches.iter().map(|matched| matched.value()).collect()),
        );
        record.set("occurrence_ids", Value::Array(metadata.occurrence_ids));
        record.set("outcome", Value::Text(outcome.token().to_owned()));
        record.set("rule_set_digest", Value::Text(Self::rule_set_digest()));
        record.set("severity", Value::Text(highest_severity.to_owned()));
        record.set("tenant_id", Value::Text(metadata.tenant_id));
        if let Some(failure) = failure {
            record.set("failure_reason", Value::Text(failure.token().to_owned()));
        }

        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(record.clone()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        record.set("assessment_digest", Value::Text(digest.clone()));
        Self {
            record,
            digest,
            outcome,
        }
    }
}

#[derive(Clone, Copy)]
struct MatchEvidence {
    rule: Rule,
    ordinal: i64,
}

impl MatchEvidence {
    fn value(self) -> Value {
        let mut object = Object::new();
        object.set("label", Value::Text(self.rule.label.to_owned()));
        object.set("record_ordinal", Value::Int(self.ordinal));
        object.set("rule_id", Value::Text(self.rule.id.to_owned()));
        Value::Object(object)
    }
}

impl Rule {
    fn matches(self, content: &str) -> bool {
        match self.matcher {
            Matcher::RedactionMarker => content.contains("[redacted:"),
            Matcher::Phrases(phrases) => phrases
                .iter()
                .any(|phrase| obfuscated_phrase_matches(content, phrase)),
        }
    }
}

fn obfuscated_phrase_matches(content: &str, phrase: &str) -> bool {
    let expected: Vec<char> = phrase
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(ascii_fold)
        .collect();
    if expected.is_empty() {
        return false;
    }
    let source: Vec<char> = content.chars().collect();
    for start in 0..source.len() {
        if start != 0 && source[start - 1].is_alphanumeric() {
            continue;
        }
        if ascii_fold(source[start]) != expected[0] {
            continue;
        }
        let mut position = start + 1;
        let mut matched = true;
        for wanted in &expected[1..] {
            while position < source.len() && !source[position].is_alphanumeric() {
                position += 1;
            }
            if position == source.len() || ascii_fold(source[position]) != *wanted {
                matched = false;
                break;
            }
            position += 1;
        }
        if matched && (position == source.len() || !source[position].is_alphanumeric()) {
            return true;
        }
    }
    false
}

fn ascii_fold(character: char) -> char {
    match character.to_ascii_lowercase() {
        '1' => 'i',
        '0' => 'o',
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        value => value,
    }
}

fn record_object_content(value: &Value) -> Option<&str> {
    match value {
        Value::Object(object) => match object.get("content") {
            Some(Value::Text(content)) => Some(content),
            _ => None,
        },
        _ => None,
    }
}

fn record_object_content_and_ordinal(value: &Value) -> Option<(&str, i64)> {
    let Value::Object(object) = value else {
        return None;
    };
    let content = match object.get("content") {
        Some(Value::Text(content)) => content.as_str(),
        _ => return None,
    };
    let ordinal = match object.get("ordinal") {
        Some(Value::Int(ordinal)) if *ordinal >= 0 => *ordinal,
        _ => return None,
    };
    Some((content, ordinal))
}

struct EpisodeMetadata {
    tenant_id: String,
    episode_digest: String,
    episode_version: i64,
    occurrence_ids: Vec<Value>,
}

fn episode_metadata(episode: &DerivedEpisode) -> EpisodeMetadata {
    let record = episode.record();
    let tenant_id = match record.get("tenant_id") {
        Some(Value::Text(value)) => value.clone(),
        _ => String::new(),
    };
    let episode_digest = match record.get("episode_digest") {
        Some(Value::Text(value)) => value.clone(),
        _ => episode.digest().to_owned(),
    };
    let episode_version = match record.get("episode_version") {
        Some(Value::Int(value)) => *value,
        _ => 0,
    };
    let occurrence_ids = match record.get("occurrence_ids") {
        Some(Value::Array(values)) => values.clone(),
        _ => Vec::new(),
    };
    EpisodeMetadata {
        tenant_id,
        episode_digest,
        episode_version,
        occurrence_ids,
    }
}

fn rule_set_record() -> Object {
    let mut root = Object::new();
    root.set("classifier_kind", Value::Text(CLASSIFIER_KIND.to_owned()));
    root.set(
        "classifier_version",
        Value::Text(CLASSIFIER_VERSION.to_owned()),
    );
    root.set(
        "rules",
        Value::Array(
            RULES
                .iter()
                .map(|rule| {
                    let mut object = Object::new();
                    object.set("id", Value::Text(rule.id.to_owned()));
                    object.set("label", Value::Text(rule.label.to_owned()));
                    object.set("severity", Value::Text(rule.severity.to_owned()));
                    match rule.matcher {
                        Matcher::RedactionMarker => {
                            object.set("matcher", Value::Text("redaction_marker".to_owned()));
                        }
                        Matcher::Phrases(phrases) => {
                            object.set("matcher", Value::Text("obfuscated_phrase".to_owned()));
                            object.set(
                                "phrases",
                                Value::Array(
                                    phrases
                                        .iter()
                                        .map(|phrase| Value::Text((*phrase).to_owned()))
                                        .collect(),
                                ),
                            );
                        }
                    }
                    Value::Object(object)
                })
                .collect(),
        ),
    );
    root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obfuscation_and_unicode_separators_are_supported_with_boundaries() {
        assert!(obfuscated_phrase_matches(
            "Please i.g.n.o.r.e\u{200b} previous instructions.",
            "ignore previous instructions"
        ));
        assert!(obfuscated_phrase_matches(
            "o v e r r i d e-system.instructions",
            "override system instructions"
        ));
        assert!(obfuscated_phrase_matches(
            "1gn0re previous instructions",
            "ignore previous instructions"
        ));
        assert!(!obfuscated_phrase_matches(
            "Ignoring previous instructions is not a command.",
            "ignore previous instructions"
        ));
    }

    #[test]
    fn rule_set_digest_is_stable_and_nonempty() {
        let first = RiskAssessment::rule_set_digest();
        assert_eq!(first, RiskAssessment::rule_set_digest());
        assert_eq!(first.len(), 64);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
