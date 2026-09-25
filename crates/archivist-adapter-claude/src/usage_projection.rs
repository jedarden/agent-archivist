// SPDX-License-Identifier: Apache-2.0

//! Claude Code's bounded usage projection for `usage-summary-v1`.
//!
//! The catalog rebuild gives this reader one complete captured artifact. It
//! emits only normalized model/tier identities and the six numeric usage axes;
//! transcript text and arbitrary JSON members never cross the adapter
//! boundary. A present but incomplete usage object is classified as
//! `malformed`, while a total cache-creation count that cannot be assigned to
//! the pinned ephemeral classes is `unsupported` rather than guessed.

use archivist_adapter_sdk::AdapterId;
use archivist_adapter_sdk::json::{self, Object, Value};
use archivist_adapter_sdk::usage_summary::{MessageUsage, SourceUsageCounts, UsageRegion};

/// Read Claude Code assistant-message usage from one captured JSONL artifact.
///
/// Non-assistant records are irrelevant to this projection. An unknown
/// adapter identity is represented by one unsupported reading so a caller
/// cannot accidentally turn an unrecognized dialect into an absent count.
#[must_use]
pub fn read_usage(adapter: &AdapterId, bytes: &[u8]) -> Vec<MessageUsage> {
    if adapter.as_str() != super::ADAPTER_ID {
        return vec![MessageUsage {
            model_id: None,
            service_tier: None,
            region: UsageRegion::Unsupported,
        }];
    }

    let mut readings = Vec::new();
    for line in bytes.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let Ok(Value::Object(record)) = json::parse(line) else {
            // A malformed non-assistant line does not affect the assistant
            // denominator. The adapter's capture contract already admits
            // complete records only; this is defensive for old captures.
            continue;
        };
        if !is_assistant_record(&record) {
            continue;
        }
        let Some(Value::Object(message)) = record.get("message") else {
            readings.push(MessageUsage {
                model_id: None,
                service_tier: None,
                region: UsageRegion::Malformed,
            });
            continue;
        };
        let model_id = text_member(message, "model").map(str::to_owned);
        let service_tier = text_member(message, "service_tier")
            .or_else(|| {
                object_member(message, "usage").and_then(|usage| text_member(usage, "service_tier"))
            })
            .map(str::to_owned);
        let region = match object_member(message, "usage") {
            None => UsageRegion::Absent,
            Some(usage) => usage_region(usage),
        };
        readings.push(MessageUsage {
            model_id,
            service_tier,
            region,
        });
    }
    readings
}

fn is_assistant_record(record: &Object) -> bool {
    matches!(record.get("type"), Some(Value::Text(kind)) if kind == "assistant")
}

fn object_member<'a>(object: &'a Object, name: &str) -> Option<&'a Object> {
    match object.get(name) {
        Some(Value::Object(value)) => Some(value),
        _ => None,
    }
}

fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

fn usage_region(usage: &Object) -> UsageRegion {
    let Some(input_tokens) = count_member(usage, "input_tokens") else {
        return UsageRegion::Malformed;
    };
    let Some(output_tokens) = count_member(usage, "output_tokens") else {
        return UsageRegion::Malformed;
    };
    let Some(cache_read_tokens) = count_member(usage, "cache_read_input_tokens") else {
        return UsageRegion::Malformed;
    };
    let reasoning_tokens = count_member(usage, "reasoning_tokens").unwrap_or(0);

    let (five_minute_count, one_hour_count) = match object_member(usage, "cache_creation") {
        Some(cache) => {
            let Some(five_minute_tokens) = count_member(cache, "ephemeral_5m_input_tokens") else {
                return UsageRegion::Malformed;
            };
            let Some(one_hour_tokens) = count_member(cache, "ephemeral_1h_input_tokens") else {
                return UsageRegion::Malformed;
            };
            (five_minute_tokens, one_hour_tokens)
        }
        None if usage.get("cache_creation_input_tokens").is_some() => {
            // The source reported a total but did not preserve the class
            // split. Distributing it would change the meaning of a derived
            // row, so retain the bounded unsupported state.
            return UsageRegion::Unsupported;
        }
        None => return UsageRegion::Malformed,
    };

    UsageRegion::Measured(SourceUsageCounts {
        input_tokens,
        output_tokens,
        cache_read_tokens,
        cache_creation_5m: five_minute_count,
        cache_creation_1h: one_hour_count,
        reasoning_tokens,
    })
}

fn count_member(object: &Object, name: &str) -> Option<u64> {
    match object.get(name) {
        Some(Value::Int(value)) if *value >= 0 => u64::try_from(*value).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> AdapterId {
        AdapterId::parse(super::super::ADAPTER_ID).expect("adapter id grammar")
    }

    #[test]
    fn measured_usage_is_normalized_without_content() {
        let input = br#"{"type":"assistant","message":{"model":"claude-sonnet-4","service_tier":"standard","usage":{"input_tokens":2,"output_tokens":3,"cache_read_input_tokens":4,"cache_creation":{"ephemeral_5m_input_tokens":5,"ephemeral_1h_input_tokens":6}}}}"#;
        let readings = read_usage(&adapter(), input);
        assert_eq!(readings.len(), 1);
        assert!(matches!(
            readings[0].region,
            UsageRegion::Measured(SourceUsageCounts {
                input_tokens: 2,
                output_tokens: 3,
                ..
            })
        ));
        assert_eq!(readings[0].model_id.as_deref(), Some("claude-sonnet-4"));
    }

    #[test]
    fn unsplit_cache_total_is_unsupported() {
        let input = br#"{"type":"assistant","message":{"usage":{"input_tokens":1,"output_tokens":1,"cache_read_input_tokens":0,"cache_creation_input_tokens":4}}}"#;
        let readings = read_usage(&adapter(), input);
        assert!(matches!(readings[0].region, UsageRegion::Unsupported));
    }

    #[test]
    fn unknown_adapter_cannot_become_absent() {
        let other = AdapterId::parse("codex-rollout").expect("adapter id grammar");
        let readings = read_usage(&other, b"{}");
        assert!(matches!(readings[0].region, UsageRegion::Unsupported));
    }
}
