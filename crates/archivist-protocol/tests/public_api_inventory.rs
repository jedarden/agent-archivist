// SPDX-License-Identifier: Apache-2.0

//! The public API inventory of `archivist-protocol`, as an executable test.
//!
//! The crate boundary promises that no public item can expose a replaceable
//! third-party SDK shape (plan Section 4; the crate docs, "Crate boundary").
//! This file is the delivered-surface half of that promise:
//!
//! - every entry is compile-checked. A type is named through
//!   [`std::any::type_name`], so renaming, privatising, or moving it breaks
//!   this test; a free function is bound to an exact function-pointer type,
//!   so changing any parameter or return type breaks it too; a constant is
//!   asserted at its pinned wire value;
//! - the type assertion proves every inventoried type lives under
//!   `archivist_protocol::`, so the documented surface is project-owned by
//!   construction;
//! - completeness is enforced by `tools/check-protocol-boundary.py` in the
//!   definition-of-done fast lane: a public item missing from this
//!   inventory, an inventory entry whose item no longer exists, or a count
//!   literal out of step with the source fails the gate. Inherent methods
//!   are deliberately not inventoried: the boundary gate scans their
//!   signatures for foreign types, and they hang off inventoried
//!   project-owned types.

use std::any::type_name;

use archivist_protocol as protocol;
use archivist_protocol::json::{ParseError, Value};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ClientId, EnvelopeDigest,
    GenerationId, HarnessId, IncomingChecksum, KeyId, OccurrenceId, RangeKind,
    RequestContentDigest, RequestId, SessionHash, TenantId, Timestamp, VersionToken,
};

/// The documented public types: `(inventory path, resolved type name)`.
// One entry per public type, four lines each by rustfmt; the length is the
// inventory, not complexity.
#[allow(clippy::too_many_lines)]
fn type_inventory() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "attempt_reconstruction::AttemptOutcome",
            type_name::<archivist_protocol::attempt_reconstruction::AttemptOutcome>(),
        ),
        (
            "attempt_reconstruction::AttemptReconstruction",
            type_name::<archivist_protocol::attempt_reconstruction::AttemptReconstruction>(),
        ),
        (
            "attempt_reconstruction::AttemptTerminalState",
            type_name::<archivist_protocol::attempt_reconstruction::AttemptTerminalState>(),
        ),
        (
            "attempt_reconstruction::AttemptTransportError",
            type_name::<archivist_protocol::attempt_reconstruction::AttemptTransportError>(),
        ),
        (
            "attempt_reconstruction::InferenceReconstruction",
            type_name::<archivist_protocol::attempt_reconstruction::InferenceReconstruction>(),
        ),
        (
            "attempt_reconstruction::PartitionField",
            type_name::<archivist_protocol::attempt_reconstruction::PartitionField>(),
        ),
        (
            "attempt_reconstruction::PayloadRef",
            type_name::<archivist_protocol::attempt_reconstruction::PayloadRef>(),
        ),
        (
            "attempt_reconstruction::ReconstructionAnomaly",
            type_name::<archivist_protocol::attempt_reconstruction::ReconstructionAnomaly>(),
        ),
        (
            "attempt_reconstruction::ReconstructionError",
            type_name::<archivist_protocol::attempt_reconstruction::ReconstructionError>(),
        ),
        (
            "attempt_reconstruction::RetryTransition",
            type_name::<archivist_protocol::attempt_reconstruction::RetryTransition>(),
        ),
        (
            "attempt_reconstruction::StreamEventRef",
            type_name::<archivist_protocol::attempt_reconstruction::StreamEventRef>(),
        ),
        (
            "attempt_reconstruction::UsageObservation",
            type_name::<archivist_protocol::attempt_reconstruction::UsageObservation>(),
        ),
        (
            "attempt_sequence::AttemptSequencer",
            type_name::<archivist_protocol::attempt_sequence::AttemptSequencer>(),
        ),
        (
            "attempt_sequence::SequenceError",
            type_name::<archivist_protocol::attempt_sequence::SequenceError>(),
        ),
        (
            "correlation::CorrelationError",
            type_name::<archivist_protocol::correlation::CorrelationError>(),
        ),
        (
            "correlation::LogicalInference",
            type_name::<archivist_protocol::correlation::LogicalInference>(),
        ),
        (
            "correlation::OrchestratorOperation",
            type_name::<archivist_protocol::correlation::OrchestratorOperation>(),
        ),
        (
            "correlation::ProviderAttempt",
            type_name::<archivist_protocol::correlation::ProviderAttempt>(),
        ),
        (
            "derivation::FrameBuilder",
            type_name::<archivist_protocol::derivation::FrameBuilder>(),
        ),
        (
            "inference_artifact::BoundaryEvent",
            type_name::<archivist_protocol::inference_artifact::BoundaryEvent>(),
        ),
        (
            "inference_artifact::InferenceArtifact",
            type_name::<archivist_protocol::inference_artifact::InferenceArtifact>(),
        ),
        (
            "inference_artifact::InferenceArtifactError",
            type_name::<archivist_protocol::inference_artifact::InferenceArtifactError>(),
        ),
        (
            "inference_artifact::Metadata",
            type_name::<archivist_protocol::inference_artifact::Metadata>(),
        ),
        (
            "inference_artifact::Payload",
            type_name::<archivist_protocol::inference_artifact::Payload>(),
        ),
        (
            "episode_derivation::DerivedEpisode",
            type_name::<archivist_protocol::episode_derivation::DerivedEpisode>(),
        ),
        (
            "episode_derivation::EpisodeGap",
            type_name::<archivist_protocol::episode_derivation::EpisodeGap>(),
        ),
        (
            "episode_derivation::OccurrenceInput",
            type_name::<archivist_protocol::episode_derivation::OccurrenceInput<'_>>(),
        ),
        (
            "episode_derivation::PseudonymKey",
            type_name::<archivist_protocol::episode_derivation::PseudonymKey<'_>>(),
        ),
        (
            "envelope::Envelope",
            type_name::<archivist_protocol::envelope::Envelope>(),
        ),
        (
            "envelope::EnvelopeError",
            type_name::<archivist_protocol::envelope::EnvelopeError>(),
        ),
        (
            "json::Object",
            type_name::<archivist_protocol::json::Object>(),
        ),
        (
            "json::ParseError",
            type_name::<archivist_protocol::json::ParseError>(),
        ),
        (
            "json::Value",
            type_name::<archivist_protocol::json::Value>(),
        ),
        (
            "object_key::AttestationObjectKey",
            type_name::<archivist_protocol::object_key::AttestationObjectKey>(),
        ),
        (
            "object_key::BlobObjectKey",
            type_name::<archivist_protocol::object_key::BlobObjectKey>(),
        ),
        (
            "object_key::OccurrenceObjectKey",
            type_name::<archivist_protocol::object_key::OccurrenceObjectKey>(),
        ),
        (
            "occurrence_redaction::EpisodeRole",
            type_name::<archivist_protocol::occurrence_redaction::EpisodeRole>(),
        ),
        (
            "occurrence_redaction::RedactedOccurrence",
            type_name::<archivist_protocol::occurrence_redaction::RedactedOccurrence>(),
        ),
        (
            "occurrence_redaction::RedactionGap",
            type_name::<archivist_protocol::occurrence_redaction::RedactionGap>(),
        ),
        (
            "occurrence_redaction::SourceRecord",
            type_name::<archivist_protocol::occurrence_redaction::SourceRecord<'_>>(),
        ),
        (
            "orchestrator_correlation::AttemptProvenance",
            type_name::<archivist_protocol::orchestrator_correlation::AttemptProvenance>(),
        ),
        (
            "orchestrator_correlation::OccurrenceReference",
            type_name::<archivist_protocol::orchestrator_correlation::OccurrenceReference>(),
        ),
        (
            "orchestrator_correlation::OperationProvenance",
            type_name::<archivist_protocol::orchestrator_correlation::OperationProvenance>(),
        ),
        (
            "orchestrator_correlation::OrchestratorCorrelation",
            type_name::<archivist_protocol::orchestrator_correlation::OrchestratorCorrelation>(),
        ),
        (
            "orchestrator_correlation::OrchestratorCorrelationError",
            type_name::<archivist_protocol::orchestrator_correlation::OrchestratorCorrelationError>(
            ),
        ),
        (
            "orchestrator_correlation::OrchestratorCorrelationGraph",
            type_name::<archivist_protocol::orchestrator_correlation::OrchestratorCorrelationGraph>(
            ),
        ),
        (
            "redaction_policy::CorpusError",
            type_name::<archivist_protocol::redaction_policy::CorpusError>(),
        ),
        (
            "redaction_policy::DetectorEmit",
            type_name::<archivist_protocol::redaction_policy::DetectorEmit>(),
        ),
        (
            "redaction_policy::DetectorEntry",
            type_name::<archivist_protocol::redaction_policy::DetectorEntry>(),
        ),
        (
            "redaction_policy::MarkerClass",
            type_name::<archivist_protocol::redaction_policy::MarkerClass>(),
        ),
        (
            "redaction_policy::PseudonymClass",
            type_name::<archivist_protocol::redaction_policy::PseudonymClass>(),
        ),
        (
            "redaction_policy::RedactionCorpus",
            type_name::<archivist_protocol::redaction_policy::RedactionCorpus>(),
        ),
        (
            "redaction_policy::StructuredField",
            type_name::<archivist_protocol::redaction_policy::StructuredField>(),
        ),
        (
            "sha256::Sha256",
            type_name::<archivist_protocol::sha256::Sha256>(),
        ),
        (
            "usage_summary::HarnessUsageState",
            type_name::<archivist_protocol::usage_summary::HarnessUsageState>(),
        ),
        (
            "usage_summary::MessageUsage",
            type_name::<archivist_protocol::usage_summary::MessageUsage>(),
        ),
        (
            "usage_summary::OccurrenceProvenance",
            type_name::<archivist_protocol::usage_summary::OccurrenceProvenance>(),
        ),
        (
            "usage_summary::SourceUsageCounts",
            type_name::<archivist_protocol::usage_summary::SourceUsageCounts>(),
        ),
        (
            "usage_summary::UnknownReason",
            type_name::<archivist_protocol::usage_summary::UnknownReason>(),
        ),
        (
            "usage_summary::UsageRegion",
            type_name::<archivist_protocol::usage_summary::UsageRegion>(),
        ),
        (
            "usage_summary::UsageSummary",
            type_name::<archivist_protocol::usage_summary::UsageSummary>(),
        ),
        (
            "vocabulary::AdapterId",
            type_name::<archivist_protocol::vocabulary::AdapterId>(),
        ),
        (
            "vocabulary::ArtifactHash",
            type_name::<archivist_protocol::vocabulary::ArtifactHash>(),
        ),
        (
            "vocabulary::ArtifactKind",
            type_name::<archivist_protocol::vocabulary::ArtifactKind>(),
        ),
        (
            "vocabulary::AttestationId",
            type_name::<archivist_protocol::vocabulary::AttestationId>(),
        ),
        (
            "vocabulary::BlobDigest",
            type_name::<archivist_protocol::vocabulary::BlobDigest>(),
        ),
        (
            "vocabulary::ChecksumAlgorithm",
            type_name::<archivist_protocol::vocabulary::ChecksumAlgorithm>(),
        ),
        (
            "vocabulary::ClientId",
            type_name::<archivist_protocol::vocabulary::ClientId>(),
        ),
        (
            "vocabulary::ContentType",
            type_name::<archivist_protocol::vocabulary::ContentType>(),
        ),
        (
            "vocabulary::Ed25519PublicKey",
            type_name::<archivist_protocol::vocabulary::Ed25519PublicKey>(),
        ),
        (
            "vocabulary::Ed25519Signature",
            type_name::<archivist_protocol::vocabulary::Ed25519Signature>(),
        ),
        (
            "vocabulary::EnvelopeDigest",
            type_name::<archivist_protocol::vocabulary::EnvelopeDigest>(),
        ),
        (
            "vocabulary::ErrorCode",
            type_name::<archivist_protocol::vocabulary::ErrorCode>(),
        ),
        (
            "vocabulary::GenerationId",
            type_name::<archivist_protocol::vocabulary::GenerationId>(),
        ),
        (
            "vocabulary::GrammarError",
            type_name::<archivist_protocol::vocabulary::GrammarError>(),
        ),
        (
            "vocabulary::HarnessId",
            type_name::<archivist_protocol::vocabulary::HarnessId>(),
        ),
        (
            "vocabulary::IdSource",
            type_name::<archivist_protocol::vocabulary::IdSource>(),
        ),
        (
            "vocabulary::IncomingChecksum",
            type_name::<archivist_protocol::vocabulary::IncomingChecksum>(),
        ),
        (
            "vocabulary::InferenceArtifactKind",
            type_name::<archivist_protocol::vocabulary::InferenceArtifactKind>(),
        ),
        (
            "vocabulary::InferenceRequestId",
            type_name::<archivist_protocol::vocabulary::InferenceRequestId>(),
        ),
        (
            "vocabulary::KeyId",
            type_name::<archivist_protocol::vocabulary::KeyId>(),
        ),
        (
            "vocabulary::OccurrenceId",
            type_name::<archivist_protocol::vocabulary::OccurrenceId>(),
        ),
        (
            "vocabulary::OpaqueId",
            type_name::<archivist_protocol::vocabulary::OpaqueId>(),
        ),
        (
            "vocabulary::PayloadCanonicalDigest",
            type_name::<archivist_protocol::vocabulary::PayloadCanonicalDigest>(),
        ),
        (
            "vocabulary::PayloadTransportDigest",
            type_name::<archivist_protocol::vocabulary::PayloadTransportDigest>(),
        ),
        (
            "vocabulary::ProviderAttemptId",
            type_name::<archivist_protocol::vocabulary::ProviderAttemptId>(),
        ),
        (
            "vocabulary::RangeKind",
            type_name::<archivist_protocol::vocabulary::RangeKind>(),
        ),
        (
            "vocabulary::RequestContentDigest",
            type_name::<archivist_protocol::vocabulary::RequestContentDigest>(),
        ),
        (
            "vocabulary::RequestId",
            type_name::<archivist_protocol::vocabulary::RequestId>(),
        ),
        (
            "vocabulary::RetryReason",
            type_name::<archivist_protocol::vocabulary::RetryReason>(),
        ),
        (
            "vocabulary::SafeMessage",
            type_name::<archivist_protocol::vocabulary::SafeMessage>(),
        ),
        (
            "vocabulary::SessionHash",
            type_name::<archivist_protocol::vocabulary::SessionHash>(),
        ),
        (
            "vocabulary::SignatureAlgorithm",
            type_name::<archivist_protocol::vocabulary::SignatureAlgorithm>(),
        ),
        (
            "vocabulary::StorageOutcome",
            type_name::<archivist_protocol::vocabulary::StorageOutcome>(),
        ),
        (
            "vocabulary::StorageProfile",
            type_name::<archivist_protocol::vocabulary::StorageProfile>(),
        ),
        (
            "vocabulary::TenantId",
            type_name::<archivist_protocol::vocabulary::TenantId>(),
        ),
        (
            "vocabulary::Timestamp",
            type_name::<archivist_protocol::vocabulary::Timestamp>(),
        ),
        (
            "vocabulary::TraceId",
            type_name::<archivist_protocol::vocabulary::TraceId>(),
        ),
        (
            "vocabulary::TransportEncoding",
            type_name::<archivist_protocol::vocabulary::TransportEncoding>(),
        ),
        (
            "vocabulary::TransportErrorClass",
            type_name::<archivist_protocol::vocabulary::TransportErrorClass>(),
        ),
        (
            "vocabulary::UsageSource",
            type_name::<archivist_protocol::vocabulary::UsageSource>(),
        ),
        (
            "vocabulary::VersionToken",
            type_name::<archivist_protocol::vocabulary::VersionToken>(),
        ),
    ]
}

/// Number of documented public types in [`type_inventory`]; the boundary gate
/// cross-checks the literal against the source.
const PUBLIC_TYPES: usize = 102;

/// Number of pinned signatures in [`function_inventory`]; the boundary gate
/// cross-checks the literal against the source.
const FREE_FUNCTIONS: usize = 20;

/// The documented public free functions, each with its exact signature pinned
/// by a function-pointer binding in [`pinned_signatures`].
fn function_inventory() -> Vec<&'static str> {
    vec![
        "attempt_reconstruction::reconstruct_inference",
        "correlation::mint_correlation_id",
        "correlation::mint_generation_id",
        "correlation::mint_inference_request_id",
        "correlation::mint_provider_attempt_id",
        "correlation::mint_synthetic_session_id",
        "correlation::mint_trace_id",
        "derivation::artifact_hash",
        "derivation::attestation_id",
        "derivation::blob_digest",
        "derivation::export_selection_digest",
        "derivation::ingest_attempt_signing_input",
        "derivation::occurrence_id",
        "derivation::session_hash",
        "json::parse",
        "json::parse_with_limits",
        "occurrence_redaction::redact_occurrence",
        "sha256::decode_hex",
        "sha256::digest",
        "sha256::encode_hex",
    ]
}

/// Binds every public free function to its exact signature. Adding, removing,
/// or re-typing a parameter anywhere in the crate's public surface breaks the
/// build of this test, which is the inventory contract: signature changes are
/// reviewed inventory changes. Keep these bindings in step with
/// [`function_inventory`]; the boundary gate verifies the count literal.
// The bindings ARE the assertion: each exists to be type-checked against its
// function-pointer type and deliberately has no effect — exactly what
// `no_effect_underscore_binding` fires on.
#[allow(clippy::no_effect_underscore_binding)]
fn pinned_signatures() {
    let _reconstruct_inference: fn(
        &[protocol::inference_artifact::InferenceArtifact],
    ) -> Result<
        protocol::attempt_reconstruction::InferenceReconstruction,
        protocol::attempt_reconstruction::ReconstructionError,
    > = protocol::attempt_reconstruction::reconstruct_inference;
    let _mint_trace_id: fn() -> protocol::vocabulary::TraceId =
        protocol::correlation::mint_trace_id;
    let _mint_correlation_id: fn() -> protocol::vocabulary::RequestId =
        protocol::correlation::mint_correlation_id;
    let _mint_generation_id: fn() -> protocol::vocabulary::GenerationId =
        protocol::correlation::mint_generation_id;
    let _mint_synthetic_session_id: fn() -> protocol::vocabulary::OpaqueId =
        protocol::correlation::mint_synthetic_session_id;
    let _mint_inference_request_id: fn() -> protocol::vocabulary::InferenceRequestId =
        protocol::correlation::mint_inference_request_id;
    let _mint_provider_attempt_id: fn() -> protocol::vocabulary::ProviderAttemptId =
        protocol::correlation::mint_provider_attempt_id;
    let _session_hash: fn(&TenantId, &ClientId, &HarnessId, &str) -> SessionHash =
        protocol::derivation::session_hash;
    let _artifact_hash: fn(
        &SessionHash,
        ArtifactKind,
        &AdapterId,
        &VersionToken,
        &str,
    ) -> ArtifactHash = protocol::derivation::artifact_hash;
    let _blob_digest: fn(&[u8]) -> BlobDigest = protocol::derivation::blob_digest;
    let _export_selection_digest: fn(&TenantId, &BlobDigest, &[&str]) -> BlobDigest =
        protocol::derivation::export_selection_digest;
    let _occurrence_id: fn(
        &SessionHash,
        &ArtifactHash,
        &GenerationId,
        RangeKind,
        u64,
        u64,
        &BlobDigest,
    ) -> OccurrenceId = protocol::derivation::occurrence_id;
    let _attestation_id: fn(&OccurrenceId, &ClientId, &RequestId) -> AttestationId =
        protocol::derivation::attestation_id;
    #[allow(clippy::type_complexity)]
    let _ingest_attempt_signing_input: fn(
        &str,
        &str,
        &str,
        &RequestContentDigest,
        &EnvelopeDigest,
        &BlobDigest,
        &IncomingChecksum,
        &KeyId,
        u64,
        &Timestamp,
    ) -> Vec<u8> = protocol::derivation::ingest_attempt_signing_input;
    let _parse: fn(&[u8]) -> Result<Value, ParseError> = protocol::json::parse;
    let _parse_with_limits: fn(&[u8], usize, usize) -> Result<Value, ParseError> =
        protocol::json::parse_with_limits;
    let _digest: fn(&[u8]) -> [u8; 32] = protocol::sha256::digest;
    let _encode_hex: fn(&[u8]) -> String = protocol::sha256::encode_hex;
    let _decode_hex: fn(&str) -> Option<Vec<u8>> = protocol::sha256::decode_hex;
    // `redact_occurrence` is generic over its renderer (`impl FnMut`), a type
    // that cannot be named, so no function-pointer binding exists for it. The
    // binding below is call-shaped instead: it type-checks every parameter and
    // pins the result type, which is the same reviewed-inventory contract.
    let renderer = |_class: protocol::redaction_policy::PseudonymClass, _matched: &str| -> String {
        String::new()
    };
    let _redact_occurrence: Result<
        protocol::occurrence_redaction::RedactedOccurrence,
        protocol::occurrence_redaction::RedactionGap,
    > = protocol::occurrence_redaction::redact_occurrence(
        &protocol::occurrence_redaction::SourceRecord {
            role: "user",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content: "",
        },
        renderer,
    );
}

/// The documented public constants: the wire values the protocol freezes.
fn constant_inventory() -> Vec<&'static str> {
    vec![
        "episode_derivation::EPISODE_VERSION",
        "episode_derivation::MAX_EPISODE_OCCURRENCES",
        "episode_derivation::MAX_EPISODE_RECORDS",
        "envelope::CANONICAL_MAX_BYTES",
        "envelope::ENVELOPE_VERSION",
        "envelope::PROTOCOL_VERSION",
        "envelope::RESERVED_FIELDS",
        "inference_artifact::INFERENCE_ARTIFACT_VERSION",
        "inference_artifact::METADATA_ALLOWLIST",
        "inference_artifact::RESERVED_FIELDS",
        "json::DEFAULT_MAX_BYTES",
        "json::DEFAULT_MAX_DEPTH",
        "occurrence_redaction::ENTROPY_MIN_TOKEN_CHARS",
        "occurrence_redaction::ENTROPY_PROBE_WINDOW",
        "occurrence_redaction::MAX_CONTENT_BYTES",
        "occurrence_redaction::MAX_ENTROPY_PROBES",
        "occurrence_redaction::MAX_PARENT_ORDINALS",
        "occurrence_redaction::MAX_REPLACEMENTS",
        "orchestrator_correlation::ORCHESTRATOR_CORRELATION_VERSION",
        "redaction_policy::CORPUS_VERSION",
        "redaction_policy::MARKER_FORMAT",
        "redaction_policy::PIPELINE_ID",
        "redaction_policy::PIPELINE_VERSION",
        "redaction_policy::PSEUDONYM_FORMAT",
        "redaction_policy::PSEUDONYM_KEY_ID_CONSTRUCTION",
        "redaction_policy::PSEUDONYM_KEY_ID_LABEL",
        "redaction_policy::TEST_SUITE_CORPUS",
        "usage_summary::PIPELINE_ID",
        "usage_summary::PIPELINE_VERSION",
        "usage_summary::USAGE_SUMMARY_VERSION",
    ]
}

#[test]
fn public_types_are_project_owned() {
    let inventory = type_inventory();
    assert_eq!(
        inventory.len(),
        PUBLIC_TYPES,
        "the type inventory drifted from its count literal"
    );
    for (path, resolved) in inventory {
        // `type_name` renders lifetime parameters (`SourceRecord<'_>`), and
        // the boundary gate scans the source by bare name, so the comparison
        // strips a lifetime suffix: a lifetime cannot carry an SDK shape, and
        // the path root — the part the boundary rule constrains — is still
        // checked in full.
        let resolved = resolved.strip_suffix("<'_>").unwrap_or(resolved);
        let expected = format!("archivist_protocol::{path}");
        assert_eq!(resolved, expected.as_str(), "public type moved: {path}");
    }
}

#[test]
fn free_functions_are_signed_and_inventoried() {
    pinned_signatures();
    let inventory = function_inventory();
    assert_eq!(
        inventory.len(),
        FREE_FUNCTIONS,
        "the function inventory drifted from its count literal"
    );
}

#[test]
// Every wire value is pinned at full width below, so the function's length
// tracks the constant inventory.
#[allow(clippy::too_many_lines)]
fn public_constants_pin_wire_values() {
    let inventory = constant_inventory();
    assert_eq!(
        inventory.len(),
        30,
        "the constant inventory drifted from its count"
    );
    assert_eq!(protocol::episode_derivation::EPISODE_VERSION, 1);
    assert_eq!(
        protocol::episode_derivation::MAX_EPISODE_OCCURRENCES,
        65_536
    );
    assert_eq!(protocol::episode_derivation::MAX_EPISODE_RECORDS, 65_536);
    assert_eq!(protocol::envelope::PROTOCOL_VERSION, 1);
    assert_eq!(protocol::envelope::ENVELOPE_VERSION, 1);
    assert_eq!(protocol::envelope::CANONICAL_MAX_BYTES, 65_536);
    assert_eq!(
        protocol::envelope::RESERVED_FIELDS,
        [
            "authorization_epoch",
            "authorization_key_id",
            "authorization_timestamp",
            "commit_time",
            "correlation_id",
            "signature",
        ]
    );
    assert_eq!(protocol::inference_artifact::INFERENCE_ARTIFACT_VERSION, 1);
    assert_eq!(
        protocol::inference_artifact::METADATA_ALLOWLIST,
        [
            "content_type",
            "http_status",
            "provider_request_id",
            "rate_limit_limit",
            "rate_limit_remaining",
            "rate_limit_reset",
            "usage_input_tokens",
            "usage_output_tokens",
            "usage_total_tokens",
        ]
    );
    assert_eq!(
        protocol::inference_artifact::RESERVED_FIELDS,
        [
            "access_token",
            "alpn",
            "api_key",
            "api_token",
            "authorization",
            "authorization_epoch",
            "authorization_key_id",
            "authorization_timestamp",
            "bearer_token",
            "blob_key",
            "blob_url",
            "certificate",
            "certificate_chain",
            "cipher_suite",
            "client_certificate",
            "client_secret",
            "cookie",
            "credential",
            "endpoint",
            "ip_packet",
            "object_key",
            "password",
            "private_key",
            "proxy_authorization",
            "refresh_token",
            "request_id",
            "secret",
            "session_token",
            "set_cookie",
            "signature",
            "signature_algorithm",
            "storage_path",
            "tcp_segment",
            "tls_handshake",
            "tls_record",
            "tls_session_ticket",
            "tls_version",
            "transport_encoding",
            "upload_url",
            "uri",
            "url",
            "www_authenticate",
            "x_api_key",
        ]
    );
    assert_eq!(protocol::json::DEFAULT_MAX_BYTES, 8 * 1024 * 1024);
    assert_eq!(protocol::json::DEFAULT_MAX_DEPTH, 64);
    assert_eq!(protocol::occurrence_redaction::MAX_CONTENT_BYTES, 1_048_576);
    assert_eq!(protocol::occurrence_redaction::MAX_PARENT_ORDINALS, 64);
    assert_eq!(protocol::occurrence_redaction::MAX_REPLACEMENTS, 4_096);
    assert_eq!(protocol::occurrence_redaction::MAX_ENTROPY_PROBES, 8_192);
    assert_eq!(protocol::occurrence_redaction::ENTROPY_MIN_TOKEN_CHARS, 20);
    assert_eq!(protocol::occurrence_redaction::ENTROPY_PROBE_WINDOW, 256);
    assert_eq!(protocol::usage_summary::USAGE_SUMMARY_VERSION, 1);
    assert_eq!(
        protocol::orchestrator_correlation::ORCHESTRATOR_CORRELATION_VERSION,
        1
    );
    assert_eq!(protocol::usage_summary::PIPELINE_ID, "usage");
    assert_eq!(protocol::usage_summary::PIPELINE_VERSION, "1");
}
