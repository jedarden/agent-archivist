// SPDX-License-Identifier: Apache-2.0

//! Byte-exact, domain-separated identity derivations
//! ([`schemas/v1/ingest-identifiers.json`], plan Section 7.4).
//!
//! Every labeled derivation is `label_utf8 || 0x00 || field_1..field_n`,
//! each field `u64be(len) || content`, with the field kinds (`text`, `u63`,
//! `digest`, `bytes`) fixed per input by the construction registry. The
//! framing is unambiguous by construction: the `0x00` delimiter can only
//! appear once at the head (labels contain no NUL), a field can never be
//! mistaken for two (`u64be(len)` names its own extent), and a `u63` field
//! is always exactly 8 bytes, so no field's encoding is a prefix of
//! another interpretation — the property tests in `tests/properties.rs`
//! hammer exactly this.
//!
//! Identifiers hash as their **canonical wire text** (UUIDs as 36 lowercase
//! characters, enum values as their token), never as decoded binary — a
//! decision the registry pins so a standalone verifier can reproduce every
//! identity without importing this crate.
//!
//! [`schemas/v1/ingest-identifiers.json`]: ../../../schemas/v1/ingest-identifiers.json

use crate::sha256::{Sha256, digest};
use crate::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ClientId, EnvelopeDigest,
    GenerationId, HarnessId, KeyId, OccurrenceId, RangeKind, RequestContentDigest, RequestId,
    SessionHash, TenantId, Timestamp, VersionToken,
};

/// The single 0x00 byte separating the domain label from the first field.
const LABEL_DELIMITER: u8 = 0x00;

/// Incremental builder for one labeled derivation frame.
///
/// Fields must be pushed in the registry's pinned order; the type of each
/// `push_*` method is the registry's field-kind pin, so a mis-ordered
/// construction is a type error rather than a wrong-hash wait-for-corpus
/// surprise at test time.
#[derive(Clone, Debug)]
pub struct FrameBuilder {
    hasher: Sha256,
}

impl FrameBuilder {
    /// Start a frame under `label` (its UTF-8 bytes plus the 0x00 delimiter).
    #[must_use]
    pub fn new(label: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(label.as_bytes());
        hasher.update(&[LABEL_DELIMITER]);
        Self { hasher }
    }

    /// Append a `text` field: `u64be(len) || utf8`.
    pub fn push_text(&mut self, text: &str) {
        let bytes = text.as_bytes();
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Append a `digest` field: `u64be(32) || 32 raw bytes`.
    pub fn push_digest32(&mut self, bytes: &[u8; 32]) {
        self.hasher.update(&32u64.to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Append a `u63` field: `u64be(8) || u64be(value)` — the length is
    /// always 8 because the integer is carried as its own 8-byte encoding.
    pub fn push_u63(&mut self, value: u64) {
        self.hasher.update(&8u64.to_be_bytes());
        self.hasher.update(&value.to_be_bytes());
    }

    /// Append a `bytes` field: `u64be(len) || content`. Reserved for the
    /// label-less payload digest and future raw-byte inputs.
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(&(bytes.len() as u64).to_be_bytes());
        self.hasher.update(bytes);
    }

    /// Consume the builder and return the 32-byte digest.
    #[must_use]
    pub fn finish(self) -> [u8; 32] {
        self.hasher.finalize()
    }
}

/// The logical-session namespace hash (`session-v1`; SID-001).
///
/// Namespaces by tenant, origin client, harness, and upstream session ID.
/// Hostname never enters (mutable provenance); origin-client scope contains
/// cloned harness UUIDs (SID-002).
#[must_use]
pub fn session_hash(
    tenant_id: &TenantId,
    origin_client_id: &ClientId,
    harness: &HarnessId,
    upstream_session_id: &str,
) -> SessionHash {
    let mut frame = FrameBuilder::new("session-v1");
    frame.push_text(tenant_id.as_str());
    frame.push_text(origin_client_id.as_str());
    frame.push_text(harness.as_str());
    frame.push_text(upstream_session_id);
    SessionHash::from_raw(frame.finish())
}

/// The artifact identity inside a session namespace (`artifact-v1`).
///
/// Includes the adapter and its projection version so an adapter change is a
/// different artifact, not a rewrite of the same one.
#[must_use]
pub fn artifact_hash(
    session: &SessionHash,
    artifact_kind: ArtifactKind,
    adapter_id: &AdapterId,
    adapter_projection_version: &VersionToken,
    adapter_artifact_id: &str,
) -> ArtifactHash {
    let mut frame = FrameBuilder::new("artifact-v1");
    frame.push_digest32(session.as_raw());
    frame.push_text(artifact_kind.token());
    frame.push_text(adapter_id.as_str());
    frame.push_text(adapter_projection_version.as_str());
    frame.push_text(adapter_artifact_id);
    ArtifactHash::from_raw(frame.finish())
}

/// The one digest that names a blob (STO-001): plain SHA-256 over the
/// canonical uncompressed payload bytes with **no domain label** — the
/// registry's single label-less construction, pinned so `blob_digest` can
/// never collide with a labeled identity over the same byte string.
#[must_use]
pub fn blob_digest(canonical_uncompressed_bytes: &[u8]) -> BlobDigest {
    BlobDigest::from_raw(digest(canonical_uncompressed_bytes))
}

/// The deterministic occurrence identity (`occurrence-v1`; SID-005).
///
/// Session namespace, artifact identity, generation, range, and blob digest.
/// Overlapping, gapped, or re-declared ranges produce distinct occurrences
/// (PI-05); uploader and request never enter, so concurrent authorized
/// uploaders converge on one key (STO-004).
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn occurrence_id(
    session: &SessionHash,
    artifact: &ArtifactHash,
    generation: &GenerationId,
    range_kind: RangeKind,
    range_start: u64,
    range_end: u64,
    blob: &BlobDigest,
) -> OccurrenceId {
    let mut frame = FrameBuilder::new("occurrence-v1");
    frame.push_digest32(session.as_raw());
    frame.push_digest32(artifact.as_raw());
    frame.push_text(generation.as_str());
    frame.push_text(range_kind.token());
    frame.push_u63(range_start);
    frame.push_u63(range_end);
    frame.push_digest32(blob.as_raw());
    OccurrenceId::from_raw(frame.finish())
}

/// The deterministic upload-attestation identity (`attestation-v1`;
/// STO-013): the occurrence plus who uploaded it under which frozen request.
#[must_use]
pub fn attestation_id(
    occurrence: &OccurrenceId,
    uploader_client_id: &ClientId,
    request_id: &RequestId,
) -> AttestationId {
    let mut frame = FrameBuilder::new("attestation-v1");
    frame.push_digest32(occurrence.as_raw());
    frame.push_text(uploader_client_id.as_str());
    frame.push_text(request_id.as_str());
    AttestationId::from_raw(frame.finish())
}

/// The bytes an ingest attempt's Ed25519 signature covers, assembled per the
/// `ingest-attempt-v1` registry entry in the pinned order. Exposed so the
/// signing crate (`archivist-auth`) and offline verifiers reproduce the
/// exact preimage without re-implementing the framing. The registry pins ten
/// covered fields, so the arity is the contract.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn ingest_attempt_signing_input(
    http_method: &str,
    route: &str,
    content_type: &str,
    request_content_digest: &RequestContentDigest,
    envelope_digest: &EnvelopeDigest,
    payload_canonical_digest: &BlobDigest,
    payload_transport_digest: &crate::vocabulary::IncomingChecksum,
    uploader_key_id: &KeyId,
    authorization_epoch: u64,
    authorization_timestamp: &Timestamp,
) -> Vec<u8> {
    // The registry frame is hashed; signing wants the preimage bytes, so the
    // same framing is written to a buffer instead of a hasher.
    let mut frame = PreimageBuilder::new("ingest-attempt-v1");
    frame.push_text(http_method);
    frame.push_text(route);
    frame.push_text(content_type);
    frame.push_digest32(request_content_digest.as_raw());
    frame.push_digest32(envelope_digest.as_raw());
    frame.push_digest32(payload_canonical_digest.as_raw());
    frame.push_digest32(payload_transport_digest.as_raw());
    frame.push_digest32(uploader_key_id.as_raw());
    frame.push_u63(authorization_epoch);
    frame.push_text(authorization_timestamp.as_str());
    frame.finish()
}

/// Byte-level twin of [`FrameBuilder`] for constructions whose preimage is
/// needed in the clear (signing) rather than only hashed.
#[derive(Clone, Debug)]
struct PreimageBuilder {
    bytes: Vec<u8>,
}

impl PreimageBuilder {
    fn new(label: &str) -> Self {
        let mut bytes = Vec::with_capacity(label.len() + 1 + 64);
        bytes.extend_from_slice(label.as_bytes());
        bytes.push(LABEL_DELIMITER);
        Self { bytes }
    }

    fn push_text(&mut self, text: &str) {
        self.push_len(text.len());
        self.bytes.extend_from_slice(text.as_bytes());
    }

    fn push_digest32(&mut self, raw: &[u8; 32]) {
        self.push_len(32);
        self.bytes.extend_from_slice(raw);
    }

    fn push_u63(&mut self, value: u64) {
        self.push_len(8);
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_len(&mut self, len: usize) {
        self.bytes.extend_from_slice(&(len as u64).to_be_bytes());
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(text: &str) -> ClientId {
        ClientId::parse(text).unwrap()
    }

    #[test]
    fn label_is_domain_separated() {
        // Same fields, different labels: different hashes.
        let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap();
        let origin = v4("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f");
        let harness = HarnessId::parse("claude-code").unwrap();
        let a = session_hash(&tenant, &origin, &harness, "s-1");
        let mut frame = FrameBuilder::new("not-session-v1");
        frame.push_text(tenant.as_str());
        frame.push_text(origin.as_str());
        frame.push_text(harness.as_str());
        frame.push_text("s-1");
        let b = SessionHash::from_raw(frame.finish());
        assert_ne!(a, b);
    }

    #[test]
    fn text_identity_is_wire_text_not_binary() {
        // The registry pins: identifiers hash as canonical lowercase text.
        let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap();
        let origin = v4("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f");
        let harness = HarnessId::parse("claude-code").unwrap();
        let got = session_hash(&tenant, &origin, &harness, "up");
        let mut manual = Sha256::new();
        manual.update(b"session-v1\0");
        for field in [
            tenant.to_string(),
            origin.to_string(),
            harness.to_string(),
            "up".to_owned(),
        ] {
            manual.update(&(field.len() as u64).to_be_bytes());
            manual.update(field.as_bytes());
        }
        assert_eq!(got.as_raw(), &manual.finalize()[..]);
    }

    #[test]
    fn blob_digest_is_plain_sha256_without_label() {
        let bytes = b"canonical payload bytes";
        assert_eq!(
            blob_digest(bytes).to_hex(),
            crate::sha256::encode_hex(&digest(bytes))
        );
        // And a labeled frame over the same bytes differs.
        let mut frame = FrameBuilder::new("blob");
        frame.push_bytes(bytes);
        assert_ne!(blob_digest(bytes).as_raw(), &frame.finish()[..]);
    }

    #[test]
    fn u63_field_encoding_is_length_eight_then_value() {
        // Two fields (5, 0) versus shifted ambiguity: framing must differ.
        let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").unwrap();
        let origin = v4("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f");
        let harness = HarnessId::parse("claude-code").unwrap();
        let session = session_hash(&tenant, &origin, &harness, "s");
        let artifact = artifact_hash(
            &session,
            ArtifactKind::FileSlice,
            &AdapterId::parse("adapter").unwrap(),
            &VersionToken::parse("1").unwrap(),
            "art",
        );
        let generation = GenerationId::parse("1a07a111-7000-7000-8000-000000000001").unwrap();
        let blob = blob_digest(b"x");
        let a = occurrence_id(
            &session,
            &artifact,
            &generation,
            RangeKind::Byte,
            0,
            0,
            &blob,
        );
        let b = occurrence_id(
            &session,
            &artifact,
            &generation,
            RangeKind::Byte,
            0,
            1,
            &blob,
        );
        assert_ne!(a, b);
    }

    #[test]
    fn signing_input_shape() {
        let input = ingest_attempt_signing_input(
            "POST",
            "/v1/ingest",
            "multipart/related; boundary=b",
            &RequestContentDigest::parse(&"01".repeat(32)).unwrap(),
            &EnvelopeDigest::parse(&"02".repeat(32)).unwrap(),
            &BlobDigest::parse(&"03".repeat(32)).unwrap(),
            &crate::vocabulary::IncomingChecksum::parse(&"04".repeat(32)).unwrap(),
            &KeyId::parse(&"05".repeat(32)).unwrap(),
            7,
            &Timestamp::parse("2026-09-12T00:00:00Z").unwrap(),
        );
        assert!(input.starts_with(b"ingest-attempt-v1\0"));
        // Label (17) + delimiter (1) + ten fields: one 8-byte length prefix
        // each, then the pinned content sizes.
        let content = 4 /* POST */ + 10 /* /v1/ingest */
            + 29 /* multipart/related; boundary=b */
            + 32 * 5 /* the five digests */
            + 8 /* authorization epoch */
            + 20 /* authorization timestamp */;
        assert_eq!(input.len(), 17 + 1 + 10 * 8 + content);
    }
}
