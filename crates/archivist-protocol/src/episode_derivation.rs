// SPDX-License-Identifier: Apache-2.0

//! The episode-composition stage of the `redaction-v1` derived pipeline
//! (plan Phase 10; [`schemas/v1/derived-episode.json`],
//! [docs/notes/derived-episode-schema.md]): the deterministic fold that
//! composes successful per-occurrence redactions
//! ([`crate::occurrence_redaction`]) into the canonical derived episode —
//! redacted records in episode order, the two census sums, ascending
//! occurrence provenance, the pipeline and corpus identity, the
//! tenant-scoped HMAC pseudonym key reference, and the self-verifying
//! episode digest — nothing else.
//!
//! This is the stage the redaction transformation deliberately leaves
//! open: `redact_occurrence` takes the pseudonym *renderer* as a
//! parameter because building the tenant-scoped keyed rendering is
//! composition's trusted job, not the detector engine's. The renderer
//! this module supplies is [`PseudonymKey::pseudonym`]: HMAC-SHA256 keyed
//! by the tenant's derived-pipeline key over the domain-separated pair
//! *(pseudonym class, matched bytes)*, truncated to twelve lowercase hex
//! digits inside the pinned `ps_<class>_` rendering. The keyed digest is
//! the only carrier of the match: no map from pseudonym to matched bytes
//! is built, kept, or derivable — the same matched bytes re-run the HMAC
//! every time, which is exactly what makes pseudonyms stable within a
//! tenant and key (the analytic-stability property the example bundle's
//! shared-pseudonym-space scenario demonstrates) while staying
//! irreversible without the key.
//!
//! # Fail-closed composition
//!
//! The schema's rule is absolute: an input the pipeline's version cannot
//! process — unsupported, malformed, oversized, detector-failed, or
//! limit-exceeding — produces **no episode at all** and a bounded
//! coverage gap, never a partial one. There is no mode that drops one bad
//! record and emits the rest: an episode that silently excluded an
//! unacceptable record would read as complete evidence to every
//! downstream classifier. [`DerivedEpisode::derive`] therefore returns
//! [`EpisodeGap`] — a content-free fault class in the
//! [`crate::occurrence_redaction::RedactionGap`] discipline, carrying a
//! position and nothing of the offending input — for any input that is
//! not entirely acceptable, and a canonical episode only when every
//! record redacted cleanly into one contiguous ordinal sequence.
//!
//! # Derivation stability
//!
//! Every member is a deterministic function of the input occurrence set,
//! the pinned pipeline identity and its frozen detector corpus, and the
//! tenant pseudonym key. No wall-clock, producer, or run input exists.
//! The composition is a function of the input *set*, not its
//! presentation: occurrence IDs serialize ascending, records serialize in
//! ascending ordinal order, and the censuses sum per-class counts — so
//! any permutation of the same input derives byte-identical bytes (pinned
//! by a property test below). Two runs of the same derivation agree byte
//! for byte, which is what the Phase 10 catalog-rebuild exit gate
//! requires.
//!
//! [`schemas/v1/derived-episode.json`]: ../../../schemas/v1/derived-episode.json
//! [docs/notes/derived-episode-schema.md]: ../../../docs/notes/derived-episode-schema.md

use crate::derivation::FrameBuilder;
use crate::json::{Object, Value};
use crate::occurrence_redaction::{
    RedactedOccurrence, RedactionGap, SourceRecord, redact_occurrence,
};
use crate::redaction_policy::{
    MarkerClass, PIPELINE_ID, PIPELINE_VERSION, PSEUDONYM_KEY_ID_LABEL, PseudonymClass,
    RedactionCorpus,
};
use crate::sha256::{self, Sha256};
use crate::vocabulary::{OccurrenceId, TenantId};

/// The episode schema major version this stage derives
/// (`episode_version`; plan Section 7.1 record-shape axis, independent of
/// the pipeline axis named by `pipeline_id` + `pipeline_version`).
pub const EPISODE_VERSION: i64 = 1;

/// The largest number of raw occurrences one episode may derive from:
/// the episode schema's own `occurrence_ids` bound. Anything larger is
/// [`EpisodeGap::Oversized`] — the composition never truncates
/// provenance.
pub const MAX_EPISODE_OCCURRENCES: usize = 65_536;

/// The largest number of records one episode may carry: the episode
/// schema's own `records` bound. Anything larger is
/// [`EpisodeGap::Oversized`] — an episode beyond the schema's shape is
/// not an episode, and half of one is worse than none.
pub const MAX_EPISODE_RECORDS: usize = 65_536;

/// The episode digest construction's domain label
/// (`x-archivist.derivations[0].label` in the family schema): SHA-256
/// over the canonical record bytes with the digest member removed,
/// framed like every ingest identifier — the same exclusion shape the
/// `control-record-v1` signature and the receipt-key certificate use.
const DIGEST_LABEL: &str = "episode-v1";

/// The one 0x00 byte separating the pseudonym class from the matched
/// bytes inside the keyed pseudonym preimage: the domain separator that
/// keeps `(class, bytes)` pairs unambiguous, exactly as the example
/// generator pins.
const PSEUDONYM_MESSAGE_SEPARATOR: u8 = 0x00;

/// HMAC-SHA256 (RFC 2104) over the crate's owned SHA-256: incremental,
/// so a pseudonym preimage never needs a joined copy of the matched
/// bytes.
struct HmacSha256 {
    inner: Sha256,
    outer: Sha256,
}

impl HmacSha256 {
    /// Start a keyed MAC. Keys longer than the 64-byte block are
    /// replaced by their hash; shorter keys are zero-padded — the RFC
    /// 2104 rule, pinned by the RFC 4231 vectors in the tests.
    fn new(key: &[u8]) -> Self {
        let mut block = [0u8; 64];
        if key.len() > block.len() {
            block[..32].copy_from_slice(&sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        let mut outer = Sha256::new();
        for byte in &block {
            inner.update(&[byte ^ 0x36]);
            outer.update(&[byte ^ 0x5c]);
        }
        Self { inner, outer }
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finish(mut self) -> [u8; 32] {
        let inner = self.inner.finalize();
        self.outer.update(&inner);
        self.outer.finalize()
    }
}

/// The tenant-scoped pseudonym key: the derived-pipeline key material
/// that keyed every pseudonym and the keyed key reference one episode
/// carries. Held as borrowed bytes — the key lives in the caller's
/// secret store and is never copied into any derived state; only its
/// HMAC self-ID and the pseudonyms it renders ever leave this type.
///
/// Any key length RFC 2104 accepts is legal here; a tenant provisions
/// one key per derived pipeline, and rotating it changes every pseudonym,
/// hence every episode digest — rotation is a derived-corpus event,
/// deliberately not transparent (the schema's `pseudonym_key_id` rule).
#[derive(Clone, Debug)]
pub struct PseudonymKey<'a>(&'a [u8]);

impl<'key> PseudonymKey<'key> {
    /// Bind the tenant's derived-pipeline key bytes.
    #[must_use]
    pub fn new(bytes: &'key [u8]) -> Self {
        Self(bytes)
    }

    /// The episode's `pseudonym_key_id`: lowercase hex of
    /// HMAC-SHA256(key, `pseudonym-key-id-v1`) — the keyed self-ID the
    /// schema pins. Recomputable and verifiable only by holders of the
    /// key, disclosing nothing about it; the key itself never appears in
    /// any record, file, or argument.
    #[must_use]
    pub fn key_id(&self) -> String {
        let mut mac = HmacSha256::new(self.0);
        mac.update(PSEUDONYM_KEY_ID_LABEL.as_bytes());
        sha256::encode_hex(&mac.finish())
    }

    /// The tenant-scoped HMAC pseudonym for one matched identifier: the
    /// pinned `redaction-v1` rendering `ps_<class>_<12 lowercase hex>` —
    /// HMAC-SHA256 keyed by this key over the class token, one 0x00
    /// separator, and the matched bytes, truncated to twelve hex digits.
    ///
    /// Irreversible without the key, stable within the tenant and key
    /// (identical matched bytes render identically, across records,
    /// occurrences, and episodes), and never a carrier of the matched
    /// bytes. This is the renderer the composition stage supplies to
    /// `redact_occurrence`; there is no mode that keeps a mapping from
    /// pseudonym back to match.
    #[must_use]
    pub fn pseudonym(&self, class: PseudonymClass, matched: &str) -> String {
        let mut mac = HmacSha256::new(self.0);
        mac.update(class.token().as_bytes());
        mac.update(&[PSEUDONYM_MESSAGE_SEPARATOR]);
        mac.update(matched.as_bytes());
        let hex = sha256::encode_hex(&mac.finish());
        format!("ps_{}_{}", render_token(class), &hex[..12])
    }
}

/// The class token the pinned rendering carries (`<class>` in
/// `ps_<class>_<12 lowercase hex>`): the short form the example bundle's
/// pinned episodes render — `ps_path_…`, `ps_user_…` — distinct from the
/// census token ([`PseudonymClass::token`], the schema class name) that
/// names the class inside the keyed preimage and the episode census.
/// Both spellings are part of the frozen pipeline version.
///
/// [`PseudonymClass::token`]: crate::redaction_policy::PseudonymClass::token
fn render_token(class: PseudonymClass) -> &'static str {
    match class {
        PseudonymClass::AbsolutePath => "path",
        PseudonymClass::Hostname => "hostname",
        PseudonymClass::Username => "user",
        PseudonymClass::EmailAddress => "email",
        PseudonymClass::IpAddress => "ip",
    }
}

/// One raw occurrence's contribution to an episode: its
/// `occurrence-v1` identity digest (STO-012: derived artifacts retain
/// raw occurrence references) and the source records its projection
/// normalized for it. Records carry no occurrence identity of their own
/// — the episode cites provenance at occurrence grain, exactly as the
/// schema's `occurrence_ids` member does.
#[derive(Clone, Debug)]
pub struct OccurrenceInput<'a> {
    /// The occurrence's `occurrence-v1` identity digest. Duplicate IDs
    /// across the input are [`EpisodeGap::Malformed`] — the composition
    /// never silently deduplicates incoherent provenance.
    pub occurrence_id: OccurrenceId,
    /// The occurrence's source records, verbatim from the projection.
    /// Validated here, not upstream: any record outside the pipeline's
    /// supported shape fails the whole derivation closed.
    pub records: &'a [SourceRecord<'a>],
}

/// Why no episode exists for an input set: the closed composition gap
/// set. Every variant is content-free — it names the fault class and a
/// position, never the offending input — so a gap can never become a
/// channel for the very material the pipeline exists to redact. A gap
/// carries no episode payload: the caller reports a bounded coverage gap
/// and nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpisodeGap {
    /// The input set is empty — no occurrences, or no records at all.
    /// The schema forbids an empty episode (`records` and
    /// `occurrence_ids` both have `minItems: 1`); nothing to compose is
    /// a coverage gap, never a zero-record object.
    Empty,
    /// The composition is semantically broken: two input occurrences
    /// claim one identity, or the records' ordinals are not contiguous
    /// from zero (a duplicate or a gap — the schema's producer
    /// invariants, VAL-002).
    Malformed,
    /// A composition bound is exceeded: more than
    /// [`MAX_EPISODE_OCCURRENCES`] input occurrences or more than
    /// [`MAX_EPISODE_RECORDS`] records.
    Oversized,
    /// A source record failed its own redaction at `position` (the
    /// zero-based record index across the flattened input, in input
    /// order). The inner [`RedactionGap`] names the record-level fault
    /// class; the episode-level rule is the schema's: no partial
    /// episode, only this gap.
    Occurrence {
        /// The zero-based flattened record index of the first fault.
        position: usize,
        /// The record-level fault class the redaction reported.
        gap: RedactionGap,
    },
}

impl EpisodeGap {
    /// The wire token a coverage-gap report carries for this fault
    /// class.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
            Self::Occurrence { .. } => "occurrence",
        }
    }
}

impl std::fmt::Display for EpisodeGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty input set"),
            Self::Malformed => f.write_str("incoherent composition"),
            Self::Oversized => f.write_str("episode bound exceeded"),
            Self::Occurrence { position, gap } => {
                write!(f, "record {position} failed redaction: {gap}")
            }
        }
    }
}

impl std::error::Error for EpisodeGap {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Occurrence { gap, .. } => Some(gap),
            _ => None,
        }
    }
}

/// One canonical derived episode: the complete object (`episode_digest`
/// included) and its digest. Build one with [`DerivedEpisode::derive`];
/// identical inputs and key derive identical values, byte for byte, in
/// any input order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DerivedEpisode {
    record: Object,
    digest: String,
}

impl DerivedEpisode {
    /// Compose the canonical episode of one tenant's validated raw
    /// occurrences through the pinned `redaction-v1` pipeline.
    ///
    /// Fixed first-fault order: composition bounds, then emptiness, then
    /// occurrence-identity coherence, then the records' ordinal
    /// discipline, then the per-record redactions in flattened input
    /// order — so an input with several faults always reports the same
    /// first one, and no redaction work is spent on input that is
    /// structurally doomed.
    ///
    /// # Errors
    /// An [`EpisodeGap`] when any part of the input is not entirely
    /// acceptable: empty, incoherent, over-bounded, or carrying a record
    /// that fails its own redaction. The error is content-free and the
    /// result is no episode at all — never a partial one.
    pub fn derive(
        tenant: &TenantId,
        key: &PseudonymKey<'_>,
        occurrences: &[OccurrenceInput<'_>],
    ) -> Result<Self, EpisodeGap> {
        // 1. Composition bounds, before any per-record work.
        if occurrences.len() > MAX_EPISODE_OCCURRENCES {
            return Err(EpisodeGap::Oversized);
        }
        let record_count: usize = occurrences.iter().map(|o| o.records.len()).sum();
        if record_count > MAX_EPISODE_RECORDS {
            return Err(EpisodeGap::Oversized);
        }

        // 2. Emptiness: the schema has no empty episode.
        if record_count == 0 {
            return Err(EpisodeGap::Empty);
        }

        // 3. Occurrence-identity coherence: provenance is cited, never
        // silently deduplicated.
        let mut ids: Vec<OccurrenceId> = occurrences.iter().map(|o| o.occurrence_id).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(EpisodeGap::Malformed);
        }

        // 4. Ordinal discipline: the records must be exactly contiguous
        // from zero — duplicates and gaps are composition faults,
        // checked before any redaction work.
        let mut ordinals: Vec<u64> = occurrences
            .iter()
            .flat_map(|o| o.records.iter().map(|r| r.ordinal))
            .collect();
        ordinals.sort_unstable();
        if ordinals
            .iter()
            .zip(0u64..)
            .any(|(ordinal, expected)| *ordinal != expected)
        {
            return Err(EpisodeGap::Malformed);
        }

        // 5. Per-record redaction, flattened input order, first fault
        // wins. The renderer is the keyed construction above; the engine
        // keeps no map, so each repeat of one identifier re-runs the
        // HMAC.
        let mut accepted: Vec<RedactedOccurrence> = Vec::with_capacity(record_count);
        let mut marker_sums = [0u64; MarkerClass::ALL.len()];
        let mut pseudonym_sums = [0u64; PseudonymClass::ALL.len()];
        let mut position = 0usize;
        for occurrence in occurrences {
            for record in occurrence.records {
                let redacted =
                    redact_occurrence(record, |class, matched| key.pseudonym(class, matched))
                        .map_err(|gap| EpisodeGap::Occurrence { position, gap })?;
                for (slot, count) in marker_sums.iter_mut().zip(redacted.marker_counts()) {
                    *slot += count;
                }
                for (slot, count) in pseudonym_sums.iter_mut().zip(redacted.pseudonym_counts()) {
                    *slot += count;
                }
                accepted.push(redacted);
                position += 1;
            }
        }

        Ok(Self::assemble(
            tenant,
            key,
            &ids,
            marker_sums,
            pseudonym_sums,
            accepted,
        ))
    }

    /// The complete derived record, `episode_digest` included: exactly
    /// the schema's closed member set, nothing else of the source
    /// anywhere in it.
    #[must_use]
    pub fn record(&self) -> &Object {
        &self.record
    }

    /// The record's `episode_digest`, lowercase hex — construction
    /// `episode-v1`, self-verifying from the record's own bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// The derived object key: a pure function of the record's own bytes
    /// (plan Section 7.5 derived layout), sharded by the digest's first
    /// two hex — reconstructible from the stored record alone, and never
    /// touching a raw namespace.
    #[must_use]
    pub fn object_key(&self) -> String {
        let tenant = match self.record.get("tenant_id") {
            Some(Value::Text(tenant)) => tenant.as_str(),
            _ => "",
        };
        format!(
            "tenants/{tenant}/v1/derived/{PIPELINE_ID}/{PIPELINE_VERSION}/\
             episodes/{}/{}.json",
            &self.digest[..2],
            self.digest
        )
    }

    /// The stored object's bytes: the RFC 8785 canonical serialization
    /// plus exactly one trailing LF — the family-wide rendering. The
    /// canonical bytes are also the digest preimage, so this is not a
    /// presentation choice: two byte-serializations of one record would
    /// be two identities.
    #[must_use]
    pub fn serialized(&self) -> Vec<u8> {
        let mut bytes = Value::Object(self.record.clone()).canonical_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// Assemble, digest, and store the record.
    fn assemble(
        tenant: &TenantId,
        key: &PseudonymKey<'_>,
        ids: &[OccurrenceId],
        marker_sums: [u64; MarkerClass::ALL.len()],
        pseudonym_sums: [u64; PseudonymClass::ALL.len()],
        mut accepted: Vec<RedactedOccurrence>,
    ) -> Self {
        accepted.sort_by_key(RedactedOccurrence::ordinal);
        let mut base = Object::new();
        base.set(
            "detector_corpus_digest",
            Value::Text(RedactionCorpus::pinned().digest()),
        );
        base.set("episode_version", Value::Int(EPISODE_VERSION));

        let mut markers = Object::new();
        for (class, sum) in MarkerClass::ALL.iter().zip(marker_sums) {
            markers.set(class.token(), Value::Int(census_int(sum)));
        }
        base.set("marker_counts", Value::Object(markers));
        base.set(
            "occurrence_ids",
            Value::Array(ids.iter().map(|id| Value::Text(id.to_hex())).collect()),
        );
        base.set("pipeline_id", Value::Text(PIPELINE_ID.to_owned()));
        base.set("pipeline_version", Value::Text(PIPELINE_VERSION.to_owned()));
        base.set("pseudonym_key_id", Value::Text(key.key_id()));

        let mut pseudonyms = Object::new();
        for (class, sum) in PseudonymClass::ALL.iter().zip(pseudonym_sums) {
            pseudonyms.set(class.token(), Value::Int(census_int(sum)));
        }
        base.set("pseudonym_counts", Value::Object(pseudonyms));
        base.set(
            "records",
            Value::Array(
                accepted
                    .iter()
                    .map(RedactedOccurrence::record_value)
                    .collect(),
            ),
        );
        base.set("tenant_id", Value::Text(tenant.as_str().to_owned()));

        // Construction `episode-v1`: the labeled frame over the record's
        // canonical bytes with the digest member removed — the exclusion
        // shape that makes the record self-verifying (VAL-5 discipline)
        // and every later governance record's digest binding acyclic.
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(base.clone()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        base.set("episode_digest", Value::Text(digest.clone()));

        Self {
            record: base,
            digest,
        }
    }
}

/// The census object's JSON integer for one class sum: saturating at the
/// JSON integer ceiling, because a count past `i64` has long stopped
/// being real evidence and the derivation must still render
/// deterministically instead of failing an episode that composed.
fn census_int(sum: u64) -> i64 {
    i64::try_from(sum).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::occurrence_redaction::{MAX_CONTENT_BYTES, MAX_REPLACEMENTS};

    /// The example bundle's synthetic tenant pseudonym key
    /// (`tools/episodegen.py` `PSEUDONYM_KEY`): pinned patterned bytes,
    /// never a real key — it exists only so the tests can pin the exact
    /// bytes the committed bundle was generated with. Only its HMAC
    /// self-ID and rendered pseudonyms ever appear in derived bytes.
    static EXAMPLE_KEY: [u8; 32] = [
        0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
        0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02,
        0x01, 0x00,
    ];

    /// A second synthetic key, for rotation and tenant-separation
    /// assertions: every byte different from [`EXAMPLE_KEY`]'s.
    static OTHER_KEY: [u8; 32] = [
        0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce,
        0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd,
        0xde, 0xdf,
    ];

    /// The synthetic pinned-credential fixture, assembled the way the
    /// redaction tests assemble theirs so no contiguous token shape
    /// exists in this source file — the string is a detector fixture,
    /// not a credential.
    fn github_token() -> String {
        format!("ghp_{}", "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU3vW4x")
    }

    fn tenant() -> TenantId {
        // The example bundle's tenant.
        TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").expect("tenant parses")
    }

    fn other_tenant() -> TenantId {
        TenantId::parse("1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d").expect("tenant parses")
    }

    fn key() -> PseudonymKey<'static> {
        PseudonymKey::new(&EXAMPLE_KEY)
    }

    fn other_key() -> PseudonymKey<'static> {
        PseudonymKey::new(&OTHER_KEY)
    }

    /// A synthetic occurrence ID: distinct arguments name distinct
    /// occurrences; nothing here is a real digest.
    fn occurrence_id(n: u32) -> OccurrenceId {
        let mut raw = [0u8; 32];
        raw[..4].copy_from_slice(&n.to_be_bytes());
        OccurrenceId::from_raw(raw)
    }

    fn record(ordinal: u64, content: &'static str) -> SourceRecord<'static> {
        SourceRecord {
            role: "user",
            ordinal,
            source_time: None,
            parent_ordinals: &[],
            content,
        }
    }

    fn one_input(id: u32, records: &[SourceRecord<'static>]) -> OccurrenceInput<'static> {
        let leaked: &'static [SourceRecord<'static>] =
            Box::leak(records.to_vec().into_boxed_slice());
        OccurrenceInput {
            occurrence_id: occurrence_id(id),
            records: leaked,
        }
    }

    /// The standard multi-occurrence fixture: three occurrences, six
    /// contiguous records, pseudonym and marker classes both firing, a
    /// `source_time`, and backward-only parents.
    fn fixture_records() -> Vec<Vec<SourceRecord<'static>>> {
        let credential_line: &'static str =
            Box::leak(format!("Log line cites {} inline.", github_token()).into_boxed_str());
        vec![
            vec![
                SourceRecord {
                    role: "system",
                    ordinal: 0,
                    source_time: Some("2026-09-11T16:44:05Z"),
                    parent_ordinals: &[],
                    content: "Session accepted from @agent-worker on host \
                              build-runner.internal.example.",
                },
                record(
                    1,
                    "Summarize the build log at /build/work/session-chunk.jsonl.",
                ),
            ],
            vec![SourceRecord {
                role: "assistant",
                ordinal: 2,
                source_time: None,
                parent_ordinals: &[1],
                content: "Reply to worker@internal.example from 10.9.8.7.",
            }],
            vec![
                record(3, credential_line),
                record(4, "Static status text with nothing to claim."),
                record(5, "Final note; ordinals stay contiguous."),
            ],
        ]
    }

    /// The fixture as occurrence inputs, occurrence IDs `1..=3`.
    fn fixture_inputs() -> Vec<OccurrenceInput<'static>> {
        fixture_records()
            .iter()
            .zip(1u32..)
            .map(|(records, id)| one_input(id, records))
            .collect()
    }

    fn derive_fixture() -> DerivedEpisode {
        DerivedEpisode::derive(&tenant(), &key(), &fixture_inputs()).expect("fixture derives")
    }

    /// Sum one census object's counts — the whole redaction report for
    /// that class family.
    fn census_sum(census: &Object) -> i64 {
        census
            .iter()
            .map(|(_, value)| match value {
                Value::Int(count) => *count,
                _ => panic!("census entry is an integer"),
            })
            .sum()
    }

    // --- the keyed constructions -------------------------------------------

    #[test]
    fn hmac_matches_the_rfc_4231_vectors() {
        // RFC 4231 test case 1 / case 2 / case 6 (a key longer than the
        // 64-byte block, exercised through the hash-the-key branch).
        let vectors: [(&[u8], &[u8], &str); 3] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
        ];
        for (key_bytes, data, expected) in vectors {
            let mut mac = HmacSha256::new(key_bytes);
            mac.update(data);
            assert_eq!(sha256::encode_hex(&mac.finish()), expected);
        }
    }

    #[test]
    fn pseudonyms_reproduce_the_example_bundle_bytes() {
        // The committed example bundle (schemas/v1/examples/episodes/)
        // was generated from this very key with the pinned construction;
        // every pseudonym below is byte-pinned in a committed episode
        // file, so these vectors tie the renderer to the bundle.
        let expected: [(PseudonymClass, &str, &str); 7] = [
            (
                PseudonymClass::Username,
                "agent-worker",
                "ps_user_94da4aa00f42",
            ),
            (
                PseudonymClass::AbsolutePath,
                "/build/work/session-chunk.jsonl",
                "ps_path_cd27de2dd025",
            ),
            (
                PseudonymClass::EmailAddress,
                "worker@internal.example",
                "ps_email_36b71935b6a1",
            ),
            (PseudonymClass::IpAddress, "10.9.8.7", "ps_ip_873773a9577f"),
            (
                PseudonymClass::Hostname,
                "build-runner.internal.example",
                "ps_hostname_a7ca26652600",
            ),
            (
                PseudonymClass::Hostname,
                "cache-node.internal.example",
                "ps_hostname_0e3f4bf9d039",
            ),
            (PseudonymClass::IpAddress, "10.9.8.8", "ps_ip_d669ef7dc3dd"),
        ];
        let key = key();
        for (class, matched, pseudonym) in expected {
            assert_eq!(key.pseudonym(class, matched), pseudonym, "{matched}");
        }
    }

    #[test]
    fn pseudonym_key_id_reproduces_the_bundle_self_id() {
        // `pseudonym_key_id` in both committed example episodes.
        let key = key();
        assert_eq!(
            key.key_id(),
            "30e3a1d0759226ec446648721bb1e9b80666cbe13c067eca665b3cbc5f36d285"
        );
        // A different key self-names differently — the keyed self-ID is
        // not a constant of the pipeline.
        assert_ne!(other_key().key_id(), key.key_id());
    }

    #[test]
    fn pseudonyms_are_stable_irreversible_and_domain_separated() {
        let key = key();
        // Stable: the same bytes render identically every time.
        assert_eq!(
            key.pseudonym(PseudonymClass::Username, "agent-worker"),
            key.pseudonym(PseudonymClass::Username, "agent-worker")
        );
        // Distinct matches render distinctly.
        assert_ne!(
            key.pseudonym(PseudonymClass::Username, "agent-worker"),
            key.pseudonym(PseudonymClass::Username, "other-worker")
        );
        // The class is inside the preimage: the same bytes under
        // different classes render differently.
        assert_ne!(
            key.pseudonym(PseudonymClass::AbsolutePath, "/tmp/x"),
            key.pseudonym(PseudonymClass::Username, "/tmp/x")
        );
        // Twelve lowercase hex digits inside the pinned `ps_<class>_`
        // rendering, for every class — bounded text, never the matched
        // bytes.
        for class in PseudonymClass::ALL {
            let pseudonym = key.pseudonym(class, "irreversibility probe");
            let prefix = format!("ps_{}_", render_token(class));
            assert!(pseudonym.starts_with(&prefix), "{pseudonym}");
            assert_eq!(pseudonym.len(), prefix.len() + 12, "{pseudonym}");
            assert!(
                pseudonym[prefix.len()..]
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
                "{pseudonym} carries 12 lowercase hex digits"
            );
            assert!(!pseudonym.contains("probe"));
        }
    }

    // --- derivation determinism and shape ----------------------------------

    #[test]
    fn derive_is_byte_deterministic_across_runs_and_orders() {
        let first = derive_fixture();
        let second = derive_fixture();
        assert_eq!(first.digest(), second.digest());
        assert_eq!(first.serialized(), second.serialized());

        // The composition is a function of the input *set*: any
        // presentation of the same set derives byte-identical bytes.
        // Occurrence order is permuted, and one variant also reverses
        // the records inside each occurrence.
        let records = fixture_records();
        let orders: [&[usize]; 4] = [&[0, 1, 2], &[2, 1, 0], &[1, 0, 2], &[2, 0, 1]];
        for (variant, order) in orders.iter().enumerate() {
            let mut groups: Vec<Vec<SourceRecord<'_>>> = order
                .iter()
                .map(|index| {
                    let mut group = records[*index].clone();
                    if variant % 2 == 1 {
                        group.reverse();
                    }
                    group
                })
                .collect();
            let inputs: Vec<OccurrenceInput<'_>> = groups
                .iter_mut()
                .zip(1u32..)
                .map(|(group, id)| OccurrenceInput {
                    occurrence_id: occurrence_id(id),
                    records: group.as_slice(),
                })
                .collect();
            let episode = DerivedEpisode::derive(&tenant(), &key(), &inputs)
                .expect("permuted fixture derives");
            assert_eq!(
                episode.serialized(),
                first.serialized(),
                "variant {variant} derives the same bytes"
            );
        }
    }

    #[test]
    fn provenance_and_records_serialize_in_canonical_order() {
        // Feed the fixture with occurrences in a scrambled order (and
        // one occurrence's records internally reversed): the record's
        // provenance still ascends by occurrence ID and the records
        // still ascend by ordinal.
        let records = fixture_records();
        let mut reversed = records[2].clone();
        reversed.reverse();
        let groups: [&[SourceRecord<'_>]; 3] = [&records[1], &reversed, &records[0]];
        let inputs: Vec<OccurrenceInput<'_>> = groups
            .iter()
            .zip([3u32, 2, 1])
            .map(|(records, id)| OccurrenceInput {
                occurrence_id: occurrence_id(id),
                records,
            })
            .collect();
        let episode = DerivedEpisode::derive(&tenant(), &key(), &inputs).expect("derives");

        let Some(Value::Array(ids)) = episode.record().get("occurrence_ids") else {
            panic!("occurrence_ids is an array");
        };
        let mut ids: Vec<&str> = ids
            .iter()
            .map(|id| match id {
                Value::Text(hex) => hex.as_str(),
                _ => panic!("occurrence id is text"),
            })
            .collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "provenance is ascending");
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "provenance is unique");
        assert_eq!(before, 3);

        let Some(Value::Array(records)) = episode.record().get("records") else {
            panic!("records is an array");
        };
        let ordinals: Vec<i64> = records
            .iter()
            .map(|record| match record {
                Value::Object(fields) => match fields.get("ordinal") {
                    Some(Value::Int(ordinal)) => *ordinal,
                    _ => panic!("record ordinal is an integer"),
                },
                _ => panic!("record is an object"),
            })
            .collect();
        let expected: Vec<i64> = (0..6).collect();
        assert_eq!(ordinals, expected, "records ascend by ordinal");
    }

    #[test]
    fn the_record_is_exactly_the_closed_schema_member_set() {
        let episode = derive_fixture();
        let members: Vec<&str> = episode.record().iter().map(|(name, _)| name).collect();
        assert_eq!(
            members,
            [
                "detector_corpus_digest",
                "episode_digest",
                "episode_version",
                "marker_counts",
                "occurrence_ids",
                "pipeline_id",
                "pipeline_version",
                "pseudonym_counts",
                "pseudonym_key_id",
                "records",
                "tenant_id",
            ],
            "the closed shape is the whole shape"
        );
        assert_eq!(
            episode.record().get("episode_version"),
            Some(&Value::Int(1))
        );
        assert_eq!(
            episode.record().get("pipeline_id"),
            Some(&Value::Text(PIPELINE_ID.to_owned()))
        );
        assert_eq!(
            episode.record().get("pipeline_version"),
            Some(&Value::Text(PIPELINE_VERSION.to_owned()))
        );
        assert_eq!(
            episode.record().get("detector_corpus_digest"),
            Some(&Value::Text(RedactionCorpus::pinned().digest()))
        );

        // Both censuses name every class explicitly, even at zero.
        for member in ["marker_counts", "pseudonym_counts"] {
            let Some(Value::Object(census)) = episode.record().get(member) else {
                panic!("{member} is an object");
            };
            let names: Vec<&str> = census.iter().map(|(name, _)| name).collect();
            assert_eq!(names.len(), 5, "{member} names every class: {names:?}");
        }
    }

    #[test]
    fn a_clean_scan_census_is_explicit_zeros() {
        let inputs = [one_input(1, &[record(0, "nothing here but us processors")])];
        let episode = DerivedEpisode::derive(&tenant(), &key(), &inputs).expect("derives");
        for member in ["marker_counts", "pseudonym_counts"] {
            let Some(Value::Object(census)) = episode.record().get(member) else {
                panic!("{member} is an object");
            };
            for (_, count) in census.iter() {
                assert_eq!(count, &Value::Int(0), "{member} explicit zero");
            }
        }
    }

    #[test]
    fn census_sums_count_every_match_of_the_set() {
        let episode = derive_fixture();
        let Some(Value::Object(pseudonyms)) = episode.record().get("pseudonym_counts") else {
            panic!("pseudonym_counts is an object");
        };
        let Some(Value::Object(markers)) = episode.record().get("marker_counts") else {
            panic!("marker_counts is an object");
        };
        // The fixture pseudonymizes one mention, one hostname, one path,
        // one email, and one IP across its records; the pinned
        // credential detector claims the fixture token.
        assert_eq!(census_sum(pseudonyms), 5, "every pseudonym counted once");
        assert_eq!(census_sum(markers), 1, "the pinned credential counted once");
    }

    #[test]
    fn the_digest_is_self_verifying_from_the_serialized_bytes() {
        let episode = derive_fixture();
        let bytes = episode.serialized();
        assert_eq!(bytes.last(), Some(&b'\n'), "exactly one trailing LF");
        assert_eq!(
            &bytes[..bytes.len() - 1],
            &Value::Object(episode.record().clone()).canonical_bytes(),
            "the stored bytes are the canonical bytes plus the LF"
        );

        // An auditor's recompute: digest the canonical bytes of the
        // record with the digest member removed, under the pinned
        // label — it must name the record's own digest member.
        let mut stripped = episode.record().clone();
        assert!(stripped.remove("episode_digest").is_some());
        let mut frame = FrameBuilder::new(DIGEST_LABEL);
        frame.push_bytes(&Value::Object(stripped).canonical_bytes());
        assert_eq!(sha256::encode_hex(&frame.finish()), episode.digest());
    }

    #[test]
    fn the_object_key_follows_the_pinned_derived_layout() {
        let episode = derive_fixture();
        let object_key = episode.object_key();
        let digest = episode.digest();
        let expected = format!(
            "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/derived/redaction/1/episodes/{}/\
             {digest}.json",
            &digest[..2]
        );
        assert_eq!(object_key, expected);
        assert!(object_key.len() <= 512, "the schema's maxLength");
        assert!(!object_key.contains("raw/"), "never a raw namespace");
    }

    // --- tenant separation and rotation ------------------------------------

    #[test]
    fn tenants_with_different_keys_never_share_pseudonym_bytes() {
        let a = key().pseudonym(PseudonymClass::EmailAddress, "worker@internal.example");
        let b = other_key().pseudonym(PseudonymClass::EmailAddress, "worker@internal.example");
        assert_ne!(a, b, "the key scopes the pseudonym space");

        // The same input set under two tenants' keys produces two
        // distinct episodes: different self-IDs, different pseudonym
        // bytes, different digests.
        let tenant_a =
            DerivedEpisode::derive(&tenant(), &key(), &fixture_inputs()).expect("tenant a derives");
        let tenant_b = DerivedEpisode::derive(&tenant(), &other_key(), &fixture_inputs())
            .expect("tenant b derives");
        assert_ne!(tenant_a.digest(), tenant_b.digest());
        assert_ne!(
            tenant_a.record().get("pseudonym_key_id"),
            tenant_b.record().get("pseudonym_key_id")
        );
        let content_of = |episode: &DerivedEpisode| -> String {
            match episode.record().get("records") {
                Some(Value::Array(records)) => records
                    .iter()
                    .filter_map(|record| match record {
                        Value::Object(fields) => match fields.get("content") {
                            Some(Value::Text(text)) => Some(text.clone()),
                            _ => None,
                        },
                        _ => None,
                    })
                    .collect(),
                _ => panic!("records is an array"),
            }
        };
        assert_ne!(content_of(&tenant_a), content_of(&tenant_b));
    }

    #[test]
    fn key_rotation_is_not_transparent() {
        // Rotating a tenant's key changes every pseudonym, hence the
        // episode bytes, hence the digest — the schema's rule that
        // re-derivation under a new key is a new derived corpus.
        let before = derive_fixture();
        let after = DerivedEpisode::derive(&tenant(), &other_key(), &fixture_inputs())
            .expect("rotated derivation");
        assert_ne!(before.digest(), after.digest());
    }

    #[test]
    fn the_tenant_member_separates_identical_derivations() {
        // Two tenants provisioning the same key bytes (a provisioning
        // error, but not a derivation input) still derive distinct
        // episodes: `tenant_id` is a member of the digest preimage.
        let a = DerivedEpisode::derive(&tenant(), &key(), &fixture_inputs()).expect("derives");
        let b =
            DerivedEpisode::derive(&other_tenant(), &key(), &fixture_inputs()).expect("derives");
        assert_ne!(a.digest(), b.digest());
        assert_eq!(a.digest(), derive_fixture().digest());
    }

    // --- fail-closed gaps ---------------------------------------------------

    #[test]
    fn empty_inputs_produce_a_bounded_gap_and_no_episode() {
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &[]),
            Err(EpisodeGap::Empty)
        );
        // An occurrence citing no records contributes nothing to
        // compose: still no episode.
        let inputs = [one_input(1, &[])];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Empty)
        );
        assert_eq!(EpisodeGap::Empty.token(), "empty");
    }

    #[test]
    fn incoherent_provenance_and_ordinals_are_malformed() {
        // Two occurrences claim one identity.
        let inputs = [
            one_input(7, &[record(0, "first")]),
            one_input(7, &[record(1, "second")]),
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Malformed)
        );

        // A duplicated ordinal: not contiguous from zero.
        let records = fixture_records();
        let duplicated = [
            OccurrenceInput {
                occurrence_id: occurrence_id(1),
                records: &records[0],
            },
            OccurrenceInput {
                occurrence_id: occurrence_id(2),
                records: &records[0],
            },
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &duplicated),
            Err(EpisodeGap::Malformed)
        );

        // A missing ordinal: 0, 2 has a hole at 1.
        let holed = [
            one_input(1, &[record(0, "first")]),
            one_input(2, &[record(2, "third")]),
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &holed),
            Err(EpisodeGap::Malformed)
        );
        assert_eq!(EpisodeGap::Malformed.token(), "malformed");
    }

    #[test]
    fn composition_bounds_fail_closed_at_and_past_the_limit() {
        let make = |count: usize| -> Vec<SourceRecord<'static>> {
            (0..count)
                .map(|ordinal| record(ordinal.try_into().expect("ordinal fits"), "ok"))
                .collect()
        };

        // One past the occurrence bound: oversized, before any
        // per-record work.
        let records: &'static [SourceRecord<'static>] =
            Box::leak(make(MAX_EPISODE_OCCURRENCES + 1).into_boxed_slice());
        let inputs: Vec<OccurrenceInput<'_>> = records
            .chunks(1)
            .zip(1u32..)
            .map(|(records, id)| OccurrenceInput {
                occurrence_id: occurrence_id(id),
                records,
            })
            .collect();
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Oversized)
        );

        // One past the record bound across few occurrences: the same
        // gap — the record budget is the episode's size budget.
        let records: &'static [SourceRecord<'static>] =
            Box::leak(make(MAX_EPISODE_RECORDS + 1).into_boxed_slice());
        let (head, tail) = records.split_at(MAX_EPISODE_RECORDS / 2);
        let inputs = [
            OccurrenceInput {
                occurrence_id: occurrence_id(1),
                records: head,
            },
            OccurrenceInput {
                occurrence_id: occurrence_id(2),
                records: tail,
            },
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Oversized)
        );

        // Exactly at the record bound is not oversized: the bound is
        // inclusive, and the derivation succeeds.
        let records: &'static [SourceRecord<'static>] =
            Box::leak(make(MAX_EPISODE_RECORDS).into_boxed_slice());
        let inputs: Vec<OccurrenceInput<'_>> = records
            .chunks(1)
            .zip(1u32..)
            .map(|(records, id)| OccurrenceInput {
                occurrence_id: occurrence_id(id),
                records,
            })
            .collect();
        let episode = DerivedEpisode::derive(&tenant(), &key(), &inputs)
            .expect("the inclusive bound derives");
        let Some(Value::Array(records)) = episode.record().get("records") else {
            panic!("records is an array");
        };
        assert_eq!(records.len(), MAX_EPISODE_RECORDS);
        assert_eq!(EpisodeGap::Oversized.token(), "oversized");
    }

    #[test]
    fn a_failing_record_gaps_at_its_flattened_position() {
        // The third record of the flattened input has an unsupported
        // role; the episode rule is no partial episode, only a gap that
        // names the position and the fault class — never the record.
        let inputs = [
            one_input(1, &[record(0, "fine"), record(1, "also fine")]),
            one_input(
                2,
                &[SourceRecord {
                    role: "robot",
                    ordinal: 2,
                    source_time: None,
                    parent_ordinals: &[],
                    content: "secretive robot content",
                }],
            ),
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Occurrence {
                position: 2,
                gap: RedactionGap::Unsupported,
            })
        );

        // A semantically broken record: a forward parent ordinal.
        let inputs = [
            one_input(1, &[record(0, "fine")]),
            one_input(
                2,
                &[SourceRecord {
                    role: "user",
                    ordinal: 1,
                    source_time: None,
                    parent_ordinals: &[5],
                    content: "points forward",
                }],
            ),
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Occurrence {
                position: 1,
                gap: RedactionGap::Malformed,
            })
        );
        let gap = EpisodeGap::Occurrence {
            position: 0,
            gap: RedactionGap::Unsupported,
        };
        assert_eq!(gap.token(), "occurrence");
    }

    #[test]
    fn processing_and_size_budgets_fail_closed_through_the_gap() {
        // A record past the content budget: the record-level size rule
        // surfaces as the episode-level gap.
        let oversized: &'static str = Box::leak("a".repeat(MAX_CONTENT_BYTES + 1).into_boxed_str());
        let inputs = [
            one_input(1, &[record(0, "fine")]),
            one_input(2, &[record(1, oversized)]),
        ];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Occurrence {
                position: 1,
                gap: RedactionGap::Oversized,
            })
        );

        // A record crafted to exhaust the replacement budget: the
        // pipeline's processing budget fails closed instead of doing
        // unbounded work.
        let exhausting: &'static str =
            Box::leak("10.0.0.7 ".repeat(MAX_REPLACEMENTS + 1).into_boxed_str());
        let inputs = [one_input(1, &[record(0, exhausting)])];
        assert_eq!(
            DerivedEpisode::derive(&tenant(), &key(), &inputs),
            Err(EpisodeGap::Occurrence {
                position: 0,
                gap: RedactionGap::ResourceExhausted,
            })
        );
    }

    #[test]
    fn gaps_are_content_free() {
        // Nothing of the offending input — its bytes, its matched
        // secrets — may ride out on the gap.
        let token = github_token();
        let secret_content: &'static str =
            Box::leak(format!("token {token} leaks").into_boxed_str());
        let inputs = [one_input(
            1,
            &[SourceRecord {
                role: "robot",
                ordinal: 0,
                source_time: None,
                parent_ordinals: &[],
                content: secret_content,
            }],
        )];
        let gap =
            DerivedEpisode::derive(&tenant(), &key(), &inputs).expect_err("unsupported role gaps");
        let rendered = format!("{gap}{gap:?}");
        assert!(rendered.contains("record 0"));
        assert!(!rendered.contains(&token), "no matched bytes on the gap");
        assert!(!rendered.contains(secret_content));
        // The inner redaction gap is reachable as the error source, and
        // it is content-free too.
        let EpisodeGap::Occurrence { gap: inner, .. } = gap else {
            panic!("an occurrence gap");
        };
        assert_eq!(inner.token(), "unsupported");
        assert_eq!(
            std::error::Error::source(&gap).map(<dyn std::error::Error>::to_string),
            Some(inner.to_string())
        );
    }

    // --- nothing removed survives anywhere ----------------------------------

    #[test]
    fn no_removed_bytes_or_reversible_material_reach_the_outputs() {
        let episode = derive_fixture();
        let bytes = episode.serialized();

        // Every source identifier the fixture carried is gone from the
        // canonical bytes — only keyed pseudonyms and markers remain.
        for removed in [
            "@agent-worker",
            "build-runner.internal.example",
            "/build/work/session-chunk.jsonl",
            "worker@internal.example",
            "10.9.8.7",
        ] {
            let needle = removed.as_bytes();
            assert!(
                !bytes.windows(needle.len()).any(|window| window == needle),
                "removed bytes must not survive: {removed}"
            );
        }

        // The reserved names — reversible-map material, governance
        // material, freshness breakers — are absent from the closed
        // shape by construction; pin the security-bearing ones.
        for reserved in [
            "pseudonym_map",
            "redaction_map",
            "reverse_map",
            "removed_content",
            "plaintext",
            "pseudonym_salt",
            "mapping",
            "salt",
            "assessment",
            "approval",
            "classification",
            "labels",
            "producer",
            "produced_at",
            "built_at",
            "run_id",
            "raw_object_key",
            "source_path",
            "blob_key",
            "object_key",
        ] {
            assert!(
                episode.record().get(reserved).is_none(),
                "{reserved} is reserved and never a member"
            );
        }
    }

    #[test]
    fn repeated_identifiers_render_one_stable_pseudonym_without_a_map() {
        let key = key();
        let expected = key.pseudonym(PseudonymClass::EmailAddress, "worker@internal.example");
        let inputs = [one_input(
            1,
            &[record(
                0,
                "mail worker@internal.example then worker@internal.example again",
            )],
        )];
        let episode = DerivedEpisode::derive(&tenant(), &key, &inputs).expect("derives");
        let Some(Value::Array(records)) = episode.record().get("records") else {
            panic!("records is an array");
        };
        let Some(Value::Object(fields)) = records.first() else {
            panic!("record is an object");
        };
        let Some(Value::Text(content)) = fields.get("content") else {
            panic!("content is text");
        };
        assert_eq!(
            content.matches(&expected).count(),
            2,
            "the same bytes render the same pseudonym, no map needed"
        );
        assert!(!content.contains("worker@internal.example"));
    }
}
