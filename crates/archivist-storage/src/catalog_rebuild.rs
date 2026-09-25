// SPDX-License-Identifier: Apache-2.0

//! The deterministic catalog rebuild engine (plan Section 7.10, Phase 10;
//! `archivist catalog rebuild --from-occurrences`): one fail-closed pass
//! over a frozen tenant raw prefix that emits the derived
//! [`usage-summary-v1`](archivist_protocol::usage_summary) rows and the
//! self-verifying checkpoint documents the rebuild resumes from,
//! byte-identically for one raw prefix and pipeline version.
//!
//! # What the engine is
//!
//! The engine composes three provisioned identities and owns no transport
//! of its own (crate boundary rules 3 and 7):
//!
//! - an [`AuditRestoreStore`](crate::audit_restore::AuditRestoreStore) —
//!   the offline audit/restore identity freezes the tenant raw prefix and
//!   reads its occurrences, blobs, and checkpoint documents. Being able to
//!   supply one implies the enumeration and bounded-read authority rebuild
//!   needs; nothing here holds credentials.
//! - a [`DerivedWriteStore`](crate::scoped_write::DerivedWriteStore) — the
//!   derived writer identity, `put+list` on the tenant's `derived/`
//!   namespace and nothing else. Every usage row lands through it at the
//!   content-addressed key the row itself derives.
//! - a [`CatalogWriteStore`](crate::scoped_write::CatalogWriteStore) — the
//!   catalog writer identity, `put+list` on the tenant's
//!   `catalog/checkpoints/` namespace and nothing else. Every checkpoint
//!   lands through it at the content-addressed key the plan freezes:
//!   the checkpoint document's own SHA-256 digest, so a deterministic
//!   rebuild re-putting the same bytes converges on one object.
//!
//! - a [`UsageProjection`] composes the adapter boundary: the projection's
//!   immutable reader version and the per-occurrence reader that turns one
//!   blob's decoded bytes into
//!   [`MessageUsage`](archivist_protocol::usage_summary::MessageUsage)
//!   inputs. Reading harness-specific usage dialects is the adapters' job;
//!   this module never parses transcript content.
//!
//! # Determinism
//!
//! Every emitted byte is a function of the raw prefix, the pinned pipeline
//! identity (`usage`/`1`), the composed projection version, and the
//! policy's checkpoint cadence — no wall-clock, producer, run, or path
//! input exists in anything the engine writes (the usage-summary family's
//! derivation-stability rule). Rows are content-addressed by their own
//! digests, so a row re-derived anywhere is the same bytes at the same
//! key, and the checkpoint's cumulative state (counts, chain digest) is a
//! pure fold over the canonical occurrence order. Two fresh passes over
//! one prefix write identical byte sequences, and a pass interrupted by
//! the policy's window and completed by resumed passes converges to the
//! identical final state and the identical row set — the Phase 10 exit
//! gate, proved by this module's tests.
//!
//! # Checkpoints and resume
//!
//! [`rebuild_pass`] emits a checkpoint document every
//! [`RebuildPolicy::checkpoint_every`] occurrences and once at the end of
//! every pass, through the catalog writer, at
//! [`CatalogCheckpointKey`](crate::scoped_write::CatalogCheckpointKey).
//! A checkpoint is canonical JSON plus one trailing LF, self-verifying
//! under the family digest construction (the digest member is excluded
//! from its own preimage), and carries the cumulative fold state:
//! occurrences processed, attestations observed, the row-denominator
//! tally, the last processed occurrence key, and the running chain digest.
//!
//! Resume is two steps. [`latest_checkpoint`] lists the checkpoint
//! namespace through the catalog writer, reads each listed object once
//! through the audit/restore identity, verifies each object against its
//! own key digest, and picks the furthest in-scope checkpoint
//! deterministically (most occurrences processed, key order breaking
//! ties). [`rebuild_pass`] then validates what it was handed before
//! trusting any of it: the document must parse, verify its own digest,
//! and agree with this pass's tenant, pipeline identity, projection
//! version, and frozen inventory digest — then the canonical cursor is
//! checked by skipping exactly the claimed number of occurrences in
//! canonical order and requiring the last skipped key to equal the
//! checkpoint's. Any other reading — unreadable bytes, foreign scope, a
//! cursor that no longer aligns — is not an error: the pass falls back to
//! a fresh full rebuild and says so in its [`RebuildOutcome::restart`].
//! That convergence is the fail-closed direction: the derived prefix
//! always ends up the deterministic rebuild of the current raw prefix,
//! whatever the prior state claimed. (`latest_checkpoint` itself is the
//! stricter surface: a listed object that is not a verifiable checkpoint
//! fails closed, because stored-state divergence is a fault to surface,
//! not a state to route around.)
//!
//! # Memory shape
//!
//! One occurrence's blob is decoded at a time, whole, through the
//! `zstd-v1` decoder's checksum-verified read-back; a deployment's own
//! size bounds apply, exactly as for any other offline restore read.

use archivist_protocol::derivation::{FrameBuilder, blob_digest};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::usage_summary::{
    HarnessUsageState, MessageUsage, OccurrenceProvenance, PIPELINE_ID, PIPELINE_VERSION,
    USAGE_SUMMARY_VERSION, UnknownReason, UsageSummary,
};
use archivist_protocol::vocabulary::{AdapterId, TenantId, VersionToken};

use crate::audit_restore::{AuditRestoreStore, InventoryKey, InventoryScope};
use crate::catalog_source::{RawCatalogIndex, RawCatalogSource};
use crate::error::{StorageError, StorageErrorKind};
use crate::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedObjectKey, DerivedWriteStore,
};
use crate::zstd_v1::ZstdV1Decoder;

/// The checkpoint document's schema version (`rebuild_checkpoint_version`).
/// A checkpoint declaring any other major is not this format and is never
/// resumed — the pass rebuilds fresh instead of guessing.
pub const REBUILD_CHECKPOINT_VERSION: i64 = 1;

/// The self-verifying digest's domain label, the family's exclusion
/// framing: labeled frame over the document's canonical bytes with the
/// digest member removed. The checkpoint's storage key carries the plain
/// document digest in its place; the two name different things and never
/// substitute for each other.
const CHECKPOINT_DIGEST_LABEL: &str = "catalog-rebuild-checkpoint-v1";

/// The running chain digest's domain label: each processed occurrence
/// advances the chain over the previous chain, the occurrence's canonical
/// key, and the emitted row's digest, so the final chain names the whole
/// rebuilt sequence.
const CHAIN_LABEL: &str = "catalog-rebuild-chain-v1";

const FOREIGN_CHECKPOINT_KEY: &str =
    "a listed catalog checkpoint key is outside the checkpoint grammar";
const TORN_CHECKPOINT: &str = "a listed checkpoint object's bytes do not hash to its own key";
const UNPARSEABLE_CHECKPOINT: &str =
    "a listed checkpoint object does not parse as a checkpoint document";
const ROW_KEY_GRAMMAR: &str = "the derived usage-row key left the scoped writer grammar";

/// Why a listed object refused the rebuild, as
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// with the module's own detail — the deterministic-fault style of the raw
/// source this module consumes.
fn fault(detail: &'static str) -> StorageError {
    StorageError::new(StorageErrorKind::IntegrityConflict, detail)
}

/// The usage reading a rebuild composes: the projection's immutable
/// reader version and the per-occurrence reader itself. The reader
/// receives one occurrence's decoded blob bytes and returns the
/// projection's per-message reading — never partial parse results, never
/// transcript text; the bounded region states are the reader's whole
/// channel (the protocol derivation's contract).
///
/// The engine never parses harness-specific usage dialects; supplying a
/// projection is supplying the adapter boundary.
#[derive(Clone, Debug)]
pub struct UsageProjection<F> {
    version: VersionToken,
    read: F,
}

impl<F> UsageProjection<F>
where
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    /// Compose a projection from its immutable reader version and its
    /// per-occurrence reader.
    #[must_use]
    pub fn new(version: VersionToken, read: F) -> Self {
        Self { version, read }
    }

    /// The immutable version of this projection's usage reader. A changed
    /// reading is a new version, never a silent rewrite — the version is
    /// part of every checkpoint's scope and every derived row's
    /// provenance.
    #[must_use]
    pub const fn version(&self) -> &VersionToken {
        &self.version
    }

    /// Read one occurrence's decoded blob bytes into the projection's
    /// per-message usage reading.
    #[must_use]
    pub fn project(&self, adapter: &AdapterId, plaintext: &[u8]) -> Vec<MessageUsage> {
        (self.read)(adapter, plaintext)
    }
}

/// One pass's cadence and budget.
///
/// `checkpoint_every` bounds how much work a crash can lose, counted in
/// processed occurrences; it must be at least one. `window`, when set,
/// bounds the occurrences one pass processes before emitting its
/// checkpoint and returning — the internal-loop Deployment's per-
/// iteration budget, and the seam the determinism proofs use to walk a
/// rebuild in interrupted steps.
#[derive(Clone, Copy, Debug)]
pub struct RebuildPolicy {
    /// Emit a checkpoint after this many processed occurrences.
    pub checkpoint_every: u64,
    /// Stop the pass after this many occurrences, resumable; unbounded
    /// when `None`.
    pub window: Option<u64>,
}

impl RebuildPolicy {
    /// Validate the policy's bounds: a cadence below one could pass a
    /// whole rebuild without ever writing resume state, and a zero window
    /// is a pass that processes nothing by construction.
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
    /// when `checkpoint_every` is zero or the window is `Some(0)`.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.checkpoint_every == 0 {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                "the rebuild checkpoint cadence must be at least one occurrence",
            ));
        }
        if self.window == Some(0) {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                "the rebuild pass window must be at least one occurrence",
            ));
        }
        Ok(())
    }
}

/// Why the pass started from scratch or from a checkpoint, as the closed
/// token the report carries. Every reason except
/// [`RestartReason::Resumed`] is a fresh full rebuild; the reason is
/// evidence, not a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartReason {
    /// No checkpoint was offered.
    Fresh,
    /// The offered checkpoint validated and the pass continued from it.
    Resumed,
    /// The offered bytes are not a verifiable checkpoint document.
    CheckpointUnreadable,
    /// The checkpoint verifies but names a different tenant, pipeline
    /// identity, projection version, or raw prefix.
    CheckpointScopeMismatch,
    /// The checkpoint verifies and matches scope, but its canonical
    /// cursor no longer aligns with the prefix's canonical order.
    CheckpointCursorMisaligned,
}

impl RestartReason {
    /// The wire token the report carries.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Resumed => "resumed",
            Self::CheckpointUnreadable => "checkpoint_unreadable",
            Self::CheckpointScopeMismatch => "checkpoint_scope_mismatch",
            Self::CheckpointCursorMisaligned => "checkpoint_cursor_misaligned",
        }
    }
}

/// The per-row denominator tally, cumulative across resumed passes. The
/// four states are the usage-summary family's closed denominator set:
/// every occurrence contributes exactly one row and exactly one state,
/// so the tally's sum is the rows emitted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RowTally {
    measured: u64,
    absent: u64,
    malformed: u64,
    unsupported: u64,
}

impl RowTally {
    /// Advance the tally by one row of this state.
    pub(crate) fn advance(&mut self, state: HarnessUsageState) {
        match state {
            HarnessUsageState::Measured => self.measured += 1,
            HarnessUsageState::Unknown(reason) => match reason {
                UnknownReason::Absent => self.absent += 1,
                UnknownReason::Malformed => self.malformed += 1,
                UnknownReason::Unsupported => self.unsupported += 1,
            },
        }
    }

    /// Rows whose denominator is a measured sum.
    #[must_use]
    pub const fn measured(&self) -> u64 {
        self.measured
    }

    /// Rows whose source carried no usage region at all.
    #[must_use]
    pub const fn absent(&self) -> u64 {
        self.absent
    }

    /// Rows whose source usage was present but unparseable.
    #[must_use]
    pub const fn malformed(&self) -> u64 {
        self.malformed
    }

    /// Rows whose source usage parses but is unvouchable under the pinned
    /// projection.
    #[must_use]
    pub const fn unsupported(&self) -> u64 {
        self.unsupported
    }

    /// The tally as the checkpoint's `row_states` member: all four
    /// counts, always present — a zero is an observation here, not an
    /// absence.
    pub(crate) fn record(&self) -> Object {
        let mut states = Object::new();
        states.set("measured", Value::Int(wire_count(self.measured)));
        states.set("absent", Value::Int(wire_count(self.absent)));
        states.set("malformed", Value::Int(wire_count(self.malformed)));
        states.set("unsupported", Value::Int(wire_count(self.unsupported)));
        states
    }

    /// Read the tally out of a checkpoint's `row_states` member.
    fn parse(states: &Object) -> Option<Self> {
        Some(Self {
            measured: u63_of(states, "measured")?,
            absent: u63_of(states, "absent")?,
            malformed: u63_of(states, "malformed")?,
            unsupported: u63_of(states, "unsupported")?,
        })
    }

    /// The rows the tally accounts for: the sum of the four states.
    fn total(self) -> u64 {
        self.measured + self.absent + self.malformed + self.unsupported
    }
}

/// One completed pass: the fold state the report and the next pass
/// consume. Everything on the outcome is cumulative rebuild state, not
/// run state — a resumed sequence of passes converges to the same final
/// outcome as one uninterrupted pass over the same prefix.
#[derive(Clone, Debug)]
pub struct RebuildOutcome {
    restart: RestartReason,
    occurrences_total: u64,
    occurrences_this_pass: u64,
    attestations_observed: u64,
    row_states: RowTally,
    chain_digest: String,
    checkpoint_digest: String,
    checkpoint_key: String,
    checkpoint_bytes: Vec<u8>,
    complete: bool,
    inventory_digest: String,
}

impl RebuildOutcome {
    /// Why this pass started fresh or resumed.
    #[must_use]
    pub const fn restart(&self) -> RestartReason {
        self.restart
    }

    /// The occurrences in the prefix this rebuild covers — the resumed
    /// count plus everything not yet processed when the pass opened.
    #[must_use]
    pub const fn occurrences_total(&self) -> u64 {
        self.occurrences_total
    }

    /// Occurrences this pass processed itself (excluding resumed ones).
    #[must_use]
    pub const fn occurrences_this_pass(&self) -> u64 {
        self.occurrences_this_pass
    }

    /// Upload attestations observed across the whole rebuild so far.
    #[must_use]
    pub const fn attestations_observed(&self) -> u64 {
        self.attestations_observed
    }

    /// The cumulative per-row denominator tally.
    #[must_use]
    pub const fn row_states(&self) -> &RowTally {
        &self.row_states
    }

    /// The running chain digest after the last processed occurrence: the
    /// whole rebuilt sequence, folded.
    #[must_use]
    pub fn chain_digest(&self) -> &str {
        &self.chain_digest
    }

    /// The final checkpoint's self-verifying digest (the labeled member
    /// inside the document, not the storage key's plain digest).
    #[must_use]
    pub fn checkpoint_digest(&self) -> &str {
        &self.checkpoint_digest
    }

    /// The content-addressed key the final checkpoint was written under.
    #[must_use]
    pub fn checkpoint_key(&self) -> &str {
        &self.checkpoint_key
    }

    /// The final checkpoint's exact bytes, as written to
    /// [`Self::checkpoint_key`] — the next pass's resume input.
    #[must_use]
    pub fn checkpoint_bytes(&self) -> &[u8] {
        &self.checkpoint_bytes
    }

    /// Whether the pass exhausted the prefix (`false` when the policy's
    /// window stopped it; resume from [`Self::checkpoint_bytes`]
    /// continues the rebuild).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Render the content-free result document for the completed state.
    ///
    /// The document contains only cumulative state. In particular, it does
    /// not expose whether that state arrived in one pass or through the
    /// internal loop, so a one-shot and a resumed rebuild of one frozen raw
    /// prefix have the same canonical result bytes.
    #[must_use]
    pub fn result_document(&self, tenant: &TenantId, projection_version: &VersionToken) -> Object {
        let mut document = Object::new();
        document.set(
            "catalog_rebuild_version",
            Value::Int(REBUILD_CHECKPOINT_VERSION),
        );
        document.set("pipeline_id", Value::Text(PIPELINE_ID.to_owned()));
        document.set("pipeline_version", Value::Text(PIPELINE_VERSION.to_owned()));
        document.set("usage_summary_version", Value::Int(USAGE_SUMMARY_VERSION));
        document.set(
            "usage_projection_version",
            Value::Text(projection_version.as_str().to_owned()),
        );
        document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
        document.set(
            "inventory_digest",
            Value::Text(self.inventory_digest.clone()),
        );
        document.set(
            "occurrences_total",
            Value::Int(wire_count(self.occurrences_total)),
        );
        document.set(
            "attestations_observed",
            Value::Int(wire_count(self.attestations_observed)),
        );
        document.set("row_states", Value::Object(self.row_states.record()));
        document.set("chain_digest", Value::Text(self.chain_digest.clone()));
        document.set(
            "checkpoint_digest",
            Value::Text(self.checkpoint_digest.clone()),
        );
        document.set("checkpoint_key", Value::Text(self.checkpoint_key.clone()));
        document.set("complete", Value::Bool(self.complete));
        document
    }
}

/// Read back the furthest usable checkpoint of `tenant`'s usage rebuild
/// from the checkpoint namespace: list through the catalog writer, read
/// each listed object once through the audit/restore identity, verify it
/// against its own key digest, and pick the in-scope document with the
/// most occurrences processed (key order breaking ties). The internal
/// loop's and the one-shot command's resume seam: hand the returned bytes
/// to [`rebuild_pass`] as its resume checkpoint.
///
/// A listed object that is not a verifiable checkpoint of this pipeline
/// is either skipped (a well-formed document of another pipeline or
/// projection version — the checkpoint namespace is shared across
/// pipelines) or fails the read closed (a torn or fabricated object,
/// a key outside the grammar — stored-state divergence is a fault to
/// surface, exactly the raw source's discipline).
///
/// # Errors
/// The store's and the writer's own failures, and
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// for a listed object that is outside the checkpoint grammar, does not
/// hash to its own key, or does not parse as a checkpoint document.
pub async fn latest_checkpoint<S, C, F>(
    audit: &S,
    catalog: &C,
    projection: &UsageProjection<F>,
    tenant: &TenantId,
) -> Result<Option<Vec<u8>>, StorageError>
where
    S: AuditRestoreStore + ?Sized,
    C: CatalogWriteStore + ?Sized,
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    let keys = catalog
        .list_checkpoints(&CatalogListPrefix::root(tenant))
        .await?;
    let mut best: Option<(u64, String)> = None;
    let mut picked: Option<Vec<u8>> = None;
    for key in &keys {
        let parsed = CatalogCheckpointKey::parse(key).map_err(|_| fault(FOREIGN_CHECKPOINT_KEY))?;
        let body = audit
            .read_object(&InventoryKey::parse(key).map_err(|_| fault(FOREIGN_CHECKPOINT_KEY))?)
            .await?;
        let bytes = body.bytes();
        // The key names the bytes (the plan's plain document digest): a
        // listed object whose content no longer hashes to its own key is
        // a torn or fabricated write, never a resume point.
        if parsed.checkpoint() != &blob_digest(bytes) {
            return Err(fault(TORN_CHECKPOINT));
        }
        let Some(checkpoint) = parse_checkpoint(bytes) else {
            return Err(fault(UNPARSEABLE_CHECKPOINT));
        };
        // The checkpoint namespace is one pipeline-blind prefix: a
        // document of another pipeline, another projection version, or
        // (defensively) another tenant is simply not this rebuild's
        // resume state.
        if checkpoint.tenant != *tenant
            || checkpoint.pipeline_id != PIPELINE_ID
            || checkpoint.pipeline_version != PIPELINE_VERSION
            || checkpoint.projection_version != projection.version().as_str()
        {
            continue;
        }
        let better = match &best {
            None => true,
            Some((processed, best_key)) => {
                checkpoint.processed > *processed
                    || (checkpoint.processed == *processed && key.as_str() > best_key.as_str())
            }
        };
        if better {
            best = Some((checkpoint.processed, key.clone()));
            picked = Some(bytes.to_vec());
        }
    }
    Ok(picked)
}

/// Run one rebuild pass over the tenant's raw prefix: freeze the prefix,
/// validate and resume from the offered checkpoint when it deserves
/// trust, then emit one usage row per occurrence and the pass's
/// checkpoints, all through the provisioned identities.
///
/// The pass fails closed on every source fault — the same
/// deterministic-fault discipline the raw source itself documents — and
/// on a failed put; a failed pass leaves the last landed checkpoint as
/// the next pass's resume point. A checkpoint that fails validation is
/// never an error: the pass rebuilds fresh and names the reason.
///
/// # Errors
/// The store's own failures while freezing, reading, or validating the
/// prefix (fail-closed, deterministic for one prefix), and the writers'
/// failures while putting a row or checkpoint.
#[allow(clippy::too_many_lines)]
pub async fn rebuild_pass<S, W, C, F>(
    audit: &S,
    derived: &W,
    catalog: &C,
    projection: &UsageProjection<F>,
    tenant: &TenantId,
    policy: RebuildPolicy,
    resume_checkpoint: Option<&[u8]>,
) -> Result<RebuildOutcome, StorageError>
where
    S: AuditRestoreStore + ?Sized,
    W: DerivedWriteStore + ?Sized,
    C: CatalogWriteStore + ?Sized,
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    policy.validate()?;
    let scope = InventoryScope::TenantRaw(tenant.clone());
    let inventory = audit.freeze_inventory(&scope).await?;
    let index = RawCatalogIndex::new(&inventory)?;
    let inventory_digest = inventory.digest().to_hex();

    // The offered checkpoint earns its trust member by member; anything
    // else converges to a fresh rebuild with the reason recorded.
    let offered = resume_checkpoint.and_then(parse_checkpoint);
    let mut restart = match (resume_checkpoint, offered.as_ref()) {
        (None, _) => RestartReason::Fresh,
        (Some(_), None) => RestartReason::CheckpointUnreadable,
        (Some(_), Some(_)) => RestartReason::CheckpointScopeMismatch,
    };
    let in_scope = offered.as_ref().is_some_and(|checkpoint| {
        checkpoint.tenant == *tenant
            && checkpoint.pipeline_id == PIPELINE_ID
            && checkpoint.pipeline_version == PIPELINE_VERSION
            && checkpoint.projection_version == projection.version().as_str()
            && checkpoint.inventory_digest == inventory_digest
    });
    let mut source = RawCatalogSource::open(audit, &index).await?;
    let mut state = FoldState::genesis(&inventory_digest);
    if let (true, Some(checkpoint)) = (in_scope, offered.as_ref()) {
        // The document verifies and matches scope; only the cursor check
        // below can still turn this into a fresh rebuild.
        restart = RestartReason::CheckpointCursorMisaligned;
        let mut aligned = source.len() as u64 >= checkpoint.processed;
        let mut last_skipped = String::new();
        for _ in 0..checkpoint.processed {
            if let Some(key) = source.skip_next() {
                key.as_str().clone_into(&mut last_skipped);
            } else {
                aligned = false;
                break;
            }
        }
        if aligned && checkpoint.processed > 0 {
            aligned = checkpoint.last_key.as_deref() == Some(last_skipped.as_str());
        }
        if aligned {
            state = FoldState {
                processed: checkpoint.processed,
                attestations: checkpoint.attestations,
                tally: checkpoint.row_states,
                chain: checkpoint.chain.clone(),
                last_key: checkpoint.last_key.clone(),
            };
            restart = RestartReason::Resumed;
        } else {
            // The cursor no longer names this prefix's canonical order.
            // Re-open and rebuild the whole fold from the raw bytes; the
            // content-addressed rows make that convergence safe.
            source = RawCatalogSource::open(audit, &index).await?;
        }
    }

    let occurrences_total = state.processed + source.len() as u64;
    let mut this_pass: u64 = 0;
    let mut since_emit: u64 = 0;
    let mut complete = true;

    while !source.is_empty() {
        if policy.window.is_some_and(|max| this_pass >= max) {
            complete = false;
            break;
        }
        let Some(record) = source.next_occurrence(audit).await? else {
            break;
        };
        let plaintext = decode_blob(record.blob().stored().bytes())?;
        let manifest = record.manifest();
        let messages = projection.project(manifest.adapter_id(), &plaintext);
        let provenance = OccurrenceProvenance {
            tenant_id: tenant.clone(),
            adapter_id: manifest.adapter_id().clone(),
            adapter_projection_version: projection.version().clone(),
            occurrence_id: *manifest.occurrence_id(),
        };
        let row = UsageSummary::derive(&provenance, &messages);
        let row_key =
            DerivedObjectKey::parse(&row.object_key()).map_err(|_| fault(ROW_KEY_GRAMMAR))?;
        derived.put_object(&row_key, &row.serialized()).await?;
        state.chain = chain_advance(&state.chain, manifest.key().as_str(), row.digest());
        state.tally.advance(row.harness_usage_state());
        state.attestations += record.attestations().len() as u64;
        state.processed += 1;
        state.last_key = Some(manifest.key().as_str().to_owned());
        this_pass += 1;
        since_emit += 1;

        if state.processed.is_multiple_of(policy.checkpoint_every) {
            emit_checkpoint(catalog, tenant, projection, &inventory_digest, &state).await?;
            since_emit = 0;
        }
    }

    // The final checkpoint: every pass leaves one behind, so a crash
    // after the last processed occurrence still resumes from a document
    // that names the finished fold. A checkpoint the cadence just wrote
    // is byte-identical to the one this would write — and lands at the
    // same content-addressed key — so the extra put is skipped, not
    // duplicated; a pass that processed nothing still writes the genesis
    // state it proved.
    let (checkpoint_key, checkpoint_digest, checkpoint_bytes) =
        if since_emit > 0 || (state.processed == 0 && restart != RestartReason::Resumed) {
            emit_checkpoint(catalog, tenant, projection, &inventory_digest, &state).await?
        } else {
            settle_checkpoint(tenant, projection, &inventory_digest, &state)
        };
    Ok(RebuildOutcome {
        restart,
        occurrences_total,
        occurrences_this_pass: this_pass,
        attestations_observed: state.attestations,
        row_states: state.tally,
        chain_digest: state.chain,
        checkpoint_digest,
        checkpoint_key,
        checkpoint_bytes,
        complete,
        inventory_digest,
    })
}

/// The fold state one rebuild accumulates, in canonical occurrence order.
#[derive(Clone, Debug)]
struct FoldState {
    processed: u64,
    attestations: u64,
    tally: RowTally,
    chain: String,
    last_key: Option<String>,
}

impl FoldState {
    /// The state a fresh rebuild starts from: the chain's genesis folds
    /// the prefix's inventory digest, so a chain can never be replayed
    /// against a different prefix.
    fn genesis(inventory_digest: &str) -> Self {
        Self {
            processed: 0,
            attestations: 0,
            tally: RowTally::default(),
            chain: chain_genesis(inventory_digest),
            last_key: None,
        }
    }
}

/// Write one checkpoint document through the catalog writer at its
/// content-addressed key, and return that key, the document's
/// self-verifying digest, and its bytes.
async fn emit_checkpoint<C, F>(
    catalog: &C,
    tenant: &TenantId,
    projection: &UsageProjection<F>,
    inventory_digest: &str,
    state: &FoldState,
) -> Result<(String, String, Vec<u8>), StorageError>
where
    C: CatalogWriteStore + ?Sized,
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    let (digest, bytes) = checkpoint_document(tenant, projection, inventory_digest, state);
    let key = CatalogCheckpointKey::new(tenant, &blob_digest(&bytes));
    catalog.put_checkpoint(&key, &bytes).await?;
    Ok((key.as_str().to_owned(), digest, bytes))
}

/// Assemble the pass's final checkpoint without writing it — the cadence
/// already wrote these exact bytes at this exact key, and the outcome
/// still carries them.
fn settle_checkpoint<F>(
    tenant: &TenantId,
    projection: &UsageProjection<F>,
    inventory_digest: &str,
    state: &FoldState,
) -> (String, String, Vec<u8>)
where
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    let (digest, bytes) = checkpoint_document(tenant, projection, inventory_digest, state);
    let key = CatalogCheckpointKey::new(tenant, &blob_digest(&bytes));
    (key.as_str().to_owned(), digest, bytes)
}

/// Assemble, digest, and render one checkpoint document: canonical JSON
/// plus exactly one trailing LF, the family rendering, with the
/// self-verifying digest excluding its own member from the preimage.
fn checkpoint_document<F>(
    tenant: &TenantId,
    projection: &UsageProjection<F>,
    inventory_digest: &str,
    state: &FoldState,
) -> (String, Vec<u8>)
where
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    let mut document = Object::new();
    document.set(
        "rebuild_checkpoint_version",
        Value::Int(REBUILD_CHECKPOINT_VERSION),
    );
    document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    document.set("pipeline_id", Value::Text(PIPELINE_ID.to_owned()));
    document.set("pipeline_version", Value::Text(PIPELINE_VERSION.to_owned()));
    document.set(
        "usage_projection_version",
        Value::Text(projection.version().as_str().to_owned()),
    );
    document.set("usage_summary_version", Value::Int(USAGE_SUMMARY_VERSION));
    document.set("inventory_digest", Value::Text(inventory_digest.to_owned()));
    document.set(
        "occurrences_processed",
        Value::Int(wire_count(state.processed)),
    );
    document.set(
        "attestations_observed",
        Value::Int(wire_count(state.attestations)),
    );
    document.set("row_states", Value::Object(state.tally.record()));
    if let Some(key) = &state.last_key {
        document.set("last_occurrence_key", Value::Text(key.clone()));
    }
    document.set("chain_digest", Value::Text(state.chain.clone()));

    let mut frame = FrameBuilder::new(CHECKPOINT_DIGEST_LABEL);
    frame.push_bytes(&Value::Object(document.clone()).canonical_bytes());
    let digest = sha256::encode_hex(&frame.finish());
    document.set("rebuild_checkpoint_digest", Value::Text(digest.clone()));

    let mut bytes = Value::Object(document).canonical_bytes();
    bytes.push(b'\n');
    (digest, bytes)
}

/// A parsed, digest-verified checkpoint: the fields resume validates and
/// continues from.
#[derive(Clone, Debug)]
struct RebuildCheckpoint {
    tenant: TenantId,
    pipeline_id: String,
    pipeline_version: String,
    projection_version: String,
    inventory_digest: String,
    processed: u64,
    attestations: u64,
    row_states: RowTally,
    last_key: Option<String>,
    chain: String,
}

/// Parse and self-verify offered checkpoint bytes, or `None` when the
/// bytes are not a verifiable document: not canonical JSON plus exactly
/// one trailing LF, wrong version, wrong types, or a digest that does not
/// re-derive from the document's own bytes (VAL-005).
fn parse_checkpoint(bytes: &[u8]) -> Option<RebuildCheckpoint> {
    let (trailer, body) = bytes.split_last()?;
    if *trailer != b'\n' {
        return None;
    }
    // The stored form is exactly the canonical rendering plus the
    // trailer, so re-rendering the parsed document must reproduce the
    // body byte for byte.
    let value = json::parse(body).ok()?;
    let Value::Object(mut object) = value else {
        return None;
    };
    if Value::Object(object.clone()).canonical_bytes() != body {
        return None;
    }
    match object.get("rebuild_checkpoint_version") {
        Some(Value::Int(1)) => {}
        _ => return None,
    }

    let Some(Value::Text(digest)) = object.remove("rebuild_checkpoint_digest") else {
        return None;
    };
    let mut frame = FrameBuilder::new(CHECKPOINT_DIGEST_LABEL);
    frame.push_bytes(&Value::Object(object.clone()).canonical_bytes());
    if sha256::encode_hex(&frame.finish()) != digest {
        return None;
    }

    let tenant = match object.get("tenant_id") {
        Some(Value::Text(text)) => TenantId::parse(text).ok()?,
        _ => return None,
    };
    let processed = u63_of(&object, "occurrences_processed")?;
    let attestations = u63_of(&object, "attestations_observed")?;
    let last_key = match object.get("last_occurrence_key") {
        Some(Value::Text(key)) => Some(key.clone()),
        None => None,
        Some(_) => return None,
    };
    // The cursor is carried exactly when there is a cursor to carry.
    if (processed > 0) != last_key.is_some() {
        return None;
    }
    let row_states = match object.get("row_states") {
        Some(Value::Object(states)) => RowTally::parse(states)?,
        _ => return None,
    };
    // The tally is the denominator of the row count: a document whose
    // own arithmetic disagrees is not a fold state.
    if processed != row_states.total() {
        return None;
    }

    Some(RebuildCheckpoint {
        tenant,
        pipeline_id: text_of(&object, "pipeline_id")?.to_owned(),
        pipeline_version: text_of(&object, "pipeline_version")?.to_owned(),
        projection_version: text_of(&object, "usage_projection_version")?.to_owned(),
        inventory_digest: text_of(&object, "inventory_digest")?.to_owned(),
        processed,
        attestations,
        row_states,
        last_key,
        chain: text_of(&object, "chain_digest")?.to_owned(),
    })
}

/// The only member type a checkpoint identity can carry.
fn text_of<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// Read a `u63` member: a non-negative integer that fits the wire's
/// unsigned count domain.
fn u63_of(object: &Object, name: &str) -> Option<u64> {
    match object.get(name) {
        Some(Value::Int(value)) if *value >= 0 => u64::try_from(*value).ok(),
        _ => None,
    }
}

/// Convert a non-negative protocol count to the JSON integer domain.
/// Counts are bounded by the protocol's signed integer representation.
fn wire_count(value: u64) -> i64 {
    i64::try_from(value).expect("protocol count exceeds the signed integer domain")
}

/// The chain's genesis fold: labels the chain to this exact prefix. The
/// inventory build shares the construction, so its chain digest and the
/// rebuild's stay comparable for one prefix and projection.
pub(crate) fn chain_genesis(inventory_digest: &str) -> String {
    let mut frame = FrameBuilder::new(CHAIN_LABEL);
    frame.push_text("genesis");
    frame.push_text(inventory_digest);
    sha256::encode_hex(&frame.finish())
}

/// Advance the chain over one processed occurrence: previous chain,
/// canonical occurrence key, emitted row digest.
pub(crate) fn chain_advance(previous: &str, occurrence_key: &str, row_digest: &str) -> String {
    let mut frame = FrameBuilder::new(CHAIN_LABEL);
    frame.push_text(previous);
    frame.push_text(occurrence_key);
    frame.push_text(row_digest);
    sha256::encode_hex(&frame.finish())
}

/// Decode one stored blob whole: the `zstd-v1` decoder's checksum-
/// verified read-back over the bytes the source already header-validated.
pub(crate) fn decode_blob(stored: &[u8]) -> Result<Vec<u8>, StorageError> {
    let mut decoder = ZstdV1Decoder::new()?;
    let mut plaintext = Vec::new();
    decoder.update(stored, &mut plaintext)?;
    decoder.finish(&mut plaintext)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::manual_async_fn, clippy::type_complexity)]

    use std::collections::HashMap;
    use std::fmt::Write as _;
    use std::sync::Mutex;

    use archivist_protocol::derivation::{
        FrameBuilder, attestation_id, blob_digest, occurrence_id,
    };
    use archivist_protocol::json::{self, Object, Value};
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::sha256;
    use archivist_protocol::usage_summary::{MessageUsage, SourceUsageCounts, UsageRegion};
    use archivist_protocol::vocabulary::{
        AdapterId, ArtifactHash, ClientId, GenerationId, HarnessId, RangeKind, RequestId,
        SessionHash, StorageProfile, TenantId, Timestamp, VersionToken,
    };

    use super::super::audit_restore::{
        AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryEntry, InventoryKey,
        InventoryPage, InventoryScope, ObjectBody, ObjectMetadata,
    };
    use super::super::blob::BlobEncoder;
    use super::super::error::{StorageError, StorageErrorKind};
    use super::super::metadata::Observation;
    use super::super::scoped_write::{
        CatalogCheckpointKey, CatalogListPrefix, CatalogWriteStore, DerivedListPrefix,
        DerivedObjectKey, DerivedWriteStore,
    };
    use super::super::zstd_v1::ZstdV1Encoder;
    use super::{
        RebuildOutcome, RebuildPolicy, RestartReason, UsageProjection,
        blob_digest as document_digest, latest_checkpoint, rebuild_pass,
    };

    /// The conformance corpus's tenant (the provenance bundle's own).
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    /// When the fixtures were observed (arbitrary, fixture-only).
    const OBSERVED: &str = "2026-09-13T12:00:00Z";
    /// The test projection's immutable reader version.
    const PROJECTION_VERSION: &str = "usage-fixture-1";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).unwrap()
    }

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED).unwrap()
    }

    // ---- The synthetic corpus: real occurrences with real payloads ----

    /// A committed bundle document as a member map: the occurrence (or
    /// attestation) template every synthetic fixture patches. The
    /// provenance members are used as-is — they already validate — while
    /// the payload-derived members are re-derived per fixture.
    fn bundle_doc(rel: &str) -> Object {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/examples/provenance");
        let bytes = std::fs::read(root.join(rel))
            .unwrap_or_else(|e| panic!("committed bundle document {rel}: {e}"));
        match json::parse(&bytes).expect("bundle document parses") {
            Value::Object(object) => object,
            _ => panic!("bundle document is an object"),
        }
    }

    fn text_member<'a>(object: &'a Object, name: &str) -> &'a str {
        match object.get(name) {
            Some(Value::Text(text)) => text.as_str(),
            other => panic!("template member {name} is a string, got {other:?}"),
        }
    }

    fn int_member(object: &Object, name: &str) -> i64 {
        match object.get(name) {
            Some(Value::Int(value)) => *value,
            other => panic!("template member {name} is an integer, got {other:?}"),
        }
    }

    /// Render a document map in canonical form plus exactly one trailing
    /// LF — the stored form of every raw object.
    fn render(document: &Object) -> Vec<u8> {
        let mut bytes = Value::Object(document.clone()).canonical_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// One synthetic occurrence's transcript payload: one JSONL line
    /// naming its model and (optionally) a usage region, exactly the shape
    /// the test projection reads. This is the only text that ever reaches
    /// a projection; the engine's own code paths never look inside. The
    /// fixture id rides in the line so distinct fixtures have distinct
    /// payloads and therefore distinct blob digests.
    fn payload(id: &str, model: Option<&str>, usage: Option<&str>) -> Vec<u8> {
        let mut line = format!("{{\"note\":\"{id}\",\"role\":\"assistant\"");
        if let Some(model) = model {
            let _ = write!(line, ",\"model_id\":\"{model}\"");
        }
        if let Some(usage) = usage {
            let _ = write!(line, ",\"usage\":{usage}");
        }
        line.push('}');
        let mut bytes = line.into_bytes();
        bytes.push(b'\n');
        bytes
    }

    /// The test projection's one measured usage shape.
    const MEASURED: &str = "{\"input_tokens\":11,\"output_tokens\":7,\
         \"cache_read_input_tokens\":3,\"cache_creation\":{\"\
         ephemeral_5m_input_tokens\":5,\"ephemeral_1h_input_tokens\":0},\
         \"reasoning_tokens\":0}";

    /// A real `zstd-v1` frame over a payload, produced by the codec the
    /// stored form is pinned to.
    fn stored_frame(plaintext: &[u8]) -> Vec<u8> {
        let mut encoder =
            ZstdV1Encoder::new(u64::try_from(plaintext.len()).expect("fixture under u64"))
                .expect("fixture encoder");
        let mut stored = Vec::new();
        encoder
            .update(plaintext, &mut stored)
            .expect("fixture encode");
        encoder.finish(&mut stored).expect("fixture encode finish");
        stored
    }

    /// One occurrence's three derived keys and stored documents, with all
    /// self-verifying identities re-derived exactly the way the ingest
    /// derivations define them, so the raw source's validation accepts the
    /// object set.
    struct Fixture {
        occurrence_key: OccurrenceObjectKey,
        occurrence: Vec<u8>,
        attestation_key: AttestationObjectKey,
        attestation: Vec<u8>,
        blob_key: BlobObjectKey,
        blob: Vec<u8>,
    }

    /// Build one occurrence fixture over `plaintext`: the payload-derived
    /// identity members are re-derived from the real bytes and patched
    /// into the committed template; everything else is the bundle's own
    /// validated provenance.
    fn fixture_from(id: &str, plaintext: &[u8]) -> Fixture {
        let _ = id;
        let template = bundle_doc("occurrences/direct-upload-and-relay-source.json");
        let blob = stored_frame(plaintext);
        let digest = blob_digest(plaintext);

        let tenant = tenant();
        let client = ClientId::parse(text_member(&template, "origin_client_id")).unwrap();
        let harness = HarnessId::parse(text_member(&template, "harness")).unwrap();
        let session = SessionHash::parse(text_member(&template, "session_hash")).unwrap();
        let artifact = ArtifactHash::parse(text_member(&template, "artifact_hash")).unwrap();
        let generation = GenerationId::parse(text_member(&template, "generation")).unwrap();
        let range_kind = RangeKind::parse(text_member(&template, "range_kind")).unwrap();
        let range_start = u64::try_from(int_member(&template, "range_start")).unwrap();
        let range_end = u64::try_from(plaintext.len()).expect("fixture under u64");

        let occurrence = occurrence_id(
            &session,
            &artifact,
            &generation,
            range_kind,
            range_start,
            range_end,
            &digest,
        );
        let occurrence_key =
            OccurrenceObjectKey::new(&tenant, &client, &harness, &session, &occurrence);
        let blob_key = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &digest);

        let mut document = template.clone();
        document.set("blob_digest", Value::Text(digest.to_hex()));
        document.set(
            "range_end",
            Value::Int(i64::try_from(range_end).expect("fixture under i64")),
        );
        document.set("occurrence_id", Value::Text(occurrence.to_hex()));
        let occurrence_bytes = render(&document);

        // One upload attestation per occurrence, re-targeted and
        // re-derived the same way.
        let mut attestation = bundle_doc("attestations/origin-direct-first-request.json");
        let uploader = ClientId::parse(text_member(&attestation, "uploader_client_id")).unwrap();
        let request = RequestId::parse(text_member(&attestation, "request_id")).unwrap();
        let attestation_id = attestation_id(&occurrence, &uploader, &request);
        attestation.set("occurrence_id", Value::Text(occurrence.to_hex()));
        attestation.set("attestation_id", Value::Text(attestation_id.to_hex()));
        let attestation_bytes = render(&attestation);
        let attestation_key = AttestationObjectKey::new(&tenant, &occurrence, &attestation_id);

        Fixture {
            occurrence_key,
            occurrence: occurrence_bytes,
            attestation_key,
            attestation: attestation_bytes,
            blob_key,
            blob,
        }
    }

    /// A fixture whose payload carries the given usage shape.
    fn fixture(id: &str, model: Option<&str>, usage: Option<&str>) -> Fixture {
        fixture_from(id, &payload(id, model, usage))
    }

    /// The corpus: three occurrences of the one committed provenance with
    /// distinct payloads and mixed usage states — one measured, one
    /// absent, one malformed.
    fn fixtures() -> Vec<Fixture> {
        vec![
            fixture("one", Some("claude-sonnet-4"), Some(MEASURED)),
            fixture("two", Some("claude-sonnet-4"), None),
            fixture(
                "three",
                Some("claude-haiku-4"),
                Some("{\"input_tokens\":1}"),
            ),
        ]
    }

    /// The frozen prefix over `fixtures`, frozen through the real freeze
    /// contract across two pages.
    fn freeze(fixtures: &[Fixture]) -> FrozenInventory {
        let scope = InventoryScope::TenantRaw(tenant());
        let mut entries: Vec<(&str, u64)> = Vec::new();
        for fixture in fixtures {
            entries.push((
                fixture.occurrence_key.as_str(),
                u64::try_from(fixture.occurrence.len()).unwrap(),
            ));
            entries.push((
                fixture.attestation_key.as_str(),
                u64::try_from(fixture.attestation.len()).unwrap(),
            ));
            entries.push((
                fixture.blob_key.as_str(),
                u64::try_from(fixture.blob.len()).unwrap(),
            ));
        }
        entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if entries.is_empty() {
            return FrozenInventory::from_pages(
                &scope,
                vec![Ok(InventoryPage::new(Vec::new(), None))],
            )
            .unwrap();
        }
        let page = |slice: &[(&str, u64)], token: Option<&str>| {
            InventoryPage::new(
                slice
                    .iter()
                    .map(|(key, size)| {
                        InventoryEntry::new(
                            InventoryKey::parse(key).expect("grammatical fixture key"),
                            *size,
                            Observation::new(None, None, observed_at()),
                        )
                    })
                    .collect(),
                token.map(ContinuationToken::parse).transpose().unwrap(),
            )
        };
        let mid = entries.len().div_ceil(2);
        FrozenInventory::from_pages(
            &scope,
            vec![
                Ok(page(&entries[..mid], Some("next-page"))),
                Ok(page(&entries[mid..], None)),
            ],
        )
        .unwrap()
    }

    // ---- The mock identities ----

    /// A no-dependency in-memory audit/restore store, the
    /// catalog-source-module mock pattern — carrying its own frozen
    /// inventory, since the engine freezes through the store. Doubles as
    /// the object store the writers "persist" into, so the resume seam can
    /// read checkpoints back.
    struct MockStore {
        objects: Mutex<HashMap<String, Vec<u8>>>,
        inventory: FrozenInventory,
    }

    impl MockStore {
        fn with(fixtures: &[Fixture]) -> Self {
            let inventory = freeze(fixtures);
            let mut objects = HashMap::new();
            for fixture in fixtures {
                objects.insert(
                    fixture.occurrence_key.as_str().to_owned(),
                    fixture.occurrence.clone(),
                );
                objects.insert(
                    fixture.attestation_key.as_str().to_owned(),
                    fixture.attestation.clone(),
                );
                objects.insert(fixture.blob_key.as_str().to_owned(), fixture.blob.clone());
            }
            Self {
                objects: Mutex::new(objects),
                inventory,
            }
        }

        /// Land objects the writers "persisted", the way a backend would
        /// have them readable on the next run.
        fn absorb(&self, objects: &[(String, Vec<u8>)]) {
            let mut store = self.objects.lock().expect("mock lock");
            for (key, bytes) in objects {
                store.insert(key.clone(), bytes.clone());
            }
        }

        fn insert(&self, key: &str, bytes: &[u8]) {
            self.objects
                .lock()
                .expect("mock lock")
                .insert(key.to_owned(), bytes.to_vec());
        }
    }

    impl AuditRestoreStore for MockStore {
        async fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> Result<InventoryPage, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }

        async fn freeze_inventory(
            &self,
            scope: &InventoryScope,
        ) -> Result<FrozenInventory, StorageError> {
            if matches!(scope, InventoryScope::TenantRaw(t) if t == &tenant()) {
                Ok(self.inventory.clone())
            } else {
                Err(StorageError::of_kind(StorageErrorKind::ScopeViolation))
            }
        }

        async fn inspect_object(&self, key: &InventoryKey) -> Result<ObjectMetadata, StorageError> {
            let objects = self.objects.lock().expect("mock lock");
            match objects.get(key.as_str()) {
                Some(bytes) => Ok(ObjectMetadata::new(
                    bytes.len() as u64,
                    Observation::new(None, None, observed_at()),
                )),
                None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
            }
        }

        async fn read_object(&self, key: &InventoryKey) -> Result<ObjectBody, StorageError> {
            let objects = self.objects.lock().expect("mock lock");
            match objects.get(key.as_str()) {
                Some(bytes) => Ok(ObjectBody::new(
                    bytes.clone(),
                    Observation::new(None, None, observed_at()),
                )),
                None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
            }
        }
    }

    /// The derived writer's mock: records every put in order — the row
    /// log the determinism proofs compare.
    #[derive(Default)]
    struct MockDerived {
        puts: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockDerived {
        fn log(&self) -> Vec<(String, Vec<u8>)> {
            self.puts.lock().expect("mock lock").clone()
        }
    }

    impl DerivedWriteStore for MockDerived {
        fn put_object(
            &self,
            key: &DerivedObjectKey,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            self.puts
                .lock()
                .expect("mock lock")
                .push((key.as_str().to_owned(), bytes.to_vec()));
            async { Ok(()) }
        }

        fn list_objects(
            &self,
            _prefix: &DerivedListPrefix,
        ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
            async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
        }
    }

    /// The catalog writer's mock: records every checkpoint put in order,
    /// and can be seeded with one foreign listing.
    #[derive(Default)]
    struct MockCatalog {
        puts: Mutex<Vec<(String, Vec<u8>)>>,
        foreign: Mutex<Vec<String>>,
    }

    impl MockCatalog {
        fn log(&self) -> Vec<(String, Vec<u8>)> {
            self.puts.lock().expect("mock lock").clone()
        }

        fn objects(&self) -> Vec<(String, Vec<u8>)> {
            self.puts.lock().expect("mock lock").clone()
        }

        /// List one extra key that was never put through the writer.
        fn list_foreign(&self, key: &str) {
            self.foreign.lock().expect("mock lock").push(key.to_owned());
        }
    }

    impl CatalogWriteStore for MockCatalog {
        fn put_checkpoint(
            &self,
            key: &CatalogCheckpointKey,
            bytes: &[u8],
        ) -> impl Future<Output = Result<(), StorageError>> + Send {
            self.puts
                .lock()
                .expect("mock lock")
                .push((key.as_str().to_owned(), bytes.to_vec()));
            async { Ok(()) }
        }

        fn list_checkpoints(
            &self,
            _prefix: &CatalogListPrefix,
        ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
            let mut keys: Vec<String> = self
                .puts
                .lock()
                .expect("mock lock")
                .iter()
                .map(|(key, _)| key.clone())
                .collect();
            keys.extend(self.foreign.lock().expect("mock lock").iter().cloned());
            keys.sort();
            async move { Ok(keys) }
        }
    }

    // ---- The test projection: a real bounded reader over the fixture shape ----

    /// The fixture projection: parse each JSONL line's `usage` region into
    /// the protocol's normalized reading. Present-but-unparseable regions
    /// are `Malformed`; a line without a usage region is `Absent`. This
    /// mirrors the adapter projections' contract at fixture scale.
    fn read_usage(adapter: &AdapterId, plaintext: &[u8]) -> Vec<MessageUsage> {
        let _ = adapter;
        let mut messages = Vec::new();
        for line in plaintext.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            let fields = match json::parse(line) {
                Ok(Value::Object(object)) => Some(object),
                _ => None,
            };
            let region = match &fields {
                Some(object) => match object.get("usage") {
                    None => UsageRegion::Absent,
                    Some(Value::Object(usage)) => match read_counts(usage) {
                        Some(counts) => UsageRegion::Measured(counts),
                        None => UsageRegion::Malformed,
                    },
                    Some(_) => UsageRegion::Malformed,
                },
                None => UsageRegion::Malformed,
            };
            let model = fields
                .as_ref()
                .and_then(|object| match object.get("model_id") {
                    Some(Value::Text(model)) => Some(model.clone()),
                    _ => None,
                });
            messages.push(MessageUsage {
                model_id: model,
                service_tier: None,
                region,
            });
        }
        messages
    }

    /// Read the fixture's four bounded axes; any missing or mistyped axis
    /// refuses the region.
    fn read_counts(usage: &Object) -> Option<SourceUsageCounts> {
        let int_of = |object: &Object, name: &str| -> Option<u64> {
            match object.get(name) {
                Some(Value::Int(value)) if *value >= 0 => u64::try_from(*value).ok(),
                _ => None,
            }
        };
        let Some(Value::Object(creation)) = usage.get("cache_creation") else {
            return None;
        };
        Some(SourceUsageCounts {
            input_tokens: int_of(usage, "input_tokens")?,
            output_tokens: int_of(usage, "output_tokens")?,
            cache_read_tokens: int_of(usage, "cache_read_input_tokens")?,
            cache_creation_5m: int_of(creation, "ephemeral_5m_input_tokens")?,
            cache_creation_1h: int_of(creation, "ephemeral_1h_input_tokens")?,
            reasoning_tokens: int_of(usage, "reasoning_tokens")?,
        })
    }

    fn projection() -> UsageProjection<fn(&AdapterId, &[u8]) -> Vec<MessageUsage>> {
        UsageProjection::new(
            VersionToken::parse(PROJECTION_VERSION).expect("grammar projection version"),
            read_usage,
        )
    }

    // ---- Driving ----

    /// Complete first-poll-until-ready, the catalog-source-module pattern
    /// (every mock future completes without pending).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn policy(checkpoint_every: u64) -> RebuildPolicy {
        RebuildPolicy {
            checkpoint_every,
            window: None,
        }
    }

    fn windowed(checkpoint_every: u64, window: u64) -> RebuildPolicy {
        RebuildPolicy {
            checkpoint_every,
            window: Some(window),
        }
    }

    fn pass(
        store: &MockStore,
        derived: &MockDerived,
        catalog: &MockCatalog,
        cadence: RebuildPolicy,
        resume: Option<&[u8]>,
    ) -> RebuildOutcome {
        block_on(rebuild_pass(
            store,
            derived,
            catalog,
            &projection(),
            &tenant(),
            cadence,
            resume,
        ))
        .expect("the fixture prefix passes")
    }

    /// Resume the way the composing phase does: land the catalog writer's
    /// puts into the store, then read the furthest checkpoint back
    /// through the seam.
    fn resume_of(store: &MockStore, catalog: &MockCatalog) -> Option<Vec<u8>> {
        store.absorb(&catalog.objects());
        block_on(latest_checkpoint(store, catalog, &projection(), &tenant()))
            .expect("the seam reads its own checkpoints")
    }

    // ---- The determinism proofs ----

    /// Two fresh passes over one prefix write byte-identical sequences —
    /// every key and every byte, rows and checkpoints alike (the Phase 10
    /// exit gate, uninterrupted form).
    #[test]
    fn fresh_passes_are_byte_identical() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);

        let (derived_a, catalog_a) = (MockDerived::default(), MockCatalog::default());
        let outcome_a = pass(&store, &derived_a, &catalog_a, policy(2), None);
        let (derived_b, catalog_b) = (MockDerived::default(), MockCatalog::default());
        let outcome_b = pass(&store, &derived_b, &catalog_b, policy(2), None);

        assert_eq!(derived_a.log(), derived_b.log());
        assert_eq!(catalog_a.log(), catalog_b.log());
        assert_eq!(outcome_a.checkpoint_digest(), outcome_b.checkpoint_digest());
        assert_eq!(outcome_a.checkpoint_key(), outcome_b.checkpoint_key());
        assert_eq!(outcome_a.chain_digest(), outcome_b.chain_digest());
        assert!(outcome_a.is_complete());
        assert_eq!(outcome_a.occurrences_total(), 3);
        assert_eq!(outcome_a.occurrences_this_pass(), 3);
        // One row per occurrence, every occurrence contributing exactly
        // one denominator state.
        assert_eq!(outcome_a.row_states().measured(), 1);
        assert_eq!(outcome_a.row_states().absent(), 1);
        assert_eq!(outcome_a.row_states().malformed(), 1);
        assert_eq!(outcome_a.row_states().unsupported(), 0);
        assert_eq!(outcome_a.attestations_observed(), 3);
    }

    /// A rebuild walked in interrupted window passes converges to the
    /// identical byte sequence of one uninterrupted pass — rows,
    /// intermediate checkpoints, and the final checkpoint alike (the
    /// Phase 10 exit gate, resumed form, resumed through the real seam).
    #[test]
    fn interrupted_passes_converge_byte_identically() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);

        let (whole_rows, whole_checkpoints) = (MockDerived::default(), MockCatalog::default());
        let whole_outcome = pass(&store, &whole_rows, &whole_checkpoints, policy(1), None);

        let (rows, checkpoints) = (MockDerived::default(), MockCatalog::default());
        let mut passes = 0;
        let final_outcome = loop {
            let resume = resume_of(&store, &checkpoints);
            let outcome = pass(
                &store,
                &rows,
                &checkpoints,
                windowed(1, 1),
                resume.as_deref(),
            );
            passes += 1;
            assert!(passes < 10, "the walk terminates");
            if outcome.is_complete() {
                assert_eq!(outcome.restart(), RestartReason::Resumed);
                break outcome;
            }
        };

        assert_eq!(whole_rows.log(), rows.log());
        assert_eq!(whole_checkpoints.log(), checkpoints.log());
        assert_eq!(
            whole_outcome.checkpoint_digest(),
            final_outcome.checkpoint_digest()
        );
        assert_eq!(whole_outcome.chain_digest(), final_outcome.chain_digest());
        assert_eq!(
            whole_outcome.occurrences_total(),
            final_outcome.occurrences_total()
        );
    }

    /// The final fold state converges even when the checkpoint cadence
    /// does not divide the window: intermediate checkpoints differ, the
    /// final checkpoint does not.
    #[test]
    fn non_dividing_cadence_converges_at_completion() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);

        let (whole_rows, whole_checkpoints) = (MockDerived::default(), MockCatalog::default());
        let whole_outcome = pass(&store, &whole_rows, &whole_checkpoints, policy(2), None);

        let (rows, checkpoints) = (MockDerived::default(), MockCatalog::default());
        let mut passes = 0;
        let final_outcome = loop {
            let resume = resume_of(&store, &checkpoints);
            let outcome = pass(
                &store,
                &rows,
                &checkpoints,
                windowed(2, 1),
                resume.as_deref(),
            );
            passes += 1;
            assert!(passes < 10, "the walk terminates");
            if outcome.is_complete() {
                break outcome;
            }
        };

        assert_eq!(
            whole_outcome.checkpoint_bytes(),
            final_outcome.checkpoint_bytes()
        );
        assert_eq!(whole_outcome.chain_digest(), final_outcome.chain_digest());
        assert_ne!(
            whole_checkpoints.log(),
            checkpoints.log(),
            "the cadences land differently mid-run"
        );
    }

    // ---- The resume seam ----

    /// The seam picks the furthest of several landed checkpoints.
    #[test]
    fn latest_checkpoint_picks_the_furthest() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());

        // A first, windowed pass leaves a processed=1 checkpoint behind.
        {
            let outcome = pass(&store, &rows, &catalog, windowed(4, 1), None);
            assert_eq!(outcome.occurrences_this_pass(), 1);
        }
        let intermediate = resume_of(&store, &catalog).expect("an intermediate checkpoint");

        // The completed rebuild leaves processed=3 checkpoints behind.
        let outcome = pass(&store, &rows, &catalog, policy(1), Some(&intermediate));
        assert!(outcome.is_complete());
        store.absorb(&catalog.objects());

        let resumed = resume_of(&store, &catalog).expect("the final checkpoint");
        assert_eq!(resumed, outcome.checkpoint_bytes());
        // And the resumed pass is a no-op that converges.
        let (rows_two, catalog_two) = (MockDerived::default(), MockCatalog::default());
        let outcome_two = pass(&store, &rows_two, &catalog_two, policy(4), Some(&resumed));
        assert_eq!(outcome_two.restart(), RestartReason::Resumed);
        assert_eq!(outcome_two.occurrences_this_pass(), 0);
        assert!(rows_two.log().is_empty());
        assert!(catalog_two.log().is_empty(), "nothing to rewrite");
    }

    /// The seam skips checkpoints of another projection version — the
    /// namespace is pipeline-blind, and the furthest *in-scope* document
    /// wins — while a listed object that is not a checkpoint at all fails
    /// the read closed.
    #[test]
    fn latest_checkpoint_filters_scope_and_fails_closed() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());

        let outcome = pass(&store, &rows, &catalog, policy(4), None);
        let in_scope = outcome.checkpoint_bytes().to_vec();

        // A well-formed checkpoint of another projection version, at a
        // further processed count: out of scope, skipped.
        let foreign_doc = retarget_checkpoint(&in_scope, "usage_projection_version", "other-1");
        let foreign_key = CatalogCheckpointKey::new(&tenant(), &document_digest(&foreign_doc));
        block_on(catalog.put_checkpoint(&foreign_key, &foreign_doc))
            .expect("the foreign checkpoint is well formed");
        store.absorb(&catalog.objects());

        let resumed = block_on(latest_checkpoint(
            &store,
            &catalog,
            &projection(),
            &tenant(),
        ))
        .expect("the seam reads past the foreign pipeline's checkpoint");
        assert_eq!(resumed.as_deref(), Some(in_scope.as_slice()));

        // A listed object outside the checkpoint grammar is a fault, not
        // a skip.
        let (rows_two, catalog_two) = (MockDerived::default(), MockCatalog::default());
        pass(&store, &rows_two, &catalog_two, policy(4), None);
        store.absorb(&catalog_two.objects());
        catalog_two.list_foreign(&format!(
            "{}scratch.json",
            CatalogListPrefix::root(&tenant()).as_str()
        ));
        store.insert(
            &format!(
                "{}scratch.json",
                CatalogListPrefix::root(&tenant()).as_str()
            ),
            b"not a checkpoint document\n",
        );
        let error = block_on(latest_checkpoint(
            &store,
            &catalog_two,
            &projection(),
            &tenant(),
        ))
        .expect_err("a foreign key fails the read closed");
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    // ---- Resume validation inside the pass ----

    /// Re-render a checkpoint with one text member rewritten and a fresh
    /// self-verifying digest, so the mutation exercises the scope and
    /// cursor checks and not merely the digest.
    fn retarget_checkpoint(checkpoint: &[u8], member: &str, value: &str) -> Vec<u8> {
        let body = &checkpoint[..checkpoint.len() - 1];
        let Value::Object(mut object) = json::parse(body).expect("checkpoint parses") else {
            panic!("checkpoint is an object");
        };
        let replacement = if value.is_empty() {
            format!("{}-tampered", text_member(&object, member))
        } else {
            value.to_owned()
        };
        let _ = object.remove("rebuild_checkpoint_digest");
        object.set(member, Value::Text(replacement));
        let mut frame = FrameBuilder::new(super::CHECKPOINT_DIGEST_LABEL);
        frame.push_bytes(&Value::Object(object.clone()).canonical_bytes());
        let digest = sha256::encode_hex(&frame.finish());
        object.set("rebuild_checkpoint_digest", Value::Text(digest));
        render(&object)
    }

    /// A checkpoint from a different prefix (here: a mutated inventory
    /// digest) is out of scope; the pass says so and rebuilds everything
    /// fresh.
    #[test]
    fn out_of_scope_checkpoint_rebuilds_fresh() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());

        let first = pass(&store, &rows, &catalog, windowed(4, 1), None);
        let tampered = retarget_checkpoint(first.checkpoint_bytes(), "inventory_digest", "");

        let (writer, checkpoints) = (MockDerived::default(), MockCatalog::default());
        let outcome = pass(&store, &writer, &checkpoints, policy(4), Some(&tampered));
        assert_eq!(outcome.restart(), RestartReason::CheckpointScopeMismatch);
        assert_eq!(outcome.occurrences_this_pass(), 3, "everything reprocessed");
        assert_eq!(writer.log().len(), 3, "three rows");
        assert_eq!(checkpoints.log().len(), 1, "one final checkpoint");
    }

    /// A cursor that no longer aligns with the canonical order rebuilds
    /// fresh rather than trusting a misaligned skip.
    #[test]
    fn misaligned_cursor_rebuilds_fresh() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());

        let first = pass(&store, &rows, &catalog, windowed(4, 1), None);
        let tampered = retarget_checkpoint(first.checkpoint_bytes(), "last_occurrence_key", "");

        let (writer, checkpoints) = (MockDerived::default(), MockCatalog::default());
        let outcome = pass(&store, &writer, &checkpoints, policy(4), Some(&tampered));
        assert_eq!(outcome.restart(), RestartReason::CheckpointCursorMisaligned);
        assert_eq!(outcome.occurrences_this_pass(), 3);
    }

    /// Bytes that are not a verifiable checkpoint never stop the rebuild:
    /// the pass names them unreadable and starts from scratch.
    #[test]
    fn unreadable_checkpoint_rebuilds_fresh() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);

        let writer = MockDerived::default();
        let checkpoints = MockCatalog::default();
        let outcome = pass(
            &store,
            &writer,
            &checkpoints,
            policy(4),
            Some(b"not json\n"),
        );
        assert_eq!(outcome.restart(), RestartReason::CheckpointUnreadable);
        assert_eq!(outcome.occurrences_this_pass(), 3);
    }

    /// A checkpoint whose digest does not re-derive from its own bytes is
    /// unreadable — the self-verification discipline, not an extra trust
    /// assumption.
    #[test]
    fn tampered_checkpoint_is_unreadable() {
        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());

        let first = pass(&store, &rows, &catalog, windowed(4, 1), None);
        let mut tampered = first.checkpoint_bytes().to_vec();
        let len = tampered.len();
        tampered[len - 20] ^= b'x';

        let (writer, checkpoints) = (MockDerived::default(), MockCatalog::default());
        let outcome = pass(&store, &writer, &checkpoints, policy(4), Some(&tampered));
        assert_eq!(outcome.restart(), RestartReason::CheckpointUnreadable);
        assert_eq!(outcome.occurrences_this_pass(), 3);
    }

    // ---- The prefix itself ----

    /// An empty prefix produces the genesis checkpoint: zero counts, no
    /// cursor, and a chain that folds this prefix's inventory digest — and
    /// a resume from it is the same no-op, resumed.
    #[test]
    fn empty_prefix_writes_genesis_checkpoint() {
        let store = MockStore::with(&[]);
        let (rows, catalog) = (MockDerived::default(), MockCatalog::default());
        let outcome = pass(&store, &rows, &catalog, policy(4), None);

        assert!(outcome.is_complete());
        assert_eq!(outcome.occurrences_total(), 0);
        assert_eq!(outcome.checkpoint_digest().len(), 64);
        assert_eq!(catalog.log().len(), 1, "exactly the genesis checkpoint");
        let checkpoint = outcome.checkpoint_bytes().to_vec();
        let text = std::str::from_utf8(&checkpoint).expect("checkpoint is utf-8");
        assert!(text.contains("\"occurrences_processed\":0"));
        assert!(!text.contains("last_occurrence_key"));

        store.absorb(&catalog.objects());
        let (rows_two, catalog_two) = (MockDerived::default(), MockCatalog::default());
        let outcome_two = pass(
            &store,
            &rows_two,
            &catalog_two,
            policy(4),
            Some(&checkpoint),
        );
        assert_eq!(outcome_two.restart(), RestartReason::Resumed);
        assert_eq!(outcome_two.occurrences_this_pass(), 0);
        assert_eq!(outcome_two.checkpoint_bytes(), checkpoint);
        assert!(
            catalog_two.log().is_empty(),
            "the genesis checkpoint is already at its key"
        );
    }

    /// A stored blob that is not a real `zstd-v1` frame fails the pass
    /// closed: the raw source's header validation passes the fake, and
    /// the checksum-verified decode is the check that refuses it.
    #[test]
    fn undecodable_blob_fails_closed() {
        let mut corpus = vec![fixture("poisoned", Some("claude-sonnet-4"), Some(MEASURED))];
        // A header-conforming frame whose body no decoder accepts.
        let mut fake = Vec::from([0x28_u8, 0xB5, 0x2F, 0xFD, 0xC4, 0x00]);
        fake.extend_from_slice(&9_u64.to_le_bytes());
        fake.extend_from_slice(b"frame body the reader never parses");
        corpus[0].blob = fake;
        let store = MockStore::with(&corpus);

        let writer = MockDerived::default();
        let checkpoints = MockCatalog::default();
        let outcome = block_on(rebuild_pass(
            &store,
            &writer,
            &checkpoints,
            &projection(),
            &tenant(),
            policy(4),
            None,
        ));
        let error = outcome.expect_err("the fake frame refuses to decode");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
        assert!(
            writer.log().is_empty(),
            "nothing is written on a failed pass"
        );
        assert!(checkpoints.log().is_empty());
    }

    // ---- The content-freeness boundary at the engine seam ----

    /// The projection is the engine's only channel to content: a marker
    /// planted in the payload never reaches a derived byte, and a source
    /// with no usage region reads `unknown`/`absent` — never zeros.
    #[test]
    fn content_never_reaches_the_derived_bytes() {
        let marker = fixture("TOPMARKER-never-derived", None, None);
        let store = MockStore::with(std::slice::from_ref(&marker));

        let writer = MockDerived::default();
        let checkpoints = MockCatalog::default();
        let outcome = pass(&store, &writer, &checkpoints, policy(4), None);
        assert_eq!(outcome.row_states().absent(), 1);

        for (_, bytes) in writer.log().into_iter().chain(checkpoints.log()) {
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("TOPMARKER"), "content leaked into {text}");
            assert!(
                !text.contains("note"),
                "transcript shape leaked into {text}"
            );
        }
    }

    /// A failed row put fails the pass closed — the writer's refusal is
    /// the caller's signal, never a silently skipped occurrence.
    #[test]
    fn failed_put_fails_the_pass() {
        struct RefusingDerived;
        impl DerivedWriteStore for RefusingDerived {
            fn put_object(
                &self,
                _key: &DerivedObjectKey,
                _bytes: &[u8],
            ) -> impl Future<Output = Result<(), StorageError>> + Send {
                async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
            }

            fn list_objects(
                &self,
                _prefix: &DerivedListPrefix,
            ) -> impl Future<Output = Result<Vec<String>, StorageError>> + Send {
                async { Err(StorageError::of_kind(StorageErrorKind::Unavailable)) }
            }
        }

        let fixtures = fixtures();
        let store = MockStore::with(&fixtures);
        let outcome = block_on(rebuild_pass(
            &store,
            &RefusingDerived,
            &MockCatalog::default(),
            &projection(),
            &tenant(),
            policy(4),
            None,
        ));
        assert_eq!(
            outcome
                .expect_err("the refusing writer fails the pass")
                .kind(),
            StorageErrorKind::Unavailable
        );
    }

    /// The policy's bounds refuse to assemble: no cadence-below-one and
    /// no zero-window pass can exist.
    #[test]
    fn policy_bounds_refuse_zero() {
        let error = RebuildPolicy {
            checkpoint_every: 0,
            window: None,
        }
        .validate()
        .expect_err("zero cadence is refused");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);

        let error = RebuildPolicy {
            checkpoint_every: 1,
            window: Some(0),
        }
        .validate()
        .expect_err("zero window is refused");
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
    }
}
