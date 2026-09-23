// SPDX-License-Identifier: Apache-2.0

//! Disabled-by-default, reference-safe blob collection (plan Section 7.10).
//!
//! Collection is deliberately split into three stages:
//!
//! 1. [`ReferenceScan`] is built only from a complete frozen raw inventory and
//!    validated occurrence-to-blob references.
//! 2. [`CollectionPlan`] folds the offline retention view over both scans and
//!    selects only blobs that have no retained occurrence, no changed scan
//!    evidence, and a stable object commitment.
//! 3. [`BlobCollector::execute`] revalidates each selected object immediately
//!    before invoking the separately provisioned deletion identity. The
//!    default configuration is simulation-only, and both simulation and
//!    execution render canonical, content-free audit evidence.
//!
//! A raw occurrence that is tombstoned but still inside its 30-day grace is
//! retained. Once its grace has elapsed, it no longer blocks collection; a
//! missing retention entry is always retained, which preserves the archive's
//! indefinite-retention default. Thus two occurrences sharing one blob are
//! safe in either direction: an unmarked or held occurrence blocks the blob,
//! while two expired tombstones do not.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::future::Future;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::object_key::{BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{OccurrenceId, TenantId, Timestamp};

use crate::audit_restore::{
    FrozenInventory, InventoryDigest, InventoryEntry, InventoryScope, ObjectMetadata,
};
use crate::error::{StorageError, StorageErrorKind};

/// The schema-pinned tombstone grace period.
pub const DELETION_GRACE_DAYS: u64 = 30;

/// The tombstone grace period in seconds.
pub const DELETION_GRACE_SECONDS: i64 = 30 * 24 * 60 * 60;

/// The minimum time between the completion of the two full reference scans.
pub const MIN_SCAN_SEPARATION_SECONDS: i64 = 24 * 60 * 60;

const EVIDENCE_SCHEMA: &str = "archivist.collection-evidence/v1";
const INVALID_INPUT: &str = "collection input is malformed or incomplete";
const TENANT_MISMATCH: &str = "collection scans do not address one tenant";
const SCAN_ORDER: &str = "reference scans are not ordered 24 hours apart";
const UNKNOWN_RAW_KEY: &str = "reference scan inventory contains an unknown raw key";
const REFERENCE_ABSENT: &str = "occurrence reference is absent from its frozen inventory";
const DUPLICATE_OCCURRENCE: &str = "reference scan contains a duplicate occurrence";
const RETENTION_CONFLICT: &str = "retention view contains conflicting occurrence references";
const AUDIT_PLAN_MISMATCH: &str = "collection audit event belongs to another plan";
const AUDIT_SEQUENCE: &str = "collection audit event sequence is not contiguous";
const AUDIT_CHAIN: &str = "collection audit event chain is not immutable";
const AUDIT_UNKNOWN_CANDIDATE: &str = "collection audit event names an unknown candidate";

/// Why collection cannot delete one blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecisionReason {
    /// The blob was not present in the first complete inventory.
    ///
    /// A candidate must be identified by the same committed metadata in both
    /// inventories.  Presence in only one inventory is therefore evidence of
    /// an incomplete or changing view, never evidence for deletion.
    MissingFromFirstScan,
    /// The blob was not present in the second complete inventory.
    MissingFromSecondScan,
    /// A retained occurrence in the first complete scan names this blob.
    RetainedReferenceFirstScan,
    /// A retained occurrence in the second complete scan names this blob.
    RetainedReferenceSecondScan,
    /// A retained occurrence supplied by the offline retention view names this
    /// blob even though it was not present in either frozen inventory.
    RetainedReferenceOutsideScans,
    /// The blob's commitment metadata changed between the two observations.
    ChangedBetweenScans,
    /// The backend supplied no commitment token with which to revalidate the
    /// candidate safely.
    UnstableObservation,
}

impl DecisionReason {
    /// The bounded evidence token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::MissingFromFirstScan => "missing-from-first-scan",
            Self::MissingFromSecondScan => "missing-from-second-scan",
            Self::RetainedReferenceFirstScan => "retained-reference-first-scan",
            Self::RetainedReferenceSecondScan => "retained-reference-second-scan",
            Self::RetainedReferenceOutsideScans => "retained-reference-outside-scans",
            Self::ChangedBetweenScans => "changed-between-scans",
            Self::UnstableObservation => "unstable-observation",
        }
    }
}

/// Why a pre-delete execution attempt did not remove a planned blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ActionOutcome {
    /// Simulation says the blob would be deleted; no delete call occurred.
    WouldDelete,
    /// Collection was disabled, so no delete call occurred.
    Disabled,
    /// An immutable audit record was written immediately before deletion.
    ///
    /// This is an internal journal state.  It is deliberately distinct from
    /// `deleted`: if a worker dies between the conditional delete and its
    /// completion record, a later run can re-HEAD the object and continue
    /// without treating an unrecorded delete as a fresh candidate.
    DeletePending,
    /// The immediate HEAD-style observation disagreed with the frozen scan.
    ChangedBeforeDelete,
    /// The immediate observation could not be obtained.
    UnreadableBeforeDelete,
    /// The deletion identity refused or could not complete the delete.
    DeleteFailed,
    /// The deletion identity completed the delete.
    Deleted,
}

impl ActionOutcome {
    /// The bounded evidence token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::WouldDelete => "would-delete",
            Self::Disabled => "disabled",
            Self::DeletePending => "delete-pending",
            Self::ChangedBeforeDelete => "changed-before-delete",
            Self::UnreadableBeforeDelete => "unreadable-before-delete",
            Self::DeleteFailed => "delete-failed",
            Self::Deleted => "deleted",
        }
    }
}

/// A content-free collection error. Store errors during execution are kept in
/// the evidence as a failed action so that one transient object does not erase
/// the audit trail for the rest of the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CollectionError {
    kind: CollectionErrorKind,
    detail: &'static str,
}

impl CollectionError {
    const fn new(kind: CollectionErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The collection failure class.
    #[must_use]
    pub const fn kind(self) -> CollectionErrorKind {
        self.kind
    }

    /// The content-free failure detail.
    #[must_use]
    pub const fn detail(self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for CollectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "collection {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for CollectionError {}

/// The closed collection planning failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CollectionErrorKind {
    /// Input did not satisfy the frozen-inventory or reference contract.
    InvalidInput,
    /// The two complete scans were not at least 24 hours apart.
    ScanSeparation,
    /// A scan pair or retention view spans multiple tenants.
    TenantMismatch,
}

impl fmt::Display for CollectionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid-input",
            Self::ScanSeparation => "scan-separation",
            Self::TenantMismatch => "tenant-mismatch",
        })
    }
}

/// The disabled-by-default collector configuration.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CollectionConfig {
    enabled: bool,
}

impl CollectionConfig {
    /// Construct a configuration explicitly. `false` is the safe default.
    #[must_use]
    pub const fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// The disabled configuration.
    #[must_use]
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }

    /// The opt-in execution configuration.
    #[must_use]
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// Whether destructive execution is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.enabled
    }
}

/// One validated occurrence-to-blob edge from a complete reference scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceReference {
    occurrence_id: OccurrenceId,
    blob_key: BlobObjectKey,
}

impl OccurrenceReference {
    /// Pair an occurrence identity with its server-derived blob key.
    #[must_use]
    pub const fn new(occurrence_id: OccurrenceId, blob_key: BlobObjectKey) -> Self {
        Self {
            occurrence_id,
            blob_key,
        }
    }

    /// The occurrence identity.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The referenced blob key.
    #[must_use]
    pub const fn blob_key(&self) -> &BlobObjectKey {
        &self.blob_key
    }
}

/// The folded retention result for one occurrence, supplied by the offline
/// control-plane reader. Missing entries are not represented here: the
/// collector treats them as indefinite retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetentionDecision {
    tombstone_at: Option<Timestamp>,
    legal_hold: bool,
}

impl RetentionDecision {
    /// Construct an indefinite-retention decision.
    #[must_use]
    pub const fn indefinite() -> Self {
        Self {
            tombstone_at: None,
            legal_hold: false,
        }
    }

    /// Construct a decision from the folded tombstone and hold state.
    ///
    /// # Errors
    /// [`CollectionErrorKind::InvalidInput`] when a supplied timestamp is not
    /// a calendar-valid UTC instant.
    pub fn new(tombstone_at: Option<Timestamp>, legal_hold: bool) -> Result<Self, CollectionError> {
        if tombstone_at
            .as_ref()
            .is_some_and(|timestamp| !timestamp.calendar_valid())
        {
            return Err(CollectionError::new(
                CollectionErrorKind::InvalidInput,
                INVALID_INPUT,
            ));
        }
        Ok(Self {
            tombstone_at,
            legal_hold,
        })
    }

    /// Whether this occurrence is eligible for collection at `at`.
    #[must_use]
    pub fn eligible_at(&self, at: &Timestamp) -> bool {
        let Some(tombstone_at) = self.tombstone_at.as_ref() else {
            return false;
        };
        if self.legal_hold || !at.calendar_valid() {
            return false;
        }
        grace_elapsed(tombstone_at, at)
    }

    /// Whether this occurrence must keep its referenced blob.
    #[must_use]
    pub fn is_retained_at(&self, at: &Timestamp) -> bool {
        !self.eligible_at(at)
    }

    /// The immutable tombstone grace anchor, if one exists.
    #[must_use]
    pub const fn tombstone_at(&self) -> Option<&Timestamp> {
        self.tombstone_at.as_ref()
    }

    /// Whether an active legal hold blocks collection.
    #[must_use]
    pub const fn has_active_legal_hold(&self) -> bool {
        self.legal_hold
    }
}

/// The retention view for one occurrence and its referenced blob.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OccurrenceRetention {
    occurrence_id: OccurrenceId,
    blob_key: BlobObjectKey,
    decision: RetentionDecision,
}

impl OccurrenceRetention {
    /// Pair one occurrence edge with its folded retention decision.
    #[must_use]
    pub const fn new(
        occurrence_id: OccurrenceId,
        blob_key: BlobObjectKey,
        decision: RetentionDecision,
    ) -> Self {
        Self {
            occurrence_id,
            blob_key,
            decision,
        }
    }

    /// The occurrence identity.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The blob named by the occurrence.
    #[must_use]
    pub const fn blob_key(&self) -> &BlobObjectKey {
        &self.blob_key
    }

    /// The folded retention decision.
    #[must_use]
    pub const fn decision(&self) -> &RetentionDecision {
        &self.decision
    }
}

/// One complete, frozen reference scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReferenceScan {
    tenant: TenantId,
    completed_at: Timestamp,
    inventory_digest: crate::audit_restore::InventoryDigest,
    blobs: BTreeMap<BlobObjectKey, InventoryEntry>,
    references: BTreeMap<OccurrenceId, OccurrenceReference>,
}

impl ReferenceScan {
    /// Validate and record one complete raw inventory and its occurrence
    /// references.
    ///
    /// `FrozenInventory` proves exhaustive pagination, canonical ordering,
    /// duplicate rejection, and scope membership. This constructor adds the
    /// raw-key grammar and occurrence-reference checks needed by collection.
    ///
    /// # Errors
    /// [`CollectionErrorKind::InvalidInput`] for an invalid timestamp,
    /// unknown raw key, duplicate occurrence, or reference absent from the
    /// frozen inventory; [`CollectionErrorKind::TenantMismatch`] when a key
    /// does not belong to the inventory tenant.
    pub fn new<I>(
        inventory: &FrozenInventory,
        completed_at: Timestamp,
        references: I,
    ) -> Result<Self, CollectionError>
    where
        I: IntoIterator<Item = OccurrenceReference>,
    {
        if !completed_at.calendar_valid() {
            return Err(CollectionError::new(
                CollectionErrorKind::InvalidInput,
                INVALID_INPUT,
            ));
        }
        let tenant = match inventory.scope() {
            InventoryScope::TenantRaw(tenant) => tenant.clone(),
            InventoryScope::TenantControl(_) => {
                return Err(CollectionError::new(
                    CollectionErrorKind::InvalidInput,
                    INVALID_INPUT,
                ));
            }
        };
        let raw_prefix = format!("tenants/{tenant}/v1/raw/");
        let blob_prefix = format!("{raw_prefix}blobs/");
        let mut blobs = BTreeMap::new();
        for entry in inventory.entries() {
            let key = entry.key().as_str();
            let known = BlobObjectKey::parse(key).is_ok()
                || OccurrenceObjectKey::parse(key).is_ok()
                || archivist_protocol::object_key::AttestationObjectKey::parse(key).is_ok();
            if !known {
                return Err(CollectionError::new(
                    CollectionErrorKind::InvalidInput,
                    UNKNOWN_RAW_KEY,
                ));
            }
            if let Ok(blob) = BlobObjectKey::parse(key) {
                if !blob.as_str().starts_with(&blob_prefix) {
                    return Err(CollectionError::new(
                        CollectionErrorKind::TenantMismatch,
                        TENANT_MISMATCH,
                    ));
                }
                blobs.insert(blob, entry.clone());
            }
        }

        let mut normalized = BTreeMap::new();
        for reference in references {
            if !reference.blob_key().as_str().starts_with(&blob_prefix) {
                return Err(CollectionError::new(
                    CollectionErrorKind::TenantMismatch,
                    TENANT_MISMATCH,
                ));
            }
            if !blobs.contains_key(reference.blob_key()) {
                return Err(CollectionError::new(
                    CollectionErrorKind::InvalidInput,
                    REFERENCE_ABSENT,
                ));
            }
            if normalized
                .insert(*reference.occurrence_id(), reference)
                .is_some()
            {
                return Err(CollectionError::new(
                    CollectionErrorKind::InvalidInput,
                    DUPLICATE_OCCURRENCE,
                ));
            }
        }

        Ok(Self {
            tenant,
            completed_at,
            inventory_digest: *inventory.digest(),
            blobs,
            references: normalized,
        })
    }

    /// The tenant addressed by the scan.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// When enumeration reached exhaustion.
    #[must_use]
    pub const fn completed_at(&self) -> &Timestamp {
        &self.completed_at
    }

    /// The frozen inventory digest.
    #[must_use]
    pub const fn inventory_digest(&self) -> &crate::audit_restore::InventoryDigest {
        &self.inventory_digest
    }

    /// Every stored blob observed by this scan, in canonical key order.
    pub fn blobs(&self) -> impl Iterator<Item = (&BlobObjectKey, &InventoryEntry)> {
        self.blobs.iter()
    }

    /// Every validated occurrence reference, in occurrence-id order.
    pub fn references(&self) -> impl Iterator<Item = &OccurrenceReference> {
        self.references.values()
    }

    /// The number of occurrence manifests consumed by this scan.
    #[must_use]
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Whether this scan contains a reference to `key`.
    #[must_use]
    pub fn references_blob(&self, key: &BlobObjectKey) -> bool {
        self.references
            .values()
            .any(|reference| reference.blob_key() == key)
    }

    fn observation_for(&self, key: &BlobObjectKey) -> Option<&InventoryEntry> {
        self.blobs.get(key)
    }
}

/// A reasoned decision for one blob observed by at least one scan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobDecision {
    key: BlobObjectKey,
    reasons: Vec<DecisionReason>,
}

impl BlobDecision {
    /// The blob key under consideration.
    #[must_use]
    pub const fn key(&self) -> &BlobObjectKey {
        &self.key
    }

    /// The independent reasons this blob is preserved.
    #[must_use]
    pub fn reasons(&self) -> &[DecisionReason] {
        &self.reasons
    }

    /// Whether the blob is eligible for deletion.
    #[must_use]
    pub fn eligible(&self) -> bool {
        self.reasons.is_empty()
    }
}

/// The deterministic result of the mark phase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionPlan {
    tenant: TenantId,
    evaluated_at: Timestamp,
    first: ReferenceScan,
    second: ReferenceScan,
    decisions: Vec<BlobDecision>,
    expected: BTreeMap<BlobObjectKey, InventoryEntry>,
}

impl CollectionPlan {
    /// Build the mark phase from two complete scans and the folded retention
    /// view. All missing retention entries are treated as retained.
    ///
    /// # Errors
    /// [`CollectionErrorKind::ScanSeparation`] unless the scans are ordered
    /// and at least 24 hours apart, or the other collection input failures
    /// documented by [`ReferenceScan::new`].
    #[allow(clippy::too_many_lines)]
    pub fn build<I>(
        first: ReferenceScan,
        second: ReferenceScan,
        retention: I,
        evaluated_at: Timestamp,
    ) -> Result<Self, CollectionError>
    where
        I: IntoIterator<Item = OccurrenceRetention>,
    {
        if first.tenant() != second.tenant() {
            return Err(CollectionError::new(
                CollectionErrorKind::TenantMismatch,
                TENANT_MISMATCH,
            ));
        }
        if !evaluated_at.calendar_valid() {
            return Err(CollectionError::new(
                CollectionErrorKind::InvalidInput,
                INVALID_INPUT,
            ));
        }
        let first_instant = instant(first.completed_at()).ok_or_else(|| {
            CollectionError::new(CollectionErrorKind::InvalidInput, INVALID_INPUT)
        })?;
        let second_instant = instant(second.completed_at()).ok_or_else(|| {
            CollectionError::new(CollectionErrorKind::InvalidInput, INVALID_INPUT)
        })?;
        if second_instant <= first_instant
            || second_instant.0 - first_instant.0 < MIN_SCAN_SEPARATION_SECONDS
        {
            return Err(CollectionError::new(
                CollectionErrorKind::ScanSeparation,
                SCAN_ORDER,
            ));
        }

        let mut retention_by_occurrence = BTreeMap::new();
        for item in retention {
            if !item
                .blob_key()
                .as_str()
                .starts_with(&format!("tenants/{}/v1/raw/blobs/", first.tenant()))
            {
                return Err(CollectionError::new(
                    CollectionErrorKind::TenantMismatch,
                    TENANT_MISMATCH,
                ));
            }
            let occurrence_id = *item.occurrence_id();
            if let Some(existing) = retention_by_occurrence.get(&occurrence_id) {
                if existing != &item {
                    return Err(CollectionError::new(
                        CollectionErrorKind::InvalidInput,
                        RETENTION_CONFLICT,
                    ));
                }
            } else {
                retention_by_occurrence.insert(occurrence_id, item);
            }
        }

        let mut retained_blobs = BTreeSet::new();
        for scan in [&first, &second] {
            for reference in scan.references() {
                let retained = retention_by_occurrence
                    .get(reference.occurrence_id())
                    .is_none_or(|item| item.decision().is_retained_at(&evaluated_at));
                if retained {
                    retained_blobs.insert(reference.blob_key().clone());
                }
            }
        }
        for item in retention_by_occurrence.values() {
            if item.decision().is_retained_at(&evaluated_at) {
                retained_blobs.insert(item.blob_key().clone());
            }
        }

        let mut expected = BTreeMap::new();
        let mut all_blobs = BTreeSet::new();
        for (key, entry) in first.blobs() {
            all_blobs.insert(key.clone());
            expected.insert(key.clone(), entry.clone());
        }
        for (key, entry) in second.blobs() {
            all_blobs.insert(key.clone());
            expected.entry(key.clone()).or_insert_with(|| entry.clone());
        }

        let mut decisions = Vec::with_capacity(all_blobs.len());
        for key in all_blobs {
            let mut reasons = Vec::new();
            let first_entry = first.observation_for(&key);
            let second_entry = second.observation_for(&key);
            if first_entry.is_none() {
                reasons.push(DecisionReason::MissingFromFirstScan);
            }
            if second_entry.is_none() {
                reasons.push(DecisionReason::MissingFromSecondScan);
            }
            let first_reference = first.references().any(|reference| {
                reference.blob_key() == &key
                    && retention_by_occurrence
                        .get(reference.occurrence_id())
                        .is_none_or(|item| item.decision().is_retained_at(&evaluated_at))
            });
            let second_reference = second.references().any(|reference| {
                reference.blob_key() == &key
                    && retention_by_occurrence
                        .get(reference.occurrence_id())
                        .is_none_or(|item| item.decision().is_retained_at(&evaluated_at))
            });
            if first_reference {
                reasons.push(DecisionReason::RetainedReferenceFirstScan);
            }
            if second_reference {
                reasons.push(DecisionReason::RetainedReferenceSecondScan);
            }
            if retained_blobs.contains(&key) && !first_reference && !second_reference {
                reasons.push(DecisionReason::RetainedReferenceOutsideScans);
            }
            match (first_entry, second_entry) {
                (Some(left), Some(right)) if !stable_metadata_equal(left, right) => {
                    reasons.push(DecisionReason::ChangedBetweenScans);
                }
                (Some(left), Some(right)) if !has_commitment(left) || !has_commitment(right) => {
                    reasons.push(DecisionReason::UnstableObservation);
                }
                _ => {}
            }
            decisions.push(BlobDecision { key, reasons });
        }

        Ok(Self {
            tenant: first.tenant.clone(),
            evaluated_at,
            first,
            second,
            decisions,
            expected,
        })
    }

    /// The tenant collected by this plan.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The wall-clock instant at which retention was evaluated.
    #[must_use]
    pub const fn evaluated_at(&self) -> &Timestamp {
        &self.evaluated_at
    }

    /// The stable identity of this complete collection plan.
    ///
    /// The identity covers both frozen inventories, their completion times,
    /// and every mark decision.  It is independent of execution outcomes, so
    /// a worker can find and resume the same plan after a partial run without
    /// rewriting the evidence of the run that preceded it.
    #[must_use]
    pub fn plan_digest(&self) -> InventoryDigest {
        plan_digest(self)
    }

    /// The first complete scan.
    #[must_use]
    pub const fn first_scan(&self) -> &ReferenceScan {
        &self.first
    }

    /// The second complete scan.
    #[must_use]
    pub const fn second_scan(&self) -> &ReferenceScan {
        &self.second
    }

    /// Every observed blob and its preservation reasons, in key order.
    #[must_use]
    pub fn decisions(&self) -> &[BlobDecision] {
        &self.decisions
    }

    /// Every blob with no preservation reason.
    pub fn eligible_blobs(&self) -> impl Iterator<Item = &BlobObjectKey> {
        self.decisions
            .iter()
            .filter(|decision| decision.eligible())
            .map(BlobDecision::key)
    }

    /// The scan observation selected for immediate pre-delete revalidation.
    fn expected_metadata(&self, key: &BlobObjectKey) -> Option<ObjectMetadata> {
        self.expected
            .get(key)
            .map(|entry| ObjectMetadata::new(entry.size(), entry.observation().clone()))
    }
}

/// A separately provisioned destructive identity. It is intentionally not a
/// supertrait of [`crate::audit_restore::AuditRestoreStore`], so the audit
/// reader cannot delete merely because it can enumerate and read.
pub trait BlobCollectionStore {
    /// Revalidate one candidate immediately before deletion.
    fn inspect_blob(
        &self,
        key: &BlobObjectKey,
    ) -> impl Future<Output = Result<ObjectMetadata, StorageError>> + Send;

    /// Delete one candidate conditional on the just-observed metadata.
    ///
    /// The implementation MUST make this condition part of the destructive
    /// operation itself (for example with a storage version or an atomic
    /// compare-and-delete primitive).  A best-effort HEAD followed by an
    /// unconditional delete is not a valid implementation: a concurrent
    /// rewrite between the two calls must return
    /// [`StorageErrorKind::IntegrityConflict`] and leave the object alive.
    fn delete_blob(
        &self,
        key: &BlobObjectKey,
        observed: &ObjectMetadata,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// The canonical evidence produced by a simulation or execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionEvidence {
    bytes: Vec<u8>,
    digest: archivist_protocol::vocabulary::BlobDigest,
    plan_digest: InventoryDigest,
    mode: &'static str,
}

impl CollectionEvidence {
    /// The canonical `archivist.collection-evidence/v1` document.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The digest of the canonical evidence document.
    #[must_use]
    pub const fn digest(&self) -> &archivist_protocol::vocabulary::BlobDigest {
        &self.digest
    }

    /// The stable collection-plan identity covered by this evidence.
    #[must_use]
    pub const fn plan_digest(&self) -> &InventoryDigest {
        &self.plan_digest
    }

    /// `simulation` or `execution`.
    #[must_use]
    pub const fn mode(&self) -> &str {
        self.mode
    }
}

/// The result of one collection simulation or execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionReport {
    evidence: CollectionEvidence,
    deleted: Vec<BlobObjectKey>,
}

impl CollectionReport {
    /// The canonical audit evidence.
    #[must_use]
    pub const fn evidence(&self) -> &CollectionEvidence {
        &self.evidence
    }

    /// The blobs the deletion identity confirmed as deleted.
    #[must_use]
    pub fn deleted(&self) -> &[BlobObjectKey] {
        &self.deleted
    }
}

/// One immutable, append-only journal entry for a collection attempt.
///
/// The journal is separate from the final report because deletion is a
/// multi-step operation.  A `delete-pending` entry is committed before the
/// conditional delete call; the completion entry follows it.  If a worker
/// stops between those entries, a subsequent worker can validate the chain,
/// re-HEAD the object, and continue without losing the fact that an attempt
/// was already in flight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CollectionAuditEvent {
    plan_digest: InventoryDigest,
    sequence: u64,
    previous_digest: Option<archivist_protocol::vocabulary::BlobDigest>,
    key: BlobObjectKey,
    outcome: ActionOutcome,
}

impl CollectionAuditEvent {
    /// Create an immutable journal entry.
    #[must_use]
    pub fn new(
        plan_digest: InventoryDigest,
        sequence: u64,
        previous_digest: Option<archivist_protocol::vocabulary::BlobDigest>,
        key: BlobObjectKey,
        outcome: ActionOutcome,
    ) -> Self {
        Self {
            plan_digest,
            sequence,
            previous_digest,
            key,
            outcome,
        }
    }

    /// The stable identity of the collection plan this event belongs to.
    #[must_use]
    pub const fn plan_digest(&self) -> &InventoryDigest {
        &self.plan_digest
    }

    /// The append-only sequence number.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The preceding event's digest, if this is not the first event.
    #[must_use]
    pub const fn previous_digest(&self) -> Option<&archivist_protocol::vocabulary::BlobDigest> {
        self.previous_digest.as_ref()
    }

    /// The scoped blob key named by this event.
    #[must_use]
    pub const fn key(&self) -> &BlobObjectKey {
        &self.key
    }

    /// The action outcome recorded by this event.
    #[must_use]
    pub const fn outcome(&self) -> ActionOutcome {
        self.outcome
    }

    /// The canonical immutable `archivist.collection-audit/v1` bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut object = Object::new();
        object.set(
            "schema",
            Value::Text("archivist.collection-audit/v1".to_owned()),
        );
        object.set("plan_digest", Value::Text(self.plan_digest.to_hex()));
        object.set(
            "sequence",
            Value::Int(i64::try_from(self.sequence).unwrap_or(i64::MAX)),
        );
        object.set(
            "previous_digest",
            self.previous_digest
                .as_ref()
                .map_or(Value::Null, |digest| Value::Text(digest.to_hex())),
        );
        object.set("blob_key", Value::Text(self.key.as_str().to_owned()));
        object.set("outcome", Value::Text(self.outcome.token().to_owned()));
        Value::Object(object).canonical_bytes()
    }

    /// The content-addressed digest of the immutable event.
    #[must_use]
    pub fn digest(&self) -> archivist_protocol::vocabulary::BlobDigest {
        archivist_protocol::vocabulary::BlobDigest::from_raw(sha256::digest(
            &self.canonical_bytes(),
        ))
    }
}

/// The append-only audit identity used by resumable collection execution.
///
/// Implementations must persist events at immutable, derived keys and reject
/// a conflicting replay of an occupied sequence.  The collector validates
/// the returned chain before it performs any HEAD or delete operation, so an
/// unavailable, truncated, reordered, or conflicting journal fails closed.
pub trait CollectionAuditStore {
    /// Load the immutable event chain for one plan.
    fn events(
        &self,
        plan_digest: &InventoryDigest,
    ) -> impl Future<Output = Result<Vec<CollectionAuditEvent>, StorageError>> + Send;

    /// Append one event without replacing an existing event.
    fn append_event(
        &self,
        event: &CollectionAuditEvent,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// The two-pass blob collector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobCollector {
    config: CollectionConfig,
}

impl Default for BlobCollector {
    fn default() -> Self {
        Self::new(CollectionConfig::default())
    }
}

impl BlobCollector {
    /// Compose a collector. The configuration is disabled by default.
    #[must_use]
    pub const fn new(config: CollectionConfig) -> Self {
        Self { config }
    }

    /// The collector's execution configuration.
    #[must_use]
    pub const fn config(self) -> CollectionConfig {
        self.config
    }

    /// Build a deterministic two-pass mark plan.
    ///
    /// # Errors
    /// [`CollectionErrorKind::ScanSeparation`] when the scans are not ordered
    /// and at least 24 hours apart, or another [`CollectionErrorKind`]
    /// described by [`CollectionPlan::build`].
    pub fn plan<I>(
        self,
        first: ReferenceScan,
        second: ReferenceScan,
        retention: I,
        evaluated_at: Timestamp,
    ) -> Result<CollectionPlan, CollectionError>
    where
        I: IntoIterator<Item = OccurrenceRetention>,
    {
        CollectionPlan::build(first, second, retention, evaluated_at)
    }

    /// Simulate collection without requiring or invoking a deletion identity.
    #[must_use]
    pub fn simulate(self, plan: &CollectionPlan) -> CollectionReport {
        let outcomes = plan
            .decisions
            .iter()
            .filter(|decision| decision.eligible())
            .map(|decision| (decision.key.clone(), ActionOutcome::WouldDelete))
            .collect::<Vec<_>>();
        self.report(plan, "simulation", &outcomes)
    }

    /// Execute the sweep with immediate pre-delete revalidation.
    ///
    /// A disabled collector still emits evidence, but every eligible action is
    /// recorded as `disabled` and no store method is called.
    pub async fn execute<S>(&self, plan: &CollectionPlan, store: &S) -> CollectionReport
    where
        S: BlobCollectionStore + Sync,
    {
        let mut outcomes = Vec::new();
        let mut deleted = Vec::new();
        for decision in plan.decisions.iter().filter(|decision| decision.eligible()) {
            if !self.config.is_enabled() {
                outcomes.push((decision.key.clone(), ActionOutcome::Disabled));
                continue;
            }
            let Some(expected) = plan.expected_metadata(&decision.key) else {
                outcomes.push((decision.key.clone(), ActionOutcome::UnreadableBeforeDelete));
                continue;
            };
            let Ok(observed) = store.inspect_blob(&decision.key).await else {
                outcomes.push((decision.key.clone(), ActionOutcome::UnreadableBeforeDelete));
                continue;
            };
            if !metadata_matches(&expected, &observed) {
                outcomes.push((decision.key.clone(), ActionOutcome::ChangedBeforeDelete));
                continue;
            }
            match store.delete_blob(&decision.key, &observed).await {
                Ok(()) => {
                    deleted.push(decision.key.clone());
                    outcomes.push((decision.key.clone(), ActionOutcome::Deleted));
                }
                Err(error) if error.kind() == StorageErrorKind::IntegrityConflict => {
                    outcomes.push((decision.key.clone(), ActionOutcome::ChangedBeforeDelete));
                }
                Err(_) => outcomes.push((decision.key.clone(), ActionOutcome::DeleteFailed)),
            }
        }
        let mut report = self.report(plan, "execution", &outcomes);
        report.deleted = deleted;
        report
    }

    /// Execute with an immutable journal and resume only the unfinished part
    /// of a previous attempt.
    ///
    /// The journal is read and validated before the first storage operation.
    /// Each enabled candidate gets a `delete-pending` event after its final
    /// HEAD succeeds and before the conditional delete is called.  A worker
    /// that stops after that event can safely resume: a later HEAD decides
    /// whether the object is still the same candidate, and a prior `deleted`
    /// event suppresses a duplicate delete call.  Audit read/write failures
    /// are returned before or between actions; they never turn into an
    /// unrecorded destructive operation.
    ///
    /// # Errors
    /// Returns the audit store's content-safe storage error when the journal
    /// cannot be read or an immutable event cannot be appended, or when the
    /// previously persisted journal fails its chain validation.
    #[allow(clippy::too_many_lines)]
    pub async fn execute_resumable<S, A>(
        &self,
        plan: &CollectionPlan,
        store: &S,
        audit: &A,
    ) -> Result<CollectionReport, StorageError>
    where
        S: BlobCollectionStore + Sync,
        A: CollectionAuditStore + Sync,
    {
        let plan_digest = plan.plan_digest();
        let mut events = audit.events(&plan_digest).await?;
        validate_audit_chain(plan, &plan_digest, &events)?;

        let mut next_sequence = u64::try_from(events.len()).unwrap_or(u64::MAX);
        let mut previous_digest = events.last().map(CollectionAuditEvent::digest);
        let completed = events
            .iter()
            .filter(|event| event.outcome() == ActionOutcome::Deleted)
            .map(|event| event.key().clone())
            .collect::<BTreeSet<_>>();
        let mut outcomes = Vec::new();
        let mut deleted = completed.iter().cloned().collect::<Vec<_>>();

        for decision in plan.decisions.iter().filter(|decision| decision.eligible()) {
            if completed.contains(&decision.key) {
                outcomes.push((decision.key.clone(), ActionOutcome::Deleted));
                continue;
            }

            if !self.config.is_enabled() {
                let outcome = ActionOutcome::Disabled;
                append_audit_event(
                    audit,
                    &mut events,
                    &plan_digest,
                    &mut next_sequence,
                    &mut previous_digest,
                    decision.key.clone(),
                    outcome,
                )
                .await?;
                outcomes.push((decision.key.clone(), outcome));
                continue;
            }

            let Some(expected) = plan.expected_metadata(&decision.key) else {
                let outcome = ActionOutcome::UnreadableBeforeDelete;
                append_audit_event(
                    audit,
                    &mut events,
                    &plan_digest,
                    &mut next_sequence,
                    &mut previous_digest,
                    decision.key.clone(),
                    outcome,
                )
                .await?;
                outcomes.push((decision.key.clone(), outcome));
                continue;
            };
            let Ok(observed) = store.inspect_blob(&decision.key).await else {
                let outcome = ActionOutcome::UnreadableBeforeDelete;
                append_audit_event(
                    audit,
                    &mut events,
                    &plan_digest,
                    &mut next_sequence,
                    &mut previous_digest,
                    decision.key.clone(),
                    outcome,
                )
                .await?;
                outcomes.push((decision.key.clone(), outcome));
                continue;
            };
            if !metadata_matches(&expected, &observed) {
                let outcome = ActionOutcome::ChangedBeforeDelete;
                append_audit_event(
                    audit,
                    &mut events,
                    &plan_digest,
                    &mut next_sequence,
                    &mut previous_digest,
                    decision.key.clone(),
                    outcome,
                )
                .await?;
                outcomes.push((decision.key.clone(), outcome));
                continue;
            }

            append_audit_event(
                audit,
                &mut events,
                &plan_digest,
                &mut next_sequence,
                &mut previous_digest,
                decision.key.clone(),
                ActionOutcome::DeletePending,
            )
            .await?;

            let outcome = match store.delete_blob(&decision.key, &observed).await {
                Ok(()) => {
                    deleted.push(decision.key.clone());
                    ActionOutcome::Deleted
                }
                Err(error) if error.kind() == StorageErrorKind::IntegrityConflict => {
                    ActionOutcome::ChangedBeforeDelete
                }
                Err(_) => ActionOutcome::DeleteFailed,
            };
            append_audit_event(
                audit,
                &mut events,
                &plan_digest,
                &mut next_sequence,
                &mut previous_digest,
                decision.key.clone(),
                outcome,
            )
            .await?;
            outcomes.push((decision.key.clone(), outcome));
        }

        let mut report = self.report(plan, "execution", &outcomes);
        report.deleted = deleted;
        Ok(report)
    }

    fn report(
        self,
        plan: &CollectionPlan,
        mode: &'static str,
        actions: &[(BlobObjectKey, ActionOutcome)],
    ) -> CollectionReport {
        let evidence = render_evidence(plan, mode, self.config.is_enabled(), actions);
        let deleted = actions
            .iter()
            .filter(|(_, outcome)| *outcome == ActionOutcome::Deleted)
            .map(|(key, _)| key.clone())
            .collect();
        CollectionReport { evidence, deleted }
    }
}

fn render_evidence(
    plan: &CollectionPlan,
    mode: &'static str,
    enabled: bool,
    actions: &[(BlobObjectKey, ActionOutcome)],
) -> CollectionEvidence {
    let scan_value = |scan: &ReferenceScan| {
        let mut object = Object::new();
        object.set(
            "completed_at",
            Value::Text(scan.completed_at().as_str().to_owned()),
        );
        object.set(
            "inventory_digest",
            Value::Text(scan.inventory_digest().to_hex()),
        );
        object.set("blob_count", count_value(scan.blobs.len()));
        object.set("reference_count", count_value(scan.reference_count()));
        Value::Object(object)
    };
    let mut root = Object::new();
    root.set("schema", Value::Text(EVIDENCE_SCHEMA.to_owned()));
    root.set("mode", Value::Text(mode.to_owned()));
    root.set("enabled", Value::Bool(enabled));
    root.set("plan_digest", Value::Text(plan.plan_digest().to_hex()));
    root.set("tenant_id", Value::Text(plan.tenant.as_str().to_owned()));
    root.set(
        "evaluated_at",
        Value::Text(plan.evaluated_at.as_str().to_owned()),
    );
    root.set("first_scan", scan_value(&plan.first));
    root.set("second_scan", scan_value(&plan.second));

    let decisions = plan
        .decisions
        .iter()
        .map(|decision| {
            let mut object = Object::new();
            object.set("blob_key", Value::Text(decision.key.as_str().to_owned()));
            object.set("eligible", Value::Bool(decision.reasons.is_empty()));
            object.set(
                "reasons",
                Value::Array(
                    decision
                        .reasons
                        .iter()
                        .map(|reason| Value::Text(reason.token().to_owned()))
                        .collect(),
                ),
            );
            Value::Object(object)
        })
        .collect();
    root.set("decisions", Value::Array(decisions));

    let action_values = actions
        .iter()
        .map(|(key, outcome)| {
            let mut object = Object::new();
            object.set("blob_key", Value::Text(key.as_str().to_owned()));
            object.set("outcome", Value::Text(outcome.token().to_owned()));
            Value::Object(object)
        })
        .collect();
    root.set("actions", Value::Array(action_values));
    let bytes = Value::Object(root).canonical_bytes();
    let digest = archivist_protocol::vocabulary::BlobDigest::from_raw(sha256::digest(&bytes));
    CollectionEvidence {
        bytes,
        digest,
        plan_digest: plan.plan_digest(),
        mode,
    }
}

fn count_value(value: usize) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

fn plan_digest(plan: &CollectionPlan) -> InventoryDigest {
    let mut frame = archivist_protocol::derivation::FrameBuilder::new("collection-plan-v1");
    frame.push_text(plan.tenant.as_str());
    frame.push_text(plan.evaluated_at.as_str());
    frame.push_text(plan.first.completed_at().as_str());
    frame.push_digest32(plan.first.inventory_digest().as_raw());
    frame.push_text(plan.second.completed_at().as_str());
    frame.push_digest32(plan.second.inventory_digest().as_raw());
    frame.push_u63(plan.decisions.len() as u64);
    for decision in &plan.decisions {
        frame.push_text(decision.key.as_str());
        frame.push_u63(decision.reasons.len() as u64);
        for reason in &decision.reasons {
            frame.push_text(reason.token());
        }
    }
    InventoryDigest::from_raw(frame.finish())
}

fn validate_audit_chain(
    plan: &CollectionPlan,
    plan_digest: &InventoryDigest,
    events: &[CollectionAuditEvent],
) -> Result<(), StorageError> {
    let mut previous = None;
    for (index, event) in events.iter().enumerate() {
        if event.plan_digest() != plan_digest {
            return Err(StorageError::new(
                StorageErrorKind::InventoryFault,
                AUDIT_PLAN_MISMATCH,
            ));
        }
        if event.sequence() != u64::try_from(index).unwrap_or(u64::MAX) {
            return Err(StorageError::new(
                StorageErrorKind::InventoryFault,
                AUDIT_SEQUENCE,
            ));
        }
        if event.previous_digest() != previous.as_ref() {
            return Err(StorageError::new(
                StorageErrorKind::InventoryFault,
                AUDIT_CHAIN,
            ));
        }
        let Some(decision) = plan
            .decisions
            .iter()
            .find(|decision| decision.key == *event.key())
        else {
            return Err(StorageError::new(
                StorageErrorKind::InventoryFault,
                AUDIT_UNKNOWN_CANDIDATE,
            ));
        };
        if !decision.eligible()
            && matches!(
                event.outcome(),
                ActionOutcome::DeletePending
                    | ActionOutcome::Deleted
                    | ActionOutcome::ChangedBeforeDelete
                    | ActionOutcome::UnreadableBeforeDelete
                    | ActionOutcome::DeleteFailed
            )
        {
            return Err(StorageError::new(
                StorageErrorKind::InventoryFault,
                AUDIT_UNKNOWN_CANDIDATE,
            ));
        }
        previous = Some(event.digest());
    }
    Ok(())
}

async fn append_audit_event<A>(
    audit: &A,
    events: &mut Vec<CollectionAuditEvent>,
    plan_digest: &InventoryDigest,
    next_sequence: &mut u64,
    previous_digest: &mut Option<archivist_protocol::vocabulary::BlobDigest>,
    key: BlobObjectKey,
    outcome: ActionOutcome,
) -> Result<(), StorageError>
where
    A: CollectionAuditStore + Sync,
{
    let event =
        CollectionAuditEvent::new(*plan_digest, *next_sequence, *previous_digest, key, outcome);
    audit.append_event(&event).await?;
    *previous_digest = Some(event.digest());
    *next_sequence = next_sequence.saturating_add(1);
    events.push(event);
    Ok(())
}

fn has_commitment(entry: &InventoryEntry) -> bool {
    entry.observation().etag().is_some() || entry.observation().storage_version().is_some()
}

fn stable_metadata_equal(left: &InventoryEntry, right: &InventoryEntry) -> bool {
    left.size() == right.size()
        && left.observation().etag() == right.observation().etag()
        && left.observation().storage_version() == right.observation().storage_version()
}

fn metadata_matches(expected: &ObjectMetadata, observed: &ObjectMetadata) -> bool {
    expected.size() == observed.size()
        && expected.observation().etag() == observed.observation().etag()
        && expected.observation().storage_version() == observed.observation().storage_version()
        && (expected.observation().etag().is_some()
            || expected.observation().storage_version().is_some())
}

fn grace_elapsed(anchor: &Timestamp, at: &Timestamp) -> bool {
    let Some((seconds, nanos)) = instant(anchor) else {
        return false;
    };
    let Some(close) = seconds.checked_add(DELETION_GRACE_SECONDS) else {
        return false;
    };
    instant(at).is_some_and(|at| at >= (close, nanos))
}

fn instant(stamp: &Timestamp) -> Option<(i64, u32)> {
    if !stamp.calendar_valid() {
        return None;
    }
    let bytes = stamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, byte| acc * 10 + i64::from(byte - b'0'))
    };
    let year = number(&bytes[0..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    let seconds = days_from_civil(year, month, day)
        .checked_mul(86_400)?
        .checked_add(hour.checked_mul(3_600)?)?
        .checked_add(minute.checked_mul(60)?)?
        .checked_add(second)?;
    let nanoseconds = if bytes.len() > 20 {
        let digits = &bytes[20..bytes.len() - 1];
        let mut nanoseconds = 0u32;
        for digit in digits {
            nanoseconds = nanoseconds
                .checked_mul(10)?
                .checked_add(u32::from(digit - b'0'))?;
        }
        for _ in digits.len()..9 {
            nanoseconds = nanoseconds.checked_mul(10)?;
        }
        nanoseconds
    } else {
        0
    };
    Some((seconds, nanoseconds))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_offset = if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * (month + month_offset) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit_restore::InventoryPage;
    use crate::metadata::{ObjectTag, Observation, StorageVersionId};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const BLOB_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OCC_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OCC_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const KEY_A: &str = "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/blobs/zstd-v1/sha256/aa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.zst";
    const KEY_B: &str = "tenants/0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b/v1/raw/blobs/zstd-v1/sha256/bb/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.zst";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).unwrap()
    }

    fn blob(digest: &str) -> BlobObjectKey {
        BlobObjectKey::new(
            &tenant(),
            archivist_protocol::vocabulary::StorageProfile::ZstdV1,
            &archivist_protocol::vocabulary::BlobDigest::parse(digest).unwrap(),
        )
    }

    fn occurrence(text: &str) -> OccurrenceId {
        OccurrenceId::parse(text).unwrap()
    }

    fn inventory(keys: &[(&str, &str)]) -> FrozenInventory {
        let entries = keys
            .iter()
            .map(|(key, tag)| {
                InventoryEntry::new(
                    crate::audit_restore::InventoryKey::parse(key).unwrap(),
                    42,
                    Observation::new(
                        Some(ObjectTag::parse(tag).unwrap()),
                        Some(StorageVersionId::parse(&format!("v-{tag}")).unwrap()),
                        Timestamp::parse("2026-09-01T00:00:00Z").unwrap(),
                    ),
                )
            })
            .collect::<Vec<_>>();
        FrozenInventory::from_pages(
            &InventoryScope::TenantRaw(tenant()),
            vec![Ok(InventoryPage::new(entries, None))],
        )
        .unwrap()
    }

    fn scan(
        at: &str,
        keys: &[(&str, &str)],
        references: Vec<OccurrenceReference>,
    ) -> ReferenceScan {
        ReferenceScan::new(&inventory(keys), Timestamp::parse(at).unwrap(), references).unwrap()
    }

    fn empty_scan(at: &str) -> ReferenceScan {
        scan(at, &[(KEY_A, "a"), (KEY_B, "b")], Vec::new())
    }

    fn tombstone(at: &str) -> RetentionDecision {
        RetentionDecision::new(Some(Timestamp::parse(at).unwrap()), false).unwrap()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    struct MockCollectionStore {
        inspections: AtomicUsize,
        deletions: AtomicUsize,
    }

    impl MockCollectionStore {
        fn observed(key: &BlobObjectKey) -> ObjectMetadata {
            let (tag, version) = if key.as_str().contains("/aa/") {
                ("a", "v-a")
            } else {
                ("b", "v-b")
            };
            ObjectMetadata::new(
                42,
                Observation::new(
                    Some(ObjectTag::parse(tag).unwrap()),
                    Some(StorageVersionId::parse(version).unwrap()),
                    Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
                ),
            )
        }
    }

    impl BlobCollectionStore for MockCollectionStore {
        async fn inspect_blob(&self, key: &BlobObjectKey) -> Result<ObjectMetadata, StorageError> {
            self.inspections.fetch_add(1, Ordering::SeqCst);
            Ok(Self::observed(key))
        }

        async fn delete_blob(
            &self,
            _key: &BlobObjectKey,
            _observed: &ObjectMetadata,
        ) -> Result<(), StorageError> {
            self.deletions.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[test]
    fn default_collector_is_disabled_and_simulation_never_deletes() {
        let collector = BlobCollector::default();
        assert!(!collector.config().is_enabled());
        let plan = collector
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let report = collector.simulate(&plan);
        assert_eq!(report.deleted(), &[]);
        assert_eq!(report.evidence().mode(), "simulation");
        let value = archivist_protocol::json::parse(report.evidence().canonical_bytes()).unwrap();
        assert!(matches!(value, Value::Object(_)));
    }

    #[test]
    fn disabled_execution_emits_evidence_without_calling_delete_identity() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let store = MockCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
        };
        let report = block_on(BlobCollector::default().execute(&plan, &store));
        assert!(report.deleted().is_empty());
        assert_eq!(store.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(store.deletions.load(Ordering::SeqCst), 0);
        assert_eq!(report.evidence().mode(), "execution");
        assert!(
            report
                .evidence()
                .canonical_bytes()
                .windows(b"disabled".len())
                .any(|window| window == b"disabled")
        );
    }

    #[test]
    fn enabled_execution_revalidates_then_deletes_only_marked_candidates() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let store = MockCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
        };
        let report =
            block_on(BlobCollector::new(CollectionConfig::enabled()).execute(&plan, &store));
        assert_eq!(report.deleted().len(), 2);
        assert_eq!(store.inspections.load(Ordering::SeqCst), 2);
        assert_eq!(store.deletions.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn two_pass_mark_requires_retained_occurrences_to_be_absent() {
        let shared = blob(BLOB_A);
        let first = empty_scan("2026-09-01T00:00:00Z");
        let second = empty_scan("2026-09-02T00:00:00Z");
        let plan = BlobCollector::default()
            .plan(
                first,
                second,
                vec![OccurrenceRetention::new(
                    occurrence(OCC_A),
                    shared.clone(),
                    RetentionDecision::indefinite(),
                )],
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let shared_decision = plan
            .decisions()
            .iter()
            .find(|decision| decision.key() == &shared)
            .unwrap();
        assert!(!shared_decision.eligible());
        assert!(
            shared_decision
                .reasons()
                .contains(&DecisionReason::RetainedReferenceOutsideScans)
        );
    }

    #[test]
    fn shared_blob_stays_when_any_referencing_occurrence_is_retained() {
        let shared = blob(BLOB_A);
        let references = vec![
            OccurrenceReference::new(occurrence(OCC_A), shared.clone()),
            OccurrenceReference::new(occurrence(OCC_B), shared.clone()),
        ];
        let first = scan(
            "2026-09-01T00:00:00Z",
            &[(KEY_A, "a"), (KEY_B, "b")],
            references.clone(),
        );
        let second = scan(
            "2026-09-02T00:00:00Z",
            &[(KEY_A, "a"), (KEY_B, "b")],
            references,
        );
        let plan = BlobCollector::default()
            .plan(
                first,
                second,
                vec![OccurrenceRetention::new(
                    occurrence(OCC_A),
                    shared.clone(),
                    tombstone("2026-08-01T00:00:00Z"),
                )],
                Timestamp::parse("2026-09-02T00:00:00Z").unwrap(),
            )
            .unwrap();
        let decision = plan
            .decisions()
            .iter()
            .find(|decision| decision.key() == &shared)
            .unwrap();
        assert!(!decision.eligible());
        assert!(
            decision
                .reasons()
                .contains(&DecisionReason::RetainedReferenceFirstScan)
        );
        assert!(
            decision
                .reasons()
                .contains(&DecisionReason::RetainedReferenceSecondScan)
        );
    }

    #[test]
    fn expired_tombstones_can_release_a_blob_only_after_grace() {
        let key = blob(BLOB_A);
        let ref_a = OccurrenceReference::new(occurrence(OCC_A), key.clone());
        let first = scan(
            "2026-09-01T00:00:00Z",
            &[(KEY_A, "a"), (KEY_B, "b")],
            vec![ref_a.clone()],
        );
        let second = scan(
            "2026-09-02T00:00:00Z",
            &[(KEY_A, "a"), (KEY_B, "b")],
            vec![ref_a],
        );
        let before = BlobCollector::default()
            .plan(
                first.clone(),
                second.clone(),
                vec![OccurrenceRetention::new(
                    occurrence(OCC_A),
                    key.clone(),
                    tombstone("2026-08-10T00:00:00Z"),
                )],
                Timestamp::parse("2026-08-20T00:00:00Z").unwrap(),
            )
            .unwrap();
        assert!(
            !before
                .decisions()
                .iter()
                .find(|decision| decision.key() == &key)
                .unwrap()
                .eligible()
        );
        let after = BlobCollector::default()
            .plan(
                first,
                second,
                vec![OccurrenceRetention::new(
                    occurrence(OCC_A),
                    key.clone(),
                    tombstone("2026-08-01T00:00:00Z"),
                )],
                Timestamp::parse("2026-09-02T00:00:00Z").unwrap(),
            )
            .unwrap();
        assert!(
            after
                .decisions()
                .iter()
                .find(|decision| decision.key() == &key)
                .unwrap()
                .eligible()
        );
    }

    #[test]
    fn scans_must_be_at_least_a_day_apart() {
        let error = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-01T23:59:59Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap_err();
        assert_eq!(error.kind(), CollectionErrorKind::ScanSeparation);
    }

    #[test]
    fn evidence_is_deterministic_and_hashes_its_canonical_bytes() {
        let collector = BlobCollector::default();
        let make = || {
            collector
                .plan(
                    empty_scan("2026-09-01T00:00:00Z"),
                    empty_scan("2026-09-02T00:00:00Z"),
                    Vec::<OccurrenceRetention>::new(),
                    Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
                )
                .unwrap()
        };
        let left = collector.simulate(&make());
        let right = collector.simulate(&make());
        assert_eq!(
            left.evidence().canonical_bytes(),
            right.evidence().canonical_bytes()
        );
        assert_eq!(
            left.evidence().digest().to_hex(),
            archivist_protocol::sha256::encode_hex(&sha256::digest(
                left.evidence().canonical_bytes()
            ))
        );
    }

    #[test]
    fn references_are_rejected_when_they_are_not_in_the_frozen_inventory() {
        let missing = blob(BLOB_A);
        let result = ReferenceScan::new(
            &inventory(&[(KEY_B, "b")]),
            Timestamp::parse("2026-09-01T00:00:00Z").unwrap(),
            [OccurrenceReference::new(occurrence(OCC_A), missing)],
        );
        assert_eq!(
            result.unwrap_err().kind(),
            CollectionErrorKind::InvalidInput
        );
    }

    #[test]
    fn a_candidate_must_have_the_same_identity_in_both_inventories() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                scan("2026-09-02T00:00:00Z", &[(KEY_A, "a")], Vec::new()),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let present = plan
            .decisions()
            .iter()
            .find(|decision| decision.key().as_str() == KEY_A)
            .unwrap();
        assert!(present.eligible());
        let absent = plan
            .decisions()
            .iter()
            .find(|decision| decision.key().as_str() == KEY_B)
            .unwrap();
        assert!(!absent.eligible());
        assert!(
            absent
                .reasons()
                .contains(&DecisionReason::MissingFromSecondScan)
        );
    }

    #[test]
    fn changed_identity_between_scans_survives_without_a_delete_attempt() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                scan(
                    "2026-09-02T00:00:00Z",
                    &[(KEY_A, "changed"), (KEY_B, "b")],
                    Vec::new(),
                ),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let changed = plan
            .decisions()
            .iter()
            .find(|decision| decision.key().as_str() == KEY_A)
            .unwrap();
        assert!(!changed.eligible());
        assert!(
            changed
                .reasons()
                .contains(&DecisionReason::ChangedBetweenScans)
        );
    }

    struct FailingCollectionStore {
        inspections: AtomicUsize,
        deletions: AtomicUsize,
        inspect_error: bool,
        concurrent_mutation: bool,
    }

    impl BlobCollectionStore for FailingCollectionStore {
        async fn inspect_blob(&self, key: &BlobObjectKey) -> Result<ObjectMetadata, StorageError> {
            self.inspections.fetch_add(1, Ordering::SeqCst);
            if self.inspect_error {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            Ok(MockCollectionStore::observed(key))
        }

        async fn delete_blob(
            &self,
            _key: &BlobObjectKey,
            _observed: &ObjectMetadata,
        ) -> Result<(), StorageError> {
            self.deletions.fetch_add(1, Ordering::SeqCst);
            if self.concurrent_mutation {
                return Err(StorageError::of_kind(StorageErrorKind::IntegrityConflict));
            }
            Ok(())
        }
    }

    #[test]
    fn unreadable_and_concurrently_changed_candidates_survive() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let unreadable = FailingCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
            inspect_error: true,
            concurrent_mutation: false,
        };
        let report =
            block_on(BlobCollector::new(CollectionConfig::enabled()).execute(&plan, &unreadable));
        assert!(report.deleted().is_empty());
        assert_eq!(unreadable.deletions.load(Ordering::SeqCst), 0);

        let changed = FailingCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
            inspect_error: false,
            concurrent_mutation: true,
        };
        let report =
            block_on(BlobCollector::new(CollectionConfig::enabled()).execute(&plan, &changed));
        assert!(report.deleted().is_empty());
        assert_eq!(changed.deletions.load(Ordering::SeqCst), 2);
        assert!(
            report
                .evidence()
                .canonical_bytes()
                .windows(b"changed-before-delete".len())
                .any(|window| window == b"changed-before-delete")
        );
    }

    struct InMemoryAudit {
        events: std::sync::Mutex<Vec<CollectionAuditEvent>>,
        fail_reads: bool,
        fail_appends: bool,
    }

    impl CollectionAuditStore for InMemoryAudit {
        async fn events(
            &self,
            _plan_digest: &InventoryDigest,
        ) -> Result<Vec<CollectionAuditEvent>, StorageError> {
            if self.fail_reads {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            Ok(self.events.lock().expect("audit lock").clone())
        }

        async fn append_event(&self, event: &CollectionAuditEvent) -> Result<(), StorageError> {
            if self.fail_appends {
                return Err(StorageError::of_kind(StorageErrorKind::Unavailable));
            }
            self.events.lock().expect("audit lock").push(event.clone());
            Ok(())
        }
    }

    #[test]
    fn resumable_execution_uses_immutable_events_to_skip_completed_work() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let audit = InMemoryAudit {
            events: std::sync::Mutex::new(Vec::new()),
            fail_reads: false,
            fail_appends: false,
        };
        let store = MockCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
        };
        let first = block_on(
            BlobCollector::new(CollectionConfig::enabled())
                .execute_resumable(&plan, &store, &audit),
        )
        .unwrap();
        assert_eq!(first.deleted().len(), 2);
        let first_delete_count = store.deletions.load(Ordering::SeqCst);
        let events = audit.events.lock().expect("audit lock").clone();
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].outcome(), ActionOutcome::DeletePending);
        assert_eq!(events[1].outcome(), ActionOutcome::Deleted);
        assert_eq!(events[1].previous_digest(), Some(&events[0].digest()));
        assert_eq!(first.evidence().plan_digest(), &plan.plan_digest());

        let second = block_on(
            BlobCollector::new(CollectionConfig::enabled())
                .execute_resumable(&plan, &store, &audit),
        )
        .unwrap();
        assert_eq!(second.deleted().len(), 2);
        assert_eq!(store.deletions.load(Ordering::SeqCst), first_delete_count);
    }

    #[test]
    fn audit_read_failure_is_fail_closed_before_head_or_delete() {
        let plan = BlobCollector::default()
            .plan(
                empty_scan("2026-09-01T00:00:00Z"),
                empty_scan("2026-09-02T00:00:00Z"),
                Vec::<OccurrenceRetention>::new(),
                Timestamp::parse("2026-10-01T00:00:00Z").unwrap(),
            )
            .unwrap();
        let audit = InMemoryAudit {
            events: std::sync::Mutex::new(Vec::new()),
            fail_reads: true,
            fail_appends: false,
        };
        let store = MockCollectionStore {
            inspections: AtomicUsize::new(0),
            deletions: AtomicUsize::new(0),
        };
        assert!(
            block_on(
                BlobCollector::new(CollectionConfig::enabled())
                    .execute_resumable(&plan, &store, &audit)
            )
            .is_err()
        );
        assert_eq!(store.inspections.load(Ordering::SeqCst), 0);
        assert_eq!(store.deletions.load(Ordering::SeqCst), 0);
    }
}
