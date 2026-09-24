// SPDX-License-Identifier: Apache-2.0

//! The authorized archive exporter (plan Phase 10, Section 7.10): the
//! offline act that turns one verified `export-approval-v1` into exported
//! raw bytes plus the receipt core a receipt key signs.
//!
//! # Authority is bound before any byte moves
//!
//! The exporter never sees a signed record and never verifies a signature:
//! cryptography is `archivist-auth`'s alone (crate boundary rule 5). What
//! it takes instead is an [`ExportGrant`] — the plain-data shadow of an
//! approval a caller **already verified** through
//! `archivist_auth::export_approval::ExportApproval::verify` and the
//! matching revocation check (plain text, not a link: `archivist-auth`
//! sits across the layer line and is not a dependency of this crate) —
//! plus the frozen inventory and the audit/restore store the approval's
//! tenant is readable through. Before one read it re-checks, fail closed,
//! everything that makes those bytes releasable:
//!
//! - **Tenant and scope** — the inventory froze exactly the grant tenant's
//!   raw prefix ([`InventoryScope::TenantRaw`]).
//! - **Frozen inventory** — the inventory's pinned digest equals the
//!   digest the approval bound; a different freeze is a different archive.
//! - **Exact selection** — every supplied key is an occurrence-manifest
//!   key present in that inventory, and the canonical
//!   `export-selection-v1` digest over the selection
//!   ([`archivist_protocol::derivation::export_selection_digest`]) equals
//!   the digest the approval bound. A subset, superset, substitution, or
//!   an unlisted key is refused.
//! - **Window** — the supplied instant is within the grant's issue and
//!   expiry. (Revocation status is the verification act the caller ran;
//!   this layer's job is to keep the bounds it cannot outlive.)
//!
//! # No ambient storage access
//!
//! The exporter holds no credential and no store: every call takes
//! `&store` and reads only keys in the selection's closure — the selected
//! occurrence manifests, the blobs those manifests reference, and the
//! attestations whose keys name a selected occurrence. Nothing else is
//! enumerated or read, so the read set observable at the store is exactly
//! the approved set. The [`AuditRestoreStore`] identity stays with the
//! caller, and no method hands raw bytes, object paths, or the store
//! itself to anyone: the only egress is the caller-supplied
//! [`ExportSink`], the destination the approval names by class.
//!
//! # Byte-exact, resumable output
//!
//! Items are written one at a time in canonical key-byte order — the same
//! order every other raw consumer uses. Each staged item carries the exact
//! stored bytes, their SHA-256, and the size the freeze recorded; a size
//! disagreement is divergence from the freeze and fails closed. Resume is
//! item-granular: the sink reports which items a previous run of **this
//! export run** already staged (see [`ExportRunId`]), those items are
//! skipped without a store read, and the rest are read and staged — each
//! key at most once per run, so a resume re-reads only the items it is
//! actually missing. A sink
//! holding a different run's state refuses the bind, so two approvals can
//! never interleave output into one destination. The receipt core is
//! emitted only when the last item is staged — a partial export has no
//! receipt, which is exactly what makes a receipt proof of completion.
//!
//! # The receipt core
//!
//! [`ExportReceiptCore`] is the closed, canonical JSON object the
//! composition signs with a certified receipt key: it binds the approval
//! digest, the frozen inventory digest, the exact exported
//! occurrence-set digest, the destination class, the item count, the
//! outcome, and the completion instant (carried as the receipt family's
//! `commit_time`, the member `Receipt::sign` in `archivist-auth` requires).
//! It carries no
//! storage key and no transcript bytes — the selection is bound by
//! digest, never by path.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;

use archivist_protocol::derivation::export_selection_digest;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{BlobDigest, RequestId, TenantId, Timestamp};

use crate::audit_restore::{
    AuditRestoreStore, FrozenInventory, InventoryKey, InventoryScope, ObjectBody,
};
use crate::catalog_source::{AttestationManifest, OccurrenceManifest, RawCatalogIndex};
use crate::error::{StorageError, StorageErrorKind};

/// Namespace of the export receipt record the composition signs.
pub const EXPORT_RECEIPT_SCHEMA: &str = "archivist.export/v1";
/// Record type of the signed export audit receipt.
pub const EXPORT_RECEIPT_RECORD_TYPE: &str = "export-receipt-v1";
/// The only outcome a receipt core from this module carries: the complete
/// selected closure was staged. Failures emit no receipt.
pub const EXPORT_RECEIPT_OUTCOME_COMPLETED: &str = "completed";

/// The plain-data shadow of one verified `export-approval-v1`.
///
/// Built by the composition from a record that already passed
/// `archivist_auth::export_approval::ExportApproval::verify` and the
/// revocation check; the exporter enforces every bound the grant
/// carries against the freeze, the selection, and the clock before any
/// read. The type deliberately holds no capability — it is a statement of
/// what was approved, never the means to read it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportGrantSpec {
    /// Tenant whose raw archive may be exported.
    pub tenant_id: TenantId,
    /// `UUIDv7` handle of the frozen export request.
    pub export_request_id: RequestId,
    /// Digest of the complete signed approval.
    pub approval_digest: BlobDigest,
    /// Digest of the frozen `inventory-v1` the selection was drawn from.
    pub inventory_digest: BlobDigest,
    /// Canonical `export-selection-v1` digest over the selected occurrence
    /// keys.
    pub selected_occurrence_set_digest: BlobDigest,
    /// Human-approved export purpose.
    pub purpose: String,
    /// Closed destination class.
    pub destination_class: String,
    /// Requesting operator identity.
    pub requester: String,
    /// Policy version bound by the decision.
    pub policy_version: u64,
    /// Authority issue instant; the export window's start.
    pub issued_at: Timestamp,
    /// Approval expiry; the export window's end.
    pub expires_at: Timestamp,
}

/// A bound export authorization: the verified approval's facts, checked
/// for internal consistency at bind time and enforced against the store,
/// the freeze, and the clock at export time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportGrant {
    spec: ExportGrantSpec,
}

impl ExportGrant {
    /// Adopt a verified approval's facts after checking the relationships
    /// that must already hold for the shadow to mean anything: calendar
    /// timestamps, non-empty purpose, destination, and requester, and an
    /// expiry strictly after the issue instant. The approval's own
    /// signature, chain, tenant scope, 24-hour lifetime cap, and
    /// revocation status are the verification act's, not the shadow's.
    ///
    /// # Errors
    /// [`ExportError::InvalidBounds`] when a timestamp is not calendar
    /// valid, a bound token is empty, or the window is empty or inverted.
    pub fn bind(spec: ExportGrantSpec) -> Result<Self, ExportError> {
        if !spec.issued_at.calendar_valid()
            || !spec.expires_at.calendar_valid()
            || spec.purpose.is_empty()
            || spec.destination_class.is_empty()
            || spec.requester.is_empty()
            || spec.policy_version == 0
        {
            return Err(ExportError::InvalidBounds);
        }
        if timestamp_cmp(&spec.expires_at, &spec.issued_at) != std::cmp::Ordering::Greater {
            return Err(ExportError::InvalidBounds);
        }
        Ok(Self { spec })
    }

    /// The tenant whose raw prefix may be exported.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.spec.tenant_id
    }

    /// The export request handle.
    #[must_use]
    pub const fn export_request_id(&self) -> &RequestId {
        &self.spec.export_request_id
    }

    /// The digest of the signed approval this grant shadows.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.spec.approval_digest
    }

    /// The frozen inventory digest the approval bound.
    #[must_use]
    pub const fn inventory_digest(&self) -> &BlobDigest {
        &self.spec.inventory_digest
    }

    /// The selected-occurrence-set digest the approval bound.
    #[must_use]
    pub const fn selected_occurrence_set_digest(&self) -> &BlobDigest {
        &self.spec.selected_occurrence_set_digest
    }

    /// The approved destination class.
    #[must_use]
    pub fn destination_class(&self) -> &str {
        self.spec.destination_class.as_str()
    }
}

/// The identity of one authorized export run: the tenant, approval,
/// freeze, and selection a destination's staged state belongs to.
///
/// The sink binds its staged items to this identity, so a destination that
/// already holds a different run's output refuses the new one
/// ([`ExportError::RunMismatch`]) instead of silently mixing exports from
/// two approvals, two freezes, or two selections.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRunId {
    tenant_id: TenantId,
    approval_digest: BlobDigest,
    inventory_digest: BlobDigest,
    selection_digest: BlobDigest,
}

impl ExportRunId {
    /// The run a grant names: its approval, freeze, and selection.
    #[must_use]
    pub fn of(grant: &ExportGrant) -> Self {
        Self {
            tenant_id: grant.spec.tenant_id.clone(),
            approval_digest: grant.spec.approval_digest,
            inventory_digest: grant.spec.inventory_digest,
            selection_digest: grant.spec.selected_occurrence_set_digest,
        }
    }

    /// The tenant being exported.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The approval the run executes.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// The freeze the run exports from.
    #[must_use]
    pub const fn inventory_digest(&self) -> &BlobDigest {
        &self.inventory_digest
    }

    /// The exact selection the run exports.
    #[must_use]
    pub const fn selection_digest(&self) -> &BlobDigest {
        &self.selection_digest
    }
}

/// One fully staged export item: the exact stored bytes' key, size, and
/// SHA-256 digest.
///
/// A completion record exists only for an item whose bytes were fully
/// staged by a previous run of the same [`ExportRunId`] — never for a
/// partial write — so a resume that trusts one re-reads nothing and trusts
/// only whole items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedExportItem {
    key: InventoryKey,
    size: u64,
    digest: [u8; 32],
}

impl CompletedExportItem {
    /// Record one staged item.
    #[must_use]
    pub const fn new(key: InventoryKey, size: u64, digest: [u8; 32]) -> Self {
        Self { key, size, digest }
    }

    /// The staged item's storage key.
    #[must_use]
    pub const fn key(&self) -> &InventoryKey {
        &self.key
    }

    /// The staged byte count.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The SHA-256 of the exact staged bytes.
    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// The export destination: the only egress for raw bytes.
///
/// The sink is supplied by the composition that holds the verified
/// approval — it *is* the approved destination. Its contract makes resume
/// safe: `begin` binds the destination to one [`ExportRunId`] and refuses
/// a different run's state; `completed` reports only whole items a
/// previous run of that same run staged; `put` stages one item's exact
/// bytes and records the completion only after the bytes are fully
/// written, so an interrupted `put` leaves no completion record and the
/// next run re-reads and re-stages that item.
pub trait ExportSink {
    /// Bind the destination to one export run, refusing a different run's
    /// staged state.
    ///
    /// # Errors
    /// [`ExportError::RunMismatch`] when the destination holds state from
    /// a different approval, freeze, or selection, and the sink's own
    /// failures otherwise.
    fn begin(&mut self, run: &ExportRunId) -> impl Future<Output = Result<(), ExportError>> + Send;

    /// The completion record for one key, when a previous run of the bound
    /// export staged it whole.
    ///
    /// # Errors
    /// The sink's own failures.
    fn completed(
        &self,
        key: &InventoryKey,
    ) -> impl Future<Output = Result<Option<CompletedExportItem>, ExportError>> + Send;

    /// Stage one item's exact bytes and record its completion.
    ///
    /// # Errors
    /// The sink's own failures; the exporter fails closed on the first.
    fn put(
        &mut self,
        item: &CompletedExportItem,
        bytes: &[u8],
    ) -> impl Future<Output = Result<(), ExportError>> + Send;
}

/// An in-memory [`ExportSink`] for offline tooling and tests.
///
/// Holds at most one run's state; `begin` enforces the run bind exactly as
/// a durable destination would.
#[derive(Clone, Debug, Default)]
pub struct MemoryExportSink {
    run: Option<ExportRunId>,
    staged: HashMap<String, (CompletedExportItem, Vec<u8>)>,
}

impl MemoryExportSink {
    /// An empty destination.
    #[must_use]
    pub fn new() -> Self {
        Self {
            run: None,
            staged: HashMap::new(),
        }
    }

    /// The exact staged bytes for one key, if this destination holds the
    /// item.
    #[must_use]
    pub fn staged_bytes(&self, key: &str) -> Option<&[u8]> {
        self.staged.get(key).map(|(_, bytes)| bytes.as_slice())
    }

    /// The number of whole items staged.
    #[must_use]
    pub fn len(&self) -> usize {
        self.staged.len()
    }

    /// Whether nothing is staged.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// The staged completion records, in canonical key-byte order.
    #[must_use]
    pub fn staged_items(&self) -> Vec<&CompletedExportItem> {
        let mut items: Vec<&CompletedExportItem> =
            self.staged.values().map(|(item, _)| item).collect();
        items.sort_unstable_by(|a, b| a.key().as_str().as_bytes().cmp(b.key().as_str().as_bytes()));
        items
    }
}

impl ExportSink for MemoryExportSink {
    async fn begin(&mut self, run: &ExportRunId) -> Result<(), ExportError> {
        match &self.run {
            None => {
                self.run = Some(run.clone());
                Ok(())
            }
            Some(existing) if existing == run => Ok(()),
            Some(_) => Err(ExportError::RunMismatch),
        }
    }

    async fn completed(
        &self,
        key: &InventoryKey,
    ) -> Result<Option<CompletedExportItem>, ExportError> {
        Ok(self.staged.get(key.as_str()).map(|(item, _)| item.clone()))
    }

    async fn put(&mut self, item: &CompletedExportItem, bytes: &[u8]) -> Result<(), ExportError> {
        self.staged.insert(
            item.key().as_str().to_owned(),
            (item.clone(), bytes.to_vec()),
        );
        Ok(())
    }
}

/// The unsigned audit receipt core one completed export emits: the closed,
/// canonical object the composition signs with a certified receipt key.
///
/// The member set is closed — `schema`, `record_type`, `tenant_id`,
/// `export_request_id`, `approval_digest`, `inventory_digest`,
/// `selected_occurrence_set_digest`, `purpose`, `destination_class`,
/// `item_count`, `outcome`, and `commit_time` (the completion instant,
/// named as the receipt family's signing member) — and carries no storage
/// key, no path, and no transcript bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportReceiptCore {
    tenant_id: TenantId,
    export_request_id: RequestId,
    approval_digest: BlobDigest,
    inventory_digest: BlobDigest,
    selected_occurrence_set_digest: BlobDigest,
    purpose: String,
    destination_class: String,
    item_count: u64,
    completed_at: Timestamp,
}

impl ExportReceiptCore {
    /// The canonical JSON object a receipt key signs.
    #[must_use]
    pub fn into_object(self) -> Object {
        let mut object = Object::new();
        object.set("schema", text(EXPORT_RECEIPT_SCHEMA));
        object.set("record_type", text(EXPORT_RECEIPT_RECORD_TYPE));
        object.set("tenant_id", text(self.tenant_id.as_str()));
        object.set("export_request_id", text(self.export_request_id.as_str()));
        object.set("approval_digest", text(&self.approval_digest.to_hex()));
        object.set("inventory_digest", text(&self.inventory_digest.to_hex()));
        object.set(
            "selected_occurrence_set_digest",
            text(&self.selected_occurrence_set_digest.to_hex()),
        );
        object.set("purpose", text(&self.purpose));
        object.set("destination_class", text(&self.destination_class));
        // The wire integer is `i64`; a closure larger than it is not a
        // reachable deployment, and clamping keeps the record total.
        object.set(
            "item_count",
            Value::Int(i64::try_from(self.item_count).unwrap_or(i64::MAX)),
        );
        object.set("outcome", text(EXPORT_RECEIPT_OUTCOME_COMPLETED));
        object.set("commit_time", text(self.completed_at.as_str()));
        object
    }

    /// The tenant the export belonged to.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The export request the receipt completes.
    #[must_use]
    pub const fn export_request_id(&self) -> &RequestId {
        &self.export_request_id
    }

    /// The approval the export executed.
    #[must_use]
    pub const fn approval_digest(&self) -> &BlobDigest {
        &self.approval_digest
    }

    /// The freeze the export read from.
    #[must_use]
    pub const fn inventory_digest(&self) -> &BlobDigest {
        &self.inventory_digest
    }

    /// The exact occurrence set that was exported.
    #[must_use]
    pub const fn selected_occurrence_set_digest(&self) -> &BlobDigest {
        &self.selected_occurrence_set_digest
    }

    /// The number of items staged.
    #[must_use]
    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    /// The completion instant.
    #[must_use]
    pub const fn completed_at(&self) -> &Timestamp {
        &self.completed_at
    }
}

/// One completed authorized export: the receipt core to sign, the staged
/// items, and how many of them a previous run of the same export had
/// already staged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportRunOutcome {
    receipt: ExportReceiptCore,
    items: Vec<CompletedExportItem>,
    resumed: usize,
}

impl ExportRunOutcome {
    /// The receipt core the composition signs.
    #[must_use]
    pub const fn receipt_core(&self) -> &ExportReceiptCore {
        &self.receipt
    }

    /// The staged items, in canonical key-byte order.
    #[must_use]
    pub fn items(&self) -> &[CompletedExportItem] {
        &self.items
    }

    /// How many items were already staged by a previous run of this same
    /// export and were skipped without a store read.
    #[must_use]
    pub const fn resumed_item_count(&self) -> usize {
        self.resumed
    }
}

/// The closed, content-free failure classes of the authorized export.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportError {
    /// The grant's own relationships are inconsistent (bind time).
    InvalidBounds,
    /// The supplied instant precedes the grant's issue time.
    NotYetValid,
    /// The supplied instant is at or past the grant's expiry.
    Expired,
    /// The frozen inventory is not the grant tenant's raw prefix.
    ScopeViolation,
    /// The frozen inventory's digest is not the digest the approval bound.
    InventoryMismatch,
    /// The supplied selection is not the occurrence set the approval
    /// bound: a digest disagreement, a non-occurrence key, a duplicate, or
    /// a key the freeze does not hold.
    SelectionMismatch,
    /// The destination holds a different export run's staged state.
    RunMismatch,
    /// A frozen-inventory object no longer reads, or its stored size
    /// disagrees with the freeze: the archive diverged from its own
    /// inventory and the export fails closed.
    Diverged,
    /// A store or validation failure, carrying the storage layer's own
    /// closed kind.
    Storage(StorageError),
}

impl ExportError {
    /// The stable, content-free class token.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::InvalidBounds => "export-grant-bounds-invalid",
            Self::NotYetValid => "export-not-yet-valid",
            Self::Expired => "export-expired",
            Self::ScopeViolation => "export-scope-violation",
            Self::InventoryMismatch => "export-inventory-mismatch",
            Self::SelectionMismatch => "export-selection-mismatch",
            Self::RunMismatch => "export-run-mismatch",
            Self::Diverged => "export-store-diverged",
            Self::Storage(_) => "export-storage-fault",
        }
    }
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let detail = match self {
            Self::InvalidBounds => "export grant bounds are inconsistent",
            Self::NotYetValid => "export grant is not yet valid",
            Self::Expired => "export grant has expired",
            Self::ScopeViolation => "frozen inventory is outside the export grant tenant",
            Self::InventoryMismatch => "frozen inventory is not the one the approval bound",
            Self::SelectionMismatch => "selection is not the occurrence set the approval bound",
            Self::RunMismatch => "destination holds a different export run",
            Self::Diverged => "stored object diverged from the frozen inventory",
            Self::Storage(error) => return write!(f, "export storage fault: {error}"),
        };
        f.write_str(detail)
    }
}

impl std::error::Error for ExportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<StorageError> for ExportError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Export one approved selection from one frozen inventory through the
/// audit/restore identity, staging exact bytes into `sink` and returning
/// the receipt core plus staged-item evidence.
///
/// Every authorization bound is checked before the first read — scope,
/// freeze digest, selection digest, and window — so a refused export is
/// also an un-read export. The read set is exactly the selection's
/// closure: the selected occurrence manifests (validated: schema,
/// re-derived provenance, key coupling, referenced blob present in the
/// freeze), the blobs they reference, and the attestations whose keys name
/// a selected occurrence (validated against their keys). Every key is read
/// at most once per run: a manifest stages from its discovery read, and an
/// attestation or blob is read only when the sink holds no completion
/// record for it. Items stage in
/// canonical key-byte order; whole items already staged by a previous run
/// of this same export are skipped; the receipt core is returned only when
/// the last item is staged.
///
/// # Errors
/// [`ExportError`] for every closed class above, failing closed with no
/// receipt and no partial completion records.
///
/// # Panics
/// Panics only if a staged item count cannot fit the wire integer — a
/// closure larger than it is not a reachable deployment.
pub async fn export_authorized_selection<S, K>(
    store: &S,
    inventory: &FrozenInventory,
    grant: &ExportGrant,
    now: &Timestamp,
    selection: &[InventoryKey],
    sink: &mut K,
) -> Result<ExportRunOutcome, ExportError>
where
    S: AuditRestoreStore + ?Sized,
    K: ExportSink + ?Sized,
{
    // The authorization gate, complete before any store call.
    if !now.calendar_valid() {
        return Err(ExportError::InvalidBounds);
    }
    if timestamp_cmp(now, &grant.spec.issued_at) == std::cmp::Ordering::Less {
        return Err(ExportError::NotYetValid);
    }
    if timestamp_cmp(now, &grant.spec.expires_at) != std::cmp::Ordering::Less {
        return Err(ExportError::Expired);
    }
    match inventory.scope() {
        InventoryScope::TenantRaw(tenant) if tenant == grant.tenant_id() => {}
        InventoryScope::TenantRaw(_) | InventoryScope::TenantControl(_) => {
            return Err(ExportError::ScopeViolation);
        }
    }
    if inventory.digest().as_raw() != grant.inventory_digest().as_raw() {
        return Err(ExportError::InventoryMismatch);
    }

    // The exact-selection gate: every key is an occurrence key the freeze
    // holds, and the canonical digest over them is the bound digest.
    let index = RawCatalogIndex::new(inventory)?;
    let mut seen: HashSet<&str> = HashSet::with_capacity(selection.len());
    let mut selected_keys: Vec<&str> = Vec::with_capacity(selection.len());
    let frozen: HashMap<&str, u64> = inventory
        .entries()
        .iter()
        .map(|entry| (entry.key().as_str(), entry.size()))
        .collect();
    for key in selection {
        if OccurrenceObjectKey::parse(key.as_str()).is_err() {
            return Err(ExportError::SelectionMismatch);
        }
        if !seen.insert(key.as_str()) {
            return Err(ExportError::SelectionMismatch);
        }
        if !frozen.contains_key(key.as_str()) {
            return Err(ExportError::SelectionMismatch);
        }
        selected_keys.push(key.as_str());
    }
    let selection_digest =
        export_selection_digest(grant.tenant_id(), grant.inventory_digest(), &selected_keys);
    if selection_digest.as_raw() != grant.selected_occurrence_set_digest().as_raw() {
        return Err(ExportError::SelectionMismatch);
    }

    // The destination binds to this run before anything is read, so a
    // destination holding another approval's output refuses here.
    sink.begin(&ExportRunId::of(grant)).await?;

    // Resolve the closure, then stage it: discovery reads each selected
    // manifest exactly once and hands its bytes to staging.
    let (mut manifests, closure) =
        resolve_closure(store, &index, grant.tenant_id(), &selected_keys).await?;

    // Stage the closure item by item, resuming whole items this same run
    // already staged. Every key is read at most once per run: a manifest
    // stages from its discovery read, and an attestation or blob is read
    // only when the sink holds no completion record for it.
    let mut items: Vec<CompletedExportItem> = Vec::with_capacity(closure.len());
    let mut resumed = 0_usize;
    for key in &closure {
        let expected = frozen
            .get(key.as_str())
            .copied()
            .ok_or(ExportError::Diverged)?;
        if let Some(done) = sink.completed(key).await? {
            if done.size() != expected {
                return Err(ExportError::Diverged);
            }
            resumed += 1;
            items.push(done);
            continue;
        }
        let body = if let Some(discovered) = manifests.remove(key.as_str()) {
            discovered
        } else {
            let body = read_frozen(store, key.as_str()).await?;
            // An attestation validates at its single read, exactly as
            // discovery validates a manifest at its; a blob carries no
            // manifest of its own and stages byte-for-byte.
            if let Ok(attestation) = AttestationObjectKey::parse(key.as_str()) {
                AttestationManifest::validate(body.bytes(), &attestation)?;
            }
            body
        };
        let size = u64::try_from(body.bytes().len()).map_err(|_| ExportError::Diverged)?;
        if size != expected {
            return Err(ExportError::Diverged);
        }
        let item = CompletedExportItem::new(key.clone(), size, sha256::digest(body.bytes()));
        sink.put(&item, body.bytes()).await?;
        items.push(item);
    }

    Ok(ExportRunOutcome {
        receipt: ExportReceiptCore {
            tenant_id: grant.spec.tenant_id.clone(),
            export_request_id: grant.spec.export_request_id.clone(),
            approval_digest: grant.spec.approval_digest,
            inventory_digest: grant.spec.inventory_digest,
            selected_occurrence_set_digest: grant.spec.selected_occurrence_set_digest,
            purpose: grant.spec.purpose.clone(),
            destination_class: grant.spec.destination_class.clone(),
            item_count: u64::try_from(items.len()).expect("usize items fit the wire u64"),
            completed_at: now.clone(),
        },
        items,
        resumed,
    })
}

/// Resolve the selection's closure from the frozen inventory: the selected
/// occurrence manifests — each read exactly once, here, and staged from
/// that read — the blobs they reference, and the attestations whose keys
/// name a selected occurrence, joined through the key grammar without
/// reading them.
///
/// Returns the discovered manifest bodies keyed for staging and the
/// closure's keys, sorted and deduplicated in canonical key-byte order.
///
/// # Panics
/// Panics only where a key the caller's selection gate already validated
/// fails to re-parse — an invariant of this module, not of the archive.
async fn resolve_closure<S>(
    store: &S,
    index: &RawCatalogIndex,
    tenant: &TenantId,
    selected_keys: &[&str],
) -> Result<(HashMap<String, ObjectBody>, Vec<InventoryKey>), ExportError>
where
    S: AuditRestoreStore + ?Sized,
{
    let mut manifests: HashMap<String, ObjectBody> = HashMap::new();
    let mut closure: Vec<InventoryKey> = Vec::with_capacity(selected_keys.len());
    for key in selected_keys {
        let body = read_frozen(store, key).await?;
        let parsed = OccurrenceObjectKey::parse(key).expect("selection key re-parses");
        let (manifest, blob_key) = OccurrenceManifest::validate(body.bytes(), &parsed, index)?;
        manifests.insert((*key).to_owned(), body);
        closure.push(InventoryKey::parse(key).expect("selection key re-parses"));
        closure.push(
            InventoryKey::parse(blob_key.as_str())
                .map_err(|_| StorageError::of_kind(StorageErrorKind::MalformedInput))?,
        );
        // Attestations join through the key grammar: the occurrence's own
        // hex is two segments of every attestation key about it.
        let occurrence_hex = manifest.occurrence_id().to_hex();
        let prefix = format!(
            "tenants/{tenant}/v1/raw/attestations/{shard}/{occurrence}/",
            tenant = tenant.as_str(),
            shard = &occurrence_hex[..2],
            occurrence = occurrence_hex,
        );
        for attestation in index.attestations() {
            if attestation.as_str().starts_with(&prefix) {
                closure.push(InventoryKey::parse(attestation.as_str()).expect("frozen key parses"));
            }
        }
    }
    closure.sort_unstable_by(|a, b| a.as_str().as_bytes().cmp(b.as_str().as_bytes()));
    closure.dedup();
    Ok((manifests, closure))
}

/// Read one frozen-inventory object through the audit/restore identity.
///
/// A listed object that reports unavailable has diverged from the freeze —
/// deleted, rewritten, or an enumeration the freeze no longer describes —
/// and the export fails closed, exactly as the freeze contract prescribes.
async fn read_frozen<S>(store: &S, key: &str) -> Result<ObjectBody, ExportError>
where
    S: AuditRestoreStore + ?Sized,
{
    let key = InventoryKey::parse(key)
        .map_err(|_| StorageError::of_kind(StorageErrorKind::MalformedInput))?;
    match store.read_object(&key).await {
        Ok(body) => Ok(body),
        Err(error) if error.kind() == StorageErrorKind::Unavailable => Err(ExportError::Diverged),
        Err(error) => Err(ExportError::Storage(error)),
    }
}

/// Compare two protocol timestamps on a nanosecond proleptic-Gregorian
/// timeline, so a one-digit fraction never compares lexically wrong. Both
/// timestamps are calendar validated by the caller.
fn timestamp_cmp(left: &Timestamp, right: &Timestamp) -> std::cmp::Ordering {
    nanoseconds(left).cmp(&nanoseconds(right))
}

/// The nanosecond value of one calendar-valid timestamp.
fn nanoseconds(timestamp: &Timestamp) -> i128 {
    let bytes = timestamp.as_str().as_bytes();
    let number = |start: usize, end: usize| -> i128 {
        bytes[start..end]
            .iter()
            .fold(0_i128, |value, byte| value * 10 + i128::from(byte - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let adjusted_year = year - i128::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let fraction = if bytes[19] == b'.' {
        let end = bytes.len() - 1;
        let raw = &bytes[20..end];
        let value = raw
            .iter()
            .fold(0_i128, |value, byte| value * 10 + i128::from(byte - b'0'));
        value * 10_i128.pow(u32::try_from(9 - raw.len()).expect("calendar-valid fraction"))
    } else {
        0
    };
    (((days * 24 + hour) * 60 + minute) * 60 + second) * 1_000_000_000 + fraction
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use archivist_protocol::json::{self, Value};
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::vocabulary::{
        AttestationId, BlobDigest, ClientId, HarnessId, OccurrenceId, RequestId, SessionHash,
        StorageProfile, TenantId, Timestamp,
    };

    use super::super::audit_restore::{
        AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryEntry, InventoryKey,
        InventoryPage, InventoryScope, ObjectBody, ObjectMetadata,
    };
    use super::super::error::{StorageError, StorageErrorKind};
    use super::super::metadata::Observation;
    use super::{
        CompletedExportItem, EXPORT_RECEIPT_RECORD_TYPE, EXPORT_RECEIPT_SCHEMA, ExportError,
        ExportGrant, ExportGrantSpec, ExportRunId, ExportSink, MemoryExportSink,
        export_authorized_selection,
    };

    /// The committed provenance bundle's tenant.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const REQUEST: &str = "018f2d2a-7b3c-7abc-8def-0123456789ab";
    const ISSUED: &str = "2026-09-20T00:00:00Z";
    const EXPIRES: &str = "2026-09-21T00:00:00Z";
    const NOW: &str = "2026-09-20T12:00:00Z";
    const OBSERVED: &str = "2026-09-13T12:00:00Z";
    const AUTHORITY_DIGEST: [u8; 32] = [0x42; 32];

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("tenant grammar")
    }

    fn now() -> Timestamp {
        Timestamp::parse(NOW).expect("timestamp grammar")
    }

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED).expect("timestamp grammar")
    }

    // ---- The committed provenance bundle, as catalog_source's tests load it ----

    fn bundle_doc(rel: &str) -> Vec<u8> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/examples/provenance");
        std::fs::read(root.join(rel))
            .unwrap_or_else(|error| panic!("committed bundle document {rel}: {error}"))
    }

    fn parsed(doc: &[u8]) -> json::Object {
        match json::parse(doc).expect("bundle document parses") {
            Value::Object(object) => object,
            _ => panic!("bundle document is an object"),
        }
    }

    fn text_of<'a>(object: &'a json::Object, name: &str) -> &'a str {
        match object.get(name) {
            Some(Value::Text(value)) => value,
            _ => panic!("bundle document member {name} is a string"),
        }
    }

    fn occurrence_key(doc: &[u8]) -> OccurrenceObjectKey {
        let object = parsed(doc);
        OccurrenceObjectKey::new(
            &tenant(),
            &ClientId::parse(text_of(&object, "origin_client_id")).unwrap(),
            &HarnessId::parse(text_of(&object, "harness")).unwrap(),
            &SessionHash::parse(text_of(&object, "session_hash")).unwrap(),
            &OccurrenceId::parse(text_of(&object, "occurrence_id")).unwrap(),
        )
    }

    fn attestation_key(doc: &[u8]) -> AttestationObjectKey {
        let object = parsed(doc);
        AttestationObjectKey::new(
            &tenant(),
            &OccurrenceId::parse(text_of(&object, "occurrence_id")).unwrap(),
            &AttestationId::parse(text_of(&object, "attestation_id")).unwrap(),
        )
    }

    fn blob_fixture() -> (BlobObjectKey, Vec<u8>) {
        let object = parsed(&bundle_doc(
            "occurrences/direct-upload-and-relay-source.json",
        ));
        let digest = BlobDigest::parse(text_of(&object, "blob_digest")).unwrap();
        let key = BlobObjectKey::new(&tenant(), StorageProfile::ZstdV1, &digest);
        let declared = bundle_doc("payloads/shared-session-chunk.jsonl").len();
        // A conforming `zstd-v1` frame header over an unparsed body, the
        // same shape catalog_source's tests use; the exporter copies bytes
        // without decoding them.
        let mut bytes = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC4, 0x00]);
        bytes.extend_from_slice(&(declared as u64).to_le_bytes());
        bytes.extend_from_slice(b"frame body the exporter never parses");
        (key, bytes)
    }

    /// The committed bundle: two occurrences sharing one blob, three
    /// attestations on the first and one on the second.
    struct Bundle {
        occurrence_keys: [OccurrenceObjectKey; 2],
        occurrences: [Vec<u8>; 2],
        attestation_keys: [AttestationObjectKey; 4],
        attestations: [Vec<u8>; 4],
        blob_key: BlobObjectKey,
        blob: Vec<u8>,
    }

    impl Bundle {
        fn load() -> Self {
            let occurrence_a = bundle_doc("occurrences/direct-upload-and-relay-source.json");
            let occurrence_b = bundle_doc("occurrences/identical-bytes-second-origin.json");
            let attestation_a = bundle_doc("attestations/origin-direct-first-request.json");
            let attestation_b = bundle_doc("attestations/origin-direct-refrozen-request.json");
            let attestation_c = bundle_doc("attestations/relay-delegated-request.json");
            let attestation_d = bundle_doc("attestations/second-origin-direct-request.json");
            let (blob_key, blob) = blob_fixture();
            Self {
                occurrence_keys: [occurrence_key(&occurrence_a), occurrence_key(&occurrence_b)],
                occurrences: [occurrence_a, occurrence_b],
                attestation_keys: [
                    attestation_key(&attestation_a),
                    attestation_key(&attestation_b),
                    attestation_key(&attestation_c),
                    attestation_key(&attestation_d),
                ],
                attestations: [attestation_a, attestation_b, attestation_c, attestation_d],
                blob_key,
                blob,
            }
        }

        fn objects(&self) -> Vec<(String, Vec<u8>)> {
            let mut objects = Vec::new();
            objects.push((self.blob_key.as_str().to_owned(), self.blob.clone()));
            for (key, doc) in self.occurrence_keys.iter().zip(&self.occurrences) {
                objects.push((key.as_str().to_owned(), doc.clone()));
            }
            for (key, doc) in self.attestation_keys.iter().zip(&self.attestations) {
                objects.push((key.as_str().to_owned(), doc.clone()));
            }
            objects
        }
    }

    // ---- Fixtures: store, inventory, grant ----

    /// An in-memory audit/restore store that records every read, so the
    /// tests can assert exactly which keys an export touched.
    struct TrackingStore {
        objects: Mutex<HashMap<String, Vec<u8>>>,
        reads: Mutex<Vec<String>>,
    }

    impl TrackingStore {
        fn with(objects: &[(String, Vec<u8>)]) -> Self {
            Self {
                objects: Mutex::new(objects.iter().cloned().collect()),
                reads: Mutex::new(Vec::new()),
            }
        }

        fn reads(&self) -> Vec<String> {
            self.reads.lock().expect("mock lock").clone()
        }
    }

    impl AuditRestoreStore for TrackingStore {
        async fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> Result<InventoryPage, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }

        async fn freeze_inventory(
            &self,
            _scope: &InventoryScope,
        ) -> Result<FrozenInventory, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
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
            self.reads
                .lock()
                .expect("mock lock")
                .push(key.as_str().to_owned());
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

    fn freeze(objects: &[(String, Vec<u8>)]) -> FrozenInventory {
        let scope = InventoryScope::TenantRaw(tenant());
        let entries: Vec<InventoryEntry> = objects
            .iter()
            .map(|(key, bytes)| {
                InventoryEntry::new(
                    InventoryKey::parse(key).expect("grammatical fixture key"),
                    bytes.len() as u64,
                    Observation::new(None, None, observed_at()),
                )
            })
            .collect();
        let mid = entries.len().div_ceil(2);
        FrozenInventory::from_pages(
            &scope,
            vec![
                Ok(InventoryPage::new(
                    entries[..mid].to_vec(),
                    Some(ContinuationToken::parse("next-page").unwrap()),
                )),
                Ok(InventoryPage::new(entries[mid..].to_vec(), None)),
            ],
        )
        .unwrap()
    }

    fn grant_over(inventory_digest: [u8; 32], selection_digest: [u8; 32]) -> ExportGrant {
        ExportGrant::bind(grant_spec_over(inventory_digest, selection_digest)).expect("grant binds")
    }

    fn grant_spec_over(inventory_digest: [u8; 32], selection_digest: [u8; 32]) -> ExportGrantSpec {
        ExportGrantSpec {
            tenant_id: tenant(),
            export_request_id: RequestId::parse(REQUEST).expect("uuidv7 grammar"),
            approval_digest: BlobDigest::from_raw(AUTHORITY_DIGEST),
            inventory_digest: BlobDigest::from_raw(inventory_digest),
            selected_occurrence_set_digest: BlobDigest::from_raw(selection_digest),
            purpose: "customer-restore".to_owned(),
            destination_class: "offline-vault".to_owned(),
            requester: "operator-7".to_owned(),
            policy_version: 4,
            issued_at: Timestamp::parse(ISSUED).unwrap(),
            expires_at: Timestamp::parse(EXPIRES).unwrap(),
        }
    }

    /// The freeze's digest as the `BlobDigest` vocabulary the approval and
    /// grant bind.
    fn bound_inventory_digest(inventory: &FrozenInventory) -> BlobDigest {
        BlobDigest::from_raw(*inventory.digest().as_raw())
    }

    /// The canonical selection digest over occurrence keys, against one
    /// freeze.
    fn selection_digest(inventory: &FrozenInventory, keys: &[&str]) -> BlobDigest {
        archivist_protocol::derivation::export_selection_digest(
            &tenant(),
            &bound_inventory_digest(inventory),
            keys,
        )
    }

    fn key_of(key: &str) -> InventoryKey {
        InventoryKey::parse(key).expect("grammatical key")
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut context) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    /// A sink that fails its `fail_at`-th put once, then works: the
    /// interrupted-run shape resume must survive.
    struct FlakySink {
        inner: MemoryExportSink,
        fail_at: usize,
        puts: usize,
        tripped: bool,
    }

    impl FlakySink {
        fn new(fail_at: usize) -> Self {
            Self {
                inner: MemoryExportSink::new(),
                fail_at,
                puts: 0,
                tripped: false,
            }
        }

        /// Stop failing puts: the operator fixed the destination and the
        /// same run resumes.
        fn unflaky(&mut self) {
            self.tripped = true;
        }
    }

    impl ExportSink for FlakySink {
        async fn begin(&mut self, run: &ExportRunId) -> Result<(), ExportError> {
            self.inner.begin(run).await
        }

        async fn completed(
            &self,
            key: &InventoryKey,
        ) -> Result<Option<CompletedExportItem>, ExportError> {
            self.inner.completed(key).await
        }

        async fn put(
            &mut self,
            item: &CompletedExportItem,
            bytes: &[u8],
        ) -> Result<(), ExportError> {
            self.puts += 1;
            if !self.tripped && self.puts == self.fail_at {
                // The put is interrupted after the item count advanced but
                // before any completion record exists.
                return Err(ExportError::Storage(StorageError::of_kind(
                    StorageErrorKind::Unavailable,
                )));
            }
            self.inner.put(item, bytes).await
        }
    }

    // ---- The exporter's contract ----

    #[test]
    fn exports_the_exact_selection_closure_byte_for_byte() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let selection = [key_of(bundle.occurrence_keys[0].as_str())];
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();

        let outcome = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &selection,
            &mut sink,
        ))
        .expect("authorized export completes");

        // The closure is the manifest, the shared blob, and exactly the
        // three attestations naming the selected occurrence — in canonical
        // key-byte order.
        let mut expected: Vec<&str> = vec![
            bundle.occurrence_keys[0].as_str(),
            bundle.blob_key.as_str(),
            bundle.attestation_keys[0].as_str(),
            bundle.attestation_keys[1].as_str(),
            bundle.attestation_keys[2].as_str(),
        ];
        expected.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        let staged: Vec<&str> = sink
            .staged_items()
            .iter()
            .map(|i| i.key().as_str())
            .collect();
        assert_eq!(staged, expected);
        assert_eq!(outcome.items().len(), expected.len());
        assert_eq!(outcome.resumed_item_count(), 0);
        for (key, bytes) in &objects {
            match sink.staged_bytes(key) {
                Some(staged) => assert_eq!(staged, bytes, "exact bytes for {key}"),
                None => assert!(
                    key == bundle.occurrence_keys[1].as_str()
                        || key == bundle.attestation_keys[3].as_str(),
                    "unexpected staged key {key}"
                ),
            }
        }
        // The read set is exactly the selection's closure: the other
        // occurrence and its attestation are never read.
        let mut reads = store.reads();
        reads.sort_unstable();
        let read_keys: Vec<&str> = reads.iter().map(String::as_str).collect();
        assert_eq!(read_keys, expected);
        assert!(!read_keys.contains(&bundle.occurrence_keys[1].as_str()));
        assert!(!read_keys.contains(&bundle.attestation_keys[3].as_str()));
    }

    #[test]
    fn both_occurrences_export_together_when_both_are_approved() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let selection = [
            key_of(bundle.occurrence_keys[0].as_str()),
            key_of(bundle.occurrence_keys[1].as_str()),
        ];
        let digest = selection_digest(
            &inventory,
            &[
                bundle.occurrence_keys[0].as_str(),
                bundle.occurrence_keys[1].as_str(),
            ],
        );
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();

        let outcome = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &selection,
            &mut sink,
        ))
        .expect("both-occurrence export completes");

        // Both manifests, all four attestations, and the one shared blob —
        // staged once.
        assert_eq!(outcome.items().len(), 7);
        assert_eq!(sink.len(), 7);
        let blob_items = outcome
            .items()
            .iter()
            .filter(|item| item.key().as_str() == bundle.blob_key.as_str())
            .count();
        assert_eq!(blob_items, 1, "the shared blob stages once");
    }

    #[test]
    fn receipt_core_binds_the_run_without_paths_or_bytes() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();

        let outcome = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &[key_of(bundle.occurrence_keys[0].as_str())],
            &mut sink,
        ))
        .expect("export completes");

        let core = outcome.receipt_core();
        assert_eq!(core.tenant_id(), &tenant());
        assert_eq!(core.export_request_id().as_str(), REQUEST);
        assert_eq!(core.approval_digest().as_raw(), &AUTHORITY_DIGEST);
        assert_eq!(
            core.inventory_digest().as_raw(),
            inventory.digest().as_raw()
        );
        assert_eq!(core.selected_occurrence_set_digest(), &digest);
        assert_eq!(core.item_count(), 5);
        assert_eq!(core.completed_at(), &now());

        let object = core.clone().into_object();
        let mut names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "approval_digest",
                "commit_time",
                "destination_class",
                "export_request_id",
                "inventory_digest",
                "item_count",
                "outcome",
                "purpose",
                "record_type",
                "schema",
                "selected_occurrence_set_digest",
                "tenant_id",
            ]
        );
        assert_eq!(text_of(&object, "schema"), EXPORT_RECEIPT_SCHEMA);
        assert_eq!(text_of(&object, "record_type"), EXPORT_RECEIPT_RECORD_TYPE);
        assert_eq!(text_of(&object, "outcome"), "completed");
        // Content freedom: no storage key and no staged bytes appear in
        // the receipt — the selection is bound by digest, never by path.
        let bytes = Value::Object(object).canonical_bytes();
        assert!(!bytes.windows(8).any(|window| window == b"tenants/"));
        assert!(!bytes.windows(6).any(|window| window == b"sha256"));
    }

    #[test]
    #[allow(clippy::too_many_lines)] // one refusal catalog, read top to bottom
    fn every_authorization_refusal_happens_before_any_read() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let selection = [key_of(bundle.occurrence_keys[0].as_str())];
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let matching = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );

        // Wrong inventory digest.
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        let mismatched = grant_over([9; 32], *digest.as_raw());
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &mismatched,
                &now(),
                &selection,
                &mut sink
            )),
            Err(ExportError::InventoryMismatch)
        );
        assert!(store.reads().is_empty());
        assert!(sink.is_empty());

        // Wrong selection digest.
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        let other = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *selection_digest(&inventory, &[bundle.occurrence_keys[1].as_str()]).as_raw(),
        );
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &other,
                &now(),
                &selection,
                &mut sink
            )),
            Err(ExportError::SelectionMismatch)
        );
        assert!(store.reads().is_empty());

        // A selection key the freeze does not hold.
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        let unlisted = key_of(&format!(
            "tenants/{TENANT}/v1/raw/occurrences/x/y/zz/zz/{}.json",
            "0".repeat(64)
        ));
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &matching,
                &now(),
                &[unlisted],
                &mut sink
            )),
            Err(ExportError::SelectionMismatch)
        );
        assert!(store.reads().is_empty());

        // A non-occurrence key (the shared blob) is not an occurrence
        // selection.
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &matching,
                &now(),
                &[key_of(bundle.blob_key.as_str())],
                &mut sink
            )),
            Err(ExportError::SelectionMismatch)
        );
        assert!(store.reads().is_empty());

        // Expired and not-yet-valid windows.
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &matching,
                &Timestamp::parse(EXPIRES).unwrap(),
                &selection,
                &mut sink
            )),
            Err(ExportError::Expired)
        );
        assert!(store.reads().is_empty());
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &matching,
                &Timestamp::parse("2026-09-19T12:00:00Z").unwrap(),
                &selection,
                &mut sink
            )),
            Err(ExportError::NotYetValid)
        );
        assert!(store.reads().is_empty());

        // A frozen control scope is not the grant's raw prefix.
        let control_scope = InventoryScope::TenantControl(tenant());
        let control_entry = InventoryEntry::new(
            key_of(&format!("tenants/{TENANT}/v1/control/x.json")),
            4,
            Observation::new(None, None, observed_at()),
        );
        let control_inventory = FrozenInventory::from_pages(
            &control_scope,
            vec![Ok(InventoryPage::new(vec![control_entry], None))],
        )
        .unwrap();
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &control_inventory,
                &matching,
                &now(),
                &selection,
                &mut sink
            )),
            Err(ExportError::ScopeViolation)
        );
        assert!(store.reads().is_empty());
    }

    #[test]
    fn a_destination_bound_to_another_run_refuses_before_reads() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let other = {
            // A different approval over the same freeze and selection: every
            // authorization gate passes, and only the destination bind
            // refuses it.
            let mut spec = grant_spec_over(
                *bound_inventory_digest(&inventory).as_raw(),
                *digest.as_raw(),
            );
            spec.approval_digest = BlobDigest::from_raw([7; 32]);
            ExportGrant::bind(spec).expect("grant binds")
        };
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();

        block_on(sink.begin(&ExportRunId::of(&grant))).expect("first run binds");
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &other,
                &now(),
                &[key_of(bundle.occurrence_keys[0].as_str())],
                &mut sink
            )),
            Err(ExportError::RunMismatch)
        );
        // The refusal happens before the closure resolves: no manifest is
        // read for the refused approval.
        assert!(store.reads().is_empty());
    }

    #[test]
    fn an_interrupted_run_resumes_whole_items_only() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let selection = [key_of(bundle.occurrence_keys[0].as_str())];
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = FlakySink::new(3);

        let interrupted = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &selection,
            &mut sink,
        ));
        assert!(interrupted.is_err(), "the third put fails the run");
        // Two whole items are staged; the third has no completion record.
        assert_eq!(sink.inner.len(), 2);

        // The resume: the same run re-runs, skips the two whole items
        // without reading them, and completes.
        let reads_before = store.reads().len();
        sink.unflaky();
        let outcome = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &selection,
            &mut sink,
        ))
        .expect("resumed export completes");
        assert_eq!(outcome.items().len(), 5);
        assert_eq!(outcome.resumed_item_count(), 2);
        assert_eq!(sink.inner.len(), 5);
        // Only the three missing items were read again.
        assert_eq!(store.reads().len() - reads_before, 3);
        // And the receipt is identical to an uninterrupted run's: the
        // same clock produces the same evidence either way.
        let mut fresh = MemoryExportSink::new();
        let straight = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &selection,
            &mut fresh,
        ))
        .expect("straight export completes");
        assert_eq!(
            Value::Object(outcome.receipt_core().clone().into_object()).canonical_bytes(),
            Value::Object(straight.receipt_core().clone().into_object()).canonical_bytes()
        );
    }

    #[test]
    fn a_staged_size_that_disagrees_with_the_freeze_fails_closed() {
        let bundle = Bundle::load();
        let mut objects = bundle.objects();
        let inventory = freeze(&objects);
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );

        // The store rewrites the blob after the freeze: the stored size
        // no longer matches the frozen entry.
        let grown = b"rewritten and larger than the freeze recorded".to_vec();
        for (key, bytes) in &mut objects {
            if key == bundle.blob_key.as_str() {
                *bytes = grown.clone();
            }
        }
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &grant,
                &now(),
                &[key_of(bundle.occurrence_keys[0].as_str())],
                &mut sink
            )),
            Err(ExportError::Diverged)
        );
    }

    #[test]
    fn selection_order_does_not_change_the_authorized_set() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let digest = selection_digest(
            &inventory,
            &[
                bundle.occurrence_keys[1].as_str(),
                bundle.occurrence_keys[0].as_str(),
            ],
        );
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();

        // The reversed selection authorizes against the same digest, and
        // the staged order stays canonical.
        let outcome = block_on(export_authorized_selection(
            &store,
            &inventory,
            &grant,
            &now(),
            &[
                key_of(bundle.occurrence_keys[1].as_str()),
                key_of(bundle.occurrence_keys[0].as_str()),
            ],
            &mut sink,
        ))
        .expect("reversed selection exports");
        let keys: Vec<&str> = outcome.items().iter().map(|i| i.key().as_str()).collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(keys, sorted);
    }

    #[test]
    fn duplicate_selection_keys_are_refused() {
        let bundle = Bundle::load();
        let objects = bundle.objects();
        let inventory = freeze(&objects);
        let digest = selection_digest(&inventory, &[bundle.occurrence_keys[0].as_str()]);
        let grant = grant_over(
            *bound_inventory_digest(&inventory).as_raw(),
            *digest.as_raw(),
        );
        let store = TrackingStore::with(&objects);
        let mut sink = MemoryExportSink::new();
        assert_eq!(
            block_on(export_authorized_selection(
                &store,
                &inventory,
                &grant,
                &now(),
                &[
                    key_of(bundle.occurrence_keys[0].as_str()),
                    key_of(bundle.occurrence_keys[0].as_str()),
                ],
                &mut sink
            )),
            Err(ExportError::SelectionMismatch)
        );
        assert!(store.reads().is_empty());
    }

    #[test]
    fn grant_bind_refuses_inconsistent_bounds() {
        let mut spec = ExportGrantSpec {
            tenant_id: tenant(),
            export_request_id: RequestId::parse(REQUEST).unwrap(),
            approval_digest: BlobDigest::from_raw(AUTHORITY_DIGEST),
            inventory_digest: BlobDigest::from_raw([1; 32]),
            selected_occurrence_set_digest: BlobDigest::from_raw([2; 32]),
            purpose: "customer-restore".to_owned(),
            destination_class: "offline-vault".to_owned(),
            requester: "operator-7".to_owned(),
            policy_version: 4,
            issued_at: Timestamp::parse(ISSUED).unwrap(),
            expires_at: Timestamp::parse(EXPIRES).unwrap(),
        };
        assert!(ExportGrant::bind(spec.clone()).is_ok());
        spec.expires_at = Timestamp::parse(ISSUED).unwrap();
        assert_eq!(
            ExportGrant::bind(spec.clone()),
            Err(ExportError::InvalidBounds)
        );
        spec.expires_at = Timestamp::parse("2026-09-19T00:00:00Z").unwrap();
        assert_eq!(
            ExportGrant::bind(spec.clone()),
            Err(ExportError::InvalidBounds)
        );
        spec.expires_at = Timestamp::parse(EXPIRES).unwrap();
        spec.purpose = String::new();
        assert_eq!(ExportGrant::bind(spec), Err(ExportError::InvalidBounds));
    }
}
