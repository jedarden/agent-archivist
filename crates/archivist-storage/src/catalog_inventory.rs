// SPDX-License-Identifier: Apache-2.0

//! The versioned Parquet inventory (plan Phase 10: "Produce versioned
//! Parquet inventories"; plan Section 7.10's derived-consumption surface):
//! one deterministic pass over a frozen tenant raw prefix that
//! materializes content-free, partitioned, columnar inventory files
//! through the derived writer — the query surface token questions are
//! answered by, not a second capture path.
//!
//! # What one build emits
//!
//! Everything lands under one source-scoped directory of the tenant's
//! derived namespace, so tenant isolation is the scoped writer's own
//! grammar and version isolation is the key layout:
//!
//! ```text
//! tenants/<tenant>/v1/derived/inventory/1/<source inventory digest>/part-<shard>.parquet
//! tenants/<tenant>/v1/derived/inventory/1/<source inventory digest>/manifest.json
//! ```
//!
//! - **One row per raw occurrence**, derived through the same
//!   [`UsageSummary::derive`](archivist_protocol::usage_summary::UsageSummary::derive)
//!   the catalog rebuild uses — the inventory is
//!   a projection of the derived rows' own values, never an independent
//!   reading of the raw bytes, so the two pipelines cannot disagree. The
//!   row carries the usage-summary identity members (occurrence digest,
//!   adapter and projection version, the row's own
//!   `usage_summary_digest`) plus both usage denominators as *separate
//!   column families* (below).
//! - **Partitioning is a pure function of the prefix**: the shard is the
//!   row's `usage_summary_digest` prefix (the derived family's own
//!   two-hex shard convention), and rows land in a shard in the fold's
//!   canonical occurrence order. Two builds of one frozen prefix produce
//!   byte-identical partition files — the reproducibility gate.
//! - **The manifest lands last.** It is the build's completeness
//!   statement: the source commitment (frozen `inventory-v1` digest and
//!   the fold's chain digest), the per-partition key, row count, size,
//!   and digest, and the denominator tally. A directory without its
//!   manifest is an incomplete build — never an authoritative partition
//!   set — and a completed build re-run produces byte-identical files at
//!   the same content-named keys, so a retry converges instead of
//!   overwriting.
//!
//! # The two usage denominators
//!
//! The harness-reported family (`harness_*` columns) carries the
//! usage-summary record's own contract: `measured` rows carry the summed
//! counts and the assistant-message count; `unknown` rows carry exactly
//! the refusal reason — absent, malformed, or unsupported — and no count
//! column at all. **Absent or unsupported source usage is the bounded
//! state `unknown`, never zero**: an incomplete source can never read as
//! free.
//!
//! The provider-observed family (`provider_*` columns) is the Phase 9
//! exact-capture reservation, and its coverage state is a separate
//! required column — the two denominators are never summed, and no
//! column family can silently stand in for the other. The v1 inventory
//! build reads no provider-boundary evidence, so every v1 row states
//! `provider_state = unknown` and carries no provider count: that is the
//! honest denominator of a build with no exact-capture input, never a
//! zero. When the exact-capture projection lands it is a new inventory
//! pipeline version writing a new prefix, never a rewrite of these
//! files. No monetary amount exists anywhere in the projection — cost is
//! computed outside the archive at query time (plan Phase 10).
//!
//! # Determinism and the complete pass
//!
//! Partition bytes are a pure function of the frozen prefix, the pinned
//! pipeline identity (`inventory`/`1`), the composed projection version,
//! and the inventory schema version — no wall-clock, producer, or run
//! input exists in any emitted byte. The build is deliberately a
//! complete, uninterrupted pass: a windowed partial fold would make
//! partition boundaries depend on how the pass was cut, which is exactly
//! what reproducibility forbids. A failed build simply leaves an
//! incomplete directory behind (no manifest, so never authoritative),
//! and the next run converges on the identical files.
//!
//! # Memory shape
//!
//! One occurrence's blob is decoded at a time, exactly as the rebuild;
//! the derived rows themselves accumulate in memory until their
//! partitions encode, because a partition file is one object. The v1
//! row is a fixed set of short provenance tokens and counts, so the
//! bound is linear in occurrences and small per row; a deployment whose
//! prefixes outgrow it awaits a partitioned-pass pipeline version, not a
//! silent change to this one.

use std::collections::BTreeMap;

use archivist_protocol::derivation::{FrameBuilder, blob_digest};
use archivist_protocol::json::{Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::usage_summary::{
    MessageUsage, OccurrenceProvenance, USAGE_SUMMARY_VERSION,
};
use archivist_protocol::vocabulary::{AdapterId, TenantId};

use crate::audit_restore::{AuditRestoreStore, InventoryScope};
use crate::catalog_rebuild::{
    RowTally, UsageProjection, chain_advance, chain_genesis, decode_blob,
};
use crate::catalog_source::{RawCatalogIndex, RawCatalogSource};
use crate::error::{StorageError, StorageErrorKind};
use crate::parquet::{Cell, Column, Table, TableDecodeError};
use crate::scoped_write::{DerivedObjectKey, DerivedWriteStore};

/// The derived pipeline this module produces (`pipeline_id`): the
/// versioned Parquet inventory projection.
pub const INVENTORY_PIPELINE_ID: &str = "inventory";

/// The immutable pipeline version (v1 pins `1`): the schema, the
/// partition layout, the encoding, and the static creator token are
/// frozen inside it. A changed mapping, column set, or encoding is a new
/// version writing a new derived prefix — never a silent rewrite.
pub const INVENTORY_PIPELINE_VERSION: &str = "1";

/// The inventory table schema's own version (`inventory_schema_version`),
/// the record-shape axis: the closed column list below. A new or
/// redefined column is a new schema version, which rides a new pipeline
/// version.
pub const INVENTORY_SCHEMA_VERSION: i64 = 1;

/// The fixed shard count: the two-hex digest prefix space, the derived
/// family's own sharding convention. Shard assignment never changes as a
/// prefix grows, so one source's partition set stays comparable across
/// builds.
pub const PARTITION_SHARDS: usize = 256;

/// The manifest document's self-verifying digest label — the family's
/// exclusion framing: labeled frame over the canonical bytes with the
/// digest member removed.
const MANIFEST_DIGEST_LABEL: &str = "inventory-manifest-v1";

/// The manifest object's fixed name inside one source directory.
const MANIFEST_NAME: &str = "manifest.json";

/// The provider denominator's v1 state: the build reads no
/// provider-boundary evidence, so the honest coverage state is the
/// bounded unknown — never a zero, never a borrowed harness number.
const PROVIDER_STATE_V1: &str = "unknown";

/// The usage pipeline whose rows this projection carries, stated in the
/// manifest and every partition's metadata so the evidence names its
/// source family explicitly.
const USAGE_PIPELINE: &str = "usage";
const USAGE_PIPELINE_VERSION: &str = "1";

fn fault(detail: &'static str) -> StorageError {
    StorageError::new(StorageErrorKind::IntegrityConflict, detail)
}

const ROW_KEY_GRAMMAR: &str = "an inventory key left the scoped writer grammar";
const ROW_SHAPE: &str = "an inventory row left the pinned schema's shape";

/// The inventory table's pinned schema: the provenance members, the
/// harness-reported family, and the provider-observed reservation — a
/// closed v1 column list.
fn columns() -> Vec<Column> {
    vec![
        Column::required_text("tenant_id"),
        Column::required_text("occurrence_id"),
        Column::required_text("adapter_id"),
        Column::required_text("adapter_projection_version"),
        Column::required_text("usage_summary_digest"),
        Column::required_text("harness_state"),
        Column::optional_text("harness_unknown_reason"),
        Column::optional_text("harness_model_id"),
        Column::optional_text("harness_service_tier"),
        Column::optional_int64("harness_assistant_message_count"),
        Column::optional_int64("harness_input_tokens"),
        Column::optional_int64("harness_output_tokens"),
        Column::optional_int64("harness_cache_read_tokens"),
        Column::optional_int64("harness_cache_creation_5m_tokens"),
        Column::optional_int64("harness_cache_creation_1h_tokens"),
        Column::optional_int64("harness_reasoning_tokens"),
        Column::required_text("provider_state"),
        Column::optional_int64("provider_input_tokens"),
        Column::optional_int64("provider_output_tokens"),
        Column::optional_int64("provider_total_tokens"),
    ]
}

/// One member's optional text value, or `None` when the member is
/// omitted — the family's omission-never-null rule.
fn text_of<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(text)) => Some(text.as_str()),
        _ => None,
    }
}

/// One member's optional integer value.
fn int_of(object: &Object, name: &str) -> Option<i64> {
    match object.get(name) {
        Some(Value::Int(value)) => Some(*value),
        _ => None,
    }
}

/// Turn one derived usage-summary record into the inventory row's cells,
/// in [`columns`] order. The record is the single source of truth: the
/// inventory never re-derives or reinterprets a value.
///
/// The family invariants are structural here: a `measured` denominator
/// carries every count and no reason; an `unknown` denominator carries
/// exactly the reason and no count at all — the bounded state, never a
/// zero.
fn row_cells(record: &Object) -> Vec<Cell> {
    let usage = match record.get("harness_usage") {
        Some(Value::Object(usage)) => usage.clone(),
        _ => Object::new(),
    };
    let state = text_of(&usage, "state").unwrap_or_default().to_owned();
    let measured = state == "measured";
    let cache_creation = match usage.get("cache_creation") {
        Some(Value::Object(cache)) => cache.clone(),
        _ => Object::new(),
    };

    // The denominator's own contract decides which columns exist:
    // counts only beside `measured`, a reason only beside `unknown`.
    let count = |name: &str| {
        if measured {
            int_of(&usage, name).map_or(Cell::Null, Cell::Int)
        } else {
            Cell::Null
        }
    };
    let reason = if measured {
        Cell::Null
    } else {
        text_of(&usage, "reason").map_or(Cell::Null, |reason| Cell::Text(reason.to_owned()))
    };

    vec![
        Cell::Text(text_of(record, "tenant_id").unwrap_or_default().to_owned()),
        Cell::Text(
            text_of(record, "occurrence_id")
                .unwrap_or_default()
                .to_owned(),
        ),
        Cell::Text(text_of(record, "adapter_id").unwrap_or_default().to_owned()),
        Cell::Text(
            text_of(record, "adapter_projection_version")
                .unwrap_or_default()
                .to_owned(),
        ),
        Cell::Text(
            text_of(record, "usage_summary_digest")
                .unwrap_or_default()
                .to_owned(),
        ),
        Cell::Text(state),
        reason,
        text_of(record, "model_id").map_or(Cell::Null, |model| Cell::Text(model.to_owned())),
        text_of(record, "service_tier").map_or(Cell::Null, |tier| Cell::Text(tier.to_owned())),
        count("assistant_message_count"),
        count("input_tokens"),
        count("output_tokens"),
        count("cache_read_tokens"),
        if measured {
            int_of(&cache_creation, "ephemeral_5m").map_or(Cell::Null, Cell::Int)
        } else {
            Cell::Null
        },
        if measured {
            int_of(&cache_creation, "ephemeral_1h").map_or(Cell::Null, Cell::Int)
        } else {
            Cell::Null
        },
        count("reasoning_tokens"),
        // The provider reservation: the state column is required and
        // names the bounded unknown; the counts stay absent — never a
        // zero, never a sum with the harness family.
        Cell::Text(PROVIDER_STATE_V1.to_owned()),
        Cell::Null,
        Cell::Null,
        Cell::Null,
    ]
}

/// Why one partition file cannot answer the usage query. Every variant
/// is a refusal: the query never guesses past a file it cannot vouch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UsageQueryError {
    /// The bytes are not a readable partition file of this module's
    /// Parquet subset.
    Partition(TableDecodeError),
    /// The file's columns are not the pinned inventory schema — a
    /// partition this query's column list does not vouch.
    Schema,
    /// A row violated the harness family's own contract: a count beside
    /// an `unknown` state, a missing count beside `measured`, or a
    /// state token outside the closed v1 set.
    RowInvariant,
}

/// One group of the usage query's answer: the summed harness-reported
/// counts of every `measured` row sharing one (tenant, model, service
/// tier) identity. No provider-observed count exists here — the two
/// denominators are never summed, and v1 partitions carry no provider
/// counts to sum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsageTotal {
    /// The tenant every summed row names.
    pub tenant_id: String,
    /// The model identity the rows reported, or `None` when the source
    /// named none the record could carry.
    pub model_id: Option<String>,
    /// The service tier the rows reported, or `None`.
    pub service_tier: Option<String>,
    /// `measured` rows in the group.
    pub rows: u64,
    /// Summed assistant messages behind the counts.
    pub assistant_message_count: i64,
    /// Summed harness-reported input tokens.
    pub input_tokens: i64,
    /// Summed harness-reported output tokens.
    pub output_tokens: i64,
    /// Summed harness-reported cache-read tokens.
    pub cache_read_tokens: i64,
    /// Summed harness-reported 5-minute ephemeral cache-creation tokens.
    pub cache_creation_5m_tokens: i64,
    /// Summed harness-reported 1-hour ephemeral cache-creation tokens.
    pub cache_creation_1h_tokens: i64,
    /// Summed harness-reported reasoning tokens.
    pub reasoning_tokens: i64,
}

/// The usage query's answer over one partition file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UsageTotals {
    /// One group per distinct (tenant, model, tier), in ascending key
    /// order — a pure function of the partition's rows.
    pub groups: Vec<UsageTotal>,
    /// Rows excluded because their source reported no usage — the
    /// disclosure that the totals cover `measured` rows only, never a
    /// claim that the excluded rows consumed nothing.
    pub excluded_unknown_rows: u64,
}

/// The usage query over one partition file's bytes: decode it, vouch its
/// schema against the pinned column list, and total the harness-reported
/// counts by tenant, model, and service tier.
///
/// Rows whose harness state is not `measured` are **excluded** from
/// every total and counted in
/// [`UsageTotals::excluded_unknown_rows`] — never folded in as zeros, so
/// a source that reported no usage cannot read as free. A row that
/// violates the family's own contract (counts beside `unknown`, or a
/// missing count beside `measured`) is refused, not skipped: a query
/// that tolerates a lying row would total a lie. The provider-observed
/// columns are never read here — no single column, and no single query,
/// can sum the two denominators.
///
/// # Errors
/// [`UsageQueryError::Partition`] when the bytes do not decode,
/// [`UsageQueryError::Schema`] when the decoded columns are not the
/// pinned v1 list, and [`UsageQueryError::RowInvariant`] when any row
/// violates the harness family's contract.
pub fn usage_totals(partition: &[u8]) -> Result<UsageTotals, UsageQueryError> {
    let file = Table::decode(partition).map_err(UsageQueryError::Partition)?;
    if file.table().columns() != columns().as_slice() {
        return Err(UsageQueryError::Schema);
    }

    let mut order: Vec<GroupKey> = Vec::new();
    let mut groups: Vec<UsageTotal> = Vec::new();
    let mut excluded: u64 = 0;

    for row in file.table().rows() {
        match cell_text(row, COLUMN_STATE).unwrap_or_default() {
            "measured" => fold_measured(row, &mut order, &mut groups)?,
            // No count may sit beside an unknown denominator.
            "unknown" => {
                if (COLUMN_FIRST_COUNT..=COLUMN_LAST_COUNT).any(|i| cell_count(row, i).is_some()) {
                    return Err(UsageQueryError::RowInvariant);
                }
                excluded = excluded.saturating_add(1);
            }
            _ => return Err(UsageQueryError::RowInvariant),
        }
    }

    // Ascending key order, a pure function of the rows.
    let mut keyed: Vec<(GroupKey, UsageTotal)> = order.into_iter().zip(groups).collect();
    keyed.sort_by(|(left, _), (right, _)| left.cmp(right));
    Ok(UsageTotals {
        groups: keyed.into_iter().map(|(_, total)| total).collect(),
        excluded_unknown_rows: excluded,
    })
}

/// The pinned schema's own column positions: the list [`columns`]
/// returns is the single source of truth, and the query vouches a file's
/// columns against it before reading any row by position.
const COLUMN_TENANT: usize = 0;
const COLUMN_STATE: usize = 5;
const COLUMN_REASON: usize = 6;
const COLUMN_MODEL: usize = 7;
const COLUMN_TIER: usize = 8;
const COLUMN_MESSAGE_COUNT: usize = 9;
const COLUMN_FIRST_COUNT: usize = 10;
const COLUMN_LAST_COUNT: usize = 15;

/// The identity one usage total is grouped by: tenant, model, service
/// tier.
type GroupKey = (String, Option<String>, Option<String>);

/// One row cell's optional text value.
fn cell_text(row: &[Cell], index: usize) -> Option<&str> {
    match &row[index] {
        Cell::Text(value) => Some(value.as_str()),
        _ => None,
    }
}

/// One row cell's optional integer value.
fn cell_count(row: &[Cell], index: usize) -> Option<i64> {
    match &row[index] {
        Cell::Int(value) => Some(*value),
        _ => None,
    }
}

/// Fold one `measured` row into its identity's group: every count must
/// be present, no reason may sit beside a measured denominator, and no
/// sum may overflow — a violated contract is a refusal, never a skip.
fn fold_measured(
    row: &[Cell],
    order: &mut Vec<GroupKey>,
    groups: &mut Vec<UsageTotal>,
) -> Result<(), UsageQueryError> {
    let values: Vec<i64> = (COLUMN_FIRST_COUNT..=COLUMN_LAST_COUNT)
        .map(|i| cell_count(row, i))
        .collect::<Option<Vec<i64>>>()
        .ok_or(UsageQueryError::RowInvariant)?;
    if matches!(row[COLUMN_REASON], Cell::Text(_)) {
        return Err(UsageQueryError::RowInvariant);
    }

    let key: GroupKey = (
        cell_text(row, COLUMN_TENANT).unwrap_or_default().to_owned(),
        cell_text(row, COLUMN_MODEL).map(str::to_owned),
        cell_text(row, COLUMN_TIER).map(str::to_owned),
    );
    let position = if let Some(position) = order.iter().position(|existing| *existing == key) {
        position
    } else {
        order.push(key.clone());
        groups.push(UsageTotal {
            tenant_id: key.0,
            model_id: key.1,
            service_tier: key.2,
            rows: 0,
            assistant_message_count: 0,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_tokens: 0,
        });
        groups.len() - 1
    };

    let group = &mut groups[position];
    group.rows = group.rows.saturating_add(1);
    group.assistant_message_count = group
        .assistant_message_count
        .checked_add(cell_count(row, COLUMN_MESSAGE_COUNT).ok_or(UsageQueryError::RowInvariant)?)
        .ok_or(UsageQueryError::RowInvariant)?;
    for (summed, value) in [
        &mut group.input_tokens,
        &mut group.output_tokens,
        &mut group.cache_read_tokens,
        &mut group.cache_creation_5m_tokens,
        &mut group.cache_creation_1h_tokens,
        &mut group.reasoning_tokens,
    ]
    .into_iter()
    .zip(values)
    {
        *summed = summed
            .checked_add(value)
            .ok_or(UsageQueryError::RowInvariant)?;
    }
    Ok(())
}

/// The key of one partition file: the source digest directory, the
/// digest-prefix shard, the `.parquet` name — tenant-scoped by the
/// derived writer's own grammar.
fn partition_key(
    tenant: &TenantId,
    source: &str,
    shard: &str,
) -> Result<DerivedObjectKey, StorageError> {
    DerivedObjectKey::new(
        tenant,
        INVENTORY_PIPELINE_ID,
        INVENTORY_PIPELINE_VERSION,
        &format!("{source}/part-{shard}.parquet"),
    )
    .map_err(|_| fault(ROW_KEY_GRAMMAR))
}

/// The key of the source directory's manifest.
fn manifest_key(tenant: &TenantId, source: &str) -> Result<DerivedObjectKey, StorageError> {
    DerivedObjectKey::new(
        tenant,
        INVENTORY_PIPELINE_ID,
        INVENTORY_PIPELINE_VERSION,
        &format!("{source}/{MANIFEST_NAME}"),
    )
    .map_err(|_| fault(ROW_KEY_GRAMMAR))
}

/// One completed build: everything the report and the next consumer
/// need, all of it a function of the frozen prefix and the pinned
/// identity — never of the run.
#[derive(Clone, Debug)]
pub struct InventoryOutcome {
    tenant: TenantId,
    projection_version: String,
    source_inventory_digest: String,
    occurrences_total: u64,
    row_states: RowTally,
    chain_digest: String,
    partitions: Vec<PartitionSummary>,
    manifest_digest: String,
    manifest_key: String,
    manifest_bytes: Vec<u8>,
}

impl InventoryOutcome {
    /// The tenant the build ran for.
    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The usage projection version whose reading produced the rows.
    #[must_use]
    pub fn projection_version(&self) -> &str {
        &self.projection_version
    }

    /// The frozen raw prefix's `inventory-v1` digest — the source
    /// commitment every emitted byte names.
    #[must_use]
    pub fn source_inventory_digest(&self) -> &str {
        &self.source_inventory_digest
    }

    /// Occurrences the prefix carried: one inventory row each.
    #[must_use]
    pub const fn occurrences_total(&self) -> u64 {
        self.occurrences_total
    }

    /// The cumulative per-row denominator tally, as the wire record
    /// (`measured`, `absent`, `malformed`, `unsupported` counts).
    #[must_use]
    pub fn row_states(&self) -> Object {
        self.row_states.record()
    }

    /// The fold's chain digest — the same construction the catalog
    /// rebuild's checkpoint carries for the same prefix and projection,
    /// so the two pipelines' views of one prefix are comparable by
    /// digest.
    #[must_use]
    pub fn chain_digest(&self) -> &str {
        &self.chain_digest
    }

    /// The landed partitions, in shard order.
    #[must_use]
    pub fn partitions(&self) -> &[PartitionSummary] {
        &self.partitions
    }

    /// The manifest's self-verifying digest.
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }

    /// The content-named key the manifest was written under.
    #[must_use]
    pub fn manifest_key(&self) -> &str {
        &self.manifest_key
    }

    /// The manifest's exact bytes, as written.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// Render the content-free result document: cumulative build state
    /// only, the same shape the catalog rebuild reports.
    #[must_use]
    pub fn result_document(&self) -> Object {
        let mut document = Object::new();
        document.set(
            "inventory_schema_version",
            Value::Int(INVENTORY_SCHEMA_VERSION),
        );
        document.set("pipeline_id", Value::Text(INVENTORY_PIPELINE_ID.to_owned()));
        document.set(
            "pipeline_version",
            Value::Text(INVENTORY_PIPELINE_VERSION.to_owned()),
        );
        document.set("tenant_id", Value::Text(self.tenant.as_str().to_owned()));
        document.set(
            "source_inventory_digest",
            Value::Text(self.source_inventory_digest.clone()),
        );
        document.set("usage_pipeline_id", Value::Text(USAGE_PIPELINE.to_owned()));
        document.set(
            "usage_pipeline_version",
            Value::Text(USAGE_PIPELINE_VERSION.to_owned()),
        );
        document.set(
            "usage_projection_version",
            Value::Text(self.projection_version.clone()),
        );
        document.set("usage_summary_version", Value::Int(USAGE_SUMMARY_VERSION));
        document.set(
            "occurrences_total",
            Value::Int(i64::try_from(self.occurrences_total).unwrap_or(i64::MAX)),
        );
        document.set("row_states", Value::Object(self.row_states.record()));
        document.set("chain_digest", Value::Text(self.chain_digest.clone()));
        document.set(
            "partition_count",
            Value::Int(i64::try_from(self.partitions.len()).unwrap_or(i64::MAX)),
        );
        document.set("manifest_digest", Value::Text(self.manifest_digest.clone()));
        document.set("manifest_key", Value::Text(self.manifest_key.clone()));
        document
    }
}

/// One landed partition file, as the manifest records it.
#[derive(Clone, Debug)]
pub struct PartitionSummary {
    /// The two-hex shard label.
    pub shard: String,
    /// The derived key the file was written under.
    pub key: String,
    /// Inventory rows in the file.
    pub rows: u64,
    /// The file's exact byte size.
    pub file_size: u64,
    /// The file's plain SHA-256 — the same construction the checkpoint
    /// keys use, so a reader verifies bytes against the manifest.
    pub digest: String,
}

/// Run the inventory build: one complete pass over the tenant's frozen
/// raw prefix, materializing the partition files and their manifest
/// through the derived writer.
///
/// The pass fails closed on every source fault — the raw source's own
/// discipline — and on any failed put; a failed build's directory stays
/// incomplete (no manifest), and the next run converges on the identical
/// files.
///
/// # Errors
/// The store's own failures while freezing, reading, or validating the
/// prefix, the writer's failures while putting a partition or the
/// manifest, and [`StorageErrorKind::IntegrityConflict`] if any derived
/// key left the scoped writer grammar.
#[allow(clippy::too_many_lines)]
pub async fn inventory_build<S, W, F>(
    audit: &S,
    derived: &W,
    projection: &UsageProjection<F>,
    tenant: &TenantId,
) -> Result<InventoryOutcome, StorageError>
where
    S: AuditRestoreStore + ?Sized,
    W: DerivedWriteStore + ?Sized,
    F: Fn(&AdapterId, &[u8]) -> Vec<MessageUsage>,
{
    let scope = InventoryScope::TenantRaw(tenant.clone());
    let inventory = audit.freeze_inventory(&scope).await?;
    let index = RawCatalogIndex::new(&inventory)?;
    let source_digest = inventory.digest().to_hex();
    let mut source = RawCatalogSource::open(audit, &index).await?;

    let schema = columns();
    let mut shards: BTreeMap<String, Table> = BTreeMap::new();
    let mut tally = RowTally::default();
    let mut chain = chain_genesis(&source_digest);
    let mut occurrences: u64 = 0;

    while let Some(record) = source.next_occurrence(audit).await? {
        let manifest = record.manifest();
        let plaintext = decode_blob(record.blob().stored().bytes())?;
        let messages = projection.project(manifest.adapter_id(), &plaintext);
        let provenance = OccurrenceProvenance {
            tenant_id: tenant.clone(),
            adapter_id: manifest.adapter_id().clone(),
            adapter_projection_version: projection.version().clone(),
            occurrence_id: *manifest.occurrence_id(),
        };
        let row = archivist_protocol::usage_summary::UsageSummary::derive(&provenance, &messages);

        let cells = row_cells(row.record());
        if cells.len() != schema.len() {
            return Err(fault(ROW_SHAPE));
        }
        let shard = row.digest()[..2].to_owned();
        let table = shards
            .entry(shard)
            .or_insert_with(|| Table::new(schema.clone()));
        table.push(cells).map_err(|_| fault(ROW_SHAPE))?;

        chain = chain_advance(&chain, manifest.key().as_str(), row.digest());
        tally.advance(row.harness_usage_state());
        occurrences = occurrences.saturating_add(1);
    }

    // Partitions first, manifest last: the manifest is the
    // completeness statement, so a directory without one is never
    // authoritative.
    let mut partitions = Vec::with_capacity(shards.len());
    let projection_version = projection.version().as_str().to_owned();
    for (shard, table) in &shards {
        let rows_label = table.len().to_string();
        let metadata = [
            ("inventory_schema_version", INVENTORY_SCHEMA_VERSION_STRING),
            ("pipeline_id", INVENTORY_PIPELINE_ID),
            ("pipeline_version", INVENTORY_PIPELINE_VERSION),
            ("tenant_id", tenant.as_str()),
            ("source_inventory_digest", source_digest.as_str()),
            ("usage_pipeline_id", USAGE_PIPELINE),
            ("usage_pipeline_version", USAGE_PIPELINE_VERSION),
            ("usage_projection_version", projection_version.as_str()),
            ("usage_summary_version", USAGE_SUMMARY_VERSION_STRING),
            ("partition_rows", rows_label.as_str()),
        ];
        let bytes = table.encode(&metadata);
        let key = partition_key(tenant, &source_digest, shard)?;
        derived.put_object(&key, &bytes).await?;
        partitions.push(PartitionSummary {
            shard: shard.clone(),
            key: key.as_str().to_owned(),
            rows: u64::try_from(table.len()).unwrap_or(u64::MAX),
            file_size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            digest: blob_digest(&bytes).to_hex(),
        });
    }

    let (manifest_digest, manifest_bytes) = manifest_document(
        tenant,
        &projection_version,
        &source_digest,
        &chain,
        &tally,
        occurrences,
        &partitions,
    );
    let key = manifest_key(tenant, &source_digest)?;
    derived.put_object(&key, &manifest_bytes).await?;

    Ok(InventoryOutcome {
        tenant: tenant.clone(),
        projection_version,
        source_inventory_digest: source_digest,
        occurrences_total: occurrences,
        row_states: tally,
        chain_digest: chain,
        partitions,
        manifest_digest,
        manifest_key: key.as_str().to_owned(),
        manifest_bytes,
    })
}

/// The schema version as the partition metadata string.
const INVENTORY_SCHEMA_VERSION_STRING: &str = "1";
/// The usage-summary version as the partition metadata string.
const USAGE_SUMMARY_VERSION_STRING: &str = "1";

/// Assemble, digest, and render the manifest document: canonical JSON
/// plus exactly one trailing LF, the family rendering, with the
/// self-verifying digest excluding its own member from the preimage
/// (VAL-005, the family's construction).
fn manifest_document(
    tenant: &TenantId,
    projection_version: &str,
    source_digest: &str,
    chain: &str,
    tally: &RowTally,
    occurrences: u64,
    partitions: &[PartitionSummary],
) -> (String, Vec<u8>) {
    let listed: Vec<Value> = partitions
        .iter()
        .map(|partition| {
            let mut entry = Object::new();
            entry.set("shard", Value::Text(partition.shard.clone()));
            entry.set("key", Value::Text(partition.key.clone()));
            entry.set(
                "rows",
                Value::Int(i64::try_from(partition.rows).unwrap_or(i64::MAX)),
            );
            entry.set(
                "file_size",
                Value::Int(i64::try_from(partition.file_size).unwrap_or(i64::MAX)),
            );
            entry.set("partition_digest", Value::Text(partition.digest.clone()));
            Value::Object(entry)
        })
        .collect();

    let mut document = Object::new();
    document.set(
        "inventory_schema_version",
        Value::Int(INVENTORY_SCHEMA_VERSION),
    );
    document.set("pipeline_id", Value::Text(INVENTORY_PIPELINE_ID.to_owned()));
    document.set(
        "pipeline_version",
        Value::Text(INVENTORY_PIPELINE_VERSION.to_owned()),
    );
    document.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    document.set(
        "source_inventory_digest",
        Value::Text(source_digest.to_owned()),
    );
    document.set("usage_pipeline_id", Value::Text(USAGE_PIPELINE.to_owned()));
    document.set(
        "usage_pipeline_version",
        Value::Text(USAGE_PIPELINE_VERSION.to_owned()),
    );
    document.set(
        "usage_projection_version",
        Value::Text(projection_version.to_owned()),
    );
    document.set("usage_summary_version", Value::Int(USAGE_SUMMARY_VERSION));
    document.set(
        "occurrences_total",
        Value::Int(i64::try_from(occurrences).unwrap_or(i64::MAX)),
    );
    document.set("row_states", Value::Object(tally.record()));
    document.set("chain_digest", Value::Text(chain.to_owned()));
    document.set(
        "partition_count",
        Value::Int(i64::try_from(partitions.len()).unwrap_or(i64::MAX)),
    );
    document.set("partitions", Value::Array(listed));

    let mut frame = FrameBuilder::new(MANIFEST_DIGEST_LABEL);
    frame.push_bytes(&Value::Object(document.clone()).canonical_bytes());
    let digest = sha256::encode_hex(&frame.finish());
    document.set("inventory_manifest_digest", Value::Text(digest.clone()));

    let mut bytes = Value::Object(document).canonical_bytes();
    bytes.push(b'\n');
    (digest, bytes)
}

#[cfg(test)]
mod tests {
    //! The schema and layout invariants the build depends on: the pinned
    //! column list, the family nullability contract, and the scoped
    //! writer grammar accepting the partition layout. The end-to-end
    //! build proofs — reproducibility, tenant isolation, source
    //! versioning, the unknown-never-zero rule — live in the crate's
    //! integration suite, which drives the public API over the same
    //! mock identities the rebuild engine's tests use.

    use super::{columns, manifest_key, partition_key, row_cells};
    use crate::parquet::Column;
    use crate::scoped_write::DerivedObjectKey;
    use archivist_protocol::json::{Object, Value};

    #[test]
    fn schema_is_the_pinned_v1_list() {
        let schema = columns();
        assert_eq!(schema.len(), 20);
        let names: Vec<&str> = schema.iter().map(Column::name).collect();
        assert_eq!(
            names,
            vec![
                "tenant_id",
                "occurrence_id",
                "adapter_id",
                "adapter_projection_version",
                "usage_summary_digest",
                "harness_state",
                "harness_unknown_reason",
                "harness_model_id",
                "harness_service_tier",
                "harness_assistant_message_count",
                "harness_input_tokens",
                "harness_output_tokens",
                "harness_cache_read_tokens",
                "harness_cache_creation_5m_tokens",
                "harness_cache_creation_1h_tokens",
                "harness_reasoning_tokens",
                "provider_state",
                "provider_input_tokens",
                "provider_output_tokens",
                "provider_total_tokens",
            ]
        );
        // The provenance spine is required; every count column is
        // optional — absence is how the file states *omitted*.
        for name in [
            "tenant_id",
            "occurrence_id",
            "adapter_id",
            "adapter_projection_version",
            "usage_summary_digest",
            "harness_state",
            "provider_state",
        ] {
            let column = schema.iter().find(|c| c.name() == name).expect("named");
            assert!(column.required(), "{name} is required");
        }
        for column in &schema {
            if column.name().starts_with("harness_") && column.name() != "harness_state" {
                assert!(!column.required(), "{} stays optional", column.name());
            }
            if column.name().starts_with("provider_") && column.name() != "provider_state" {
                assert!(!column.required(), "{} stays optional", column.name());
            }
        }
    }

    #[test]
    fn measured_rows_carry_counts_and_no_reason() {
        let mut record = Object::new();
        record.set("tenant_id", Value::Text("t".to_owned()));
        record.set("occurrence_id", Value::Text("occ".to_owned()));
        record.set("adapter_id", Value::Text("adapter".to_owned()));
        record.set("adapter_projection_version", Value::Text("1".to_owned()));
        record.set("usage_summary_digest", Value::Text("ab99".to_owned()));
        let mut usage = Object::new();
        usage.set("state", Value::Text("measured".to_owned()));
        usage.set("input_tokens", Value::Int(11));
        usage.set("output_tokens", Value::Int(7));
        usage.set("cache_read_tokens", Value::Int(3));
        let mut cache = Object::new();
        cache.set("ephemeral_5m", Value::Int(5));
        cache.set("ephemeral_1h", Value::Int(0));
        usage.set("cache_creation", Value::Object(cache));
        usage.set("reasoning_tokens", Value::Int(0));
        usage.set("assistant_message_count", Value::Int(1));
        record.set("harness_usage", Value::Object(usage));

        let cells = row_cells(&record);
        assert_eq!(cells.len(), columns().len());
        assert_eq!(cells[5], super::Cell::Text("measured".to_owned()));
        assert_eq!(cells[6], super::Cell::Null, "no reason beside measured");
        assert_eq!(cells[9], super::Cell::Int(1));
        assert_eq!(cells[10], super::Cell::Int(11));
        assert_eq!(cells[13], super::Cell::Int(5));
        assert_eq!(cells[14], super::Cell::Int(0), "zero is an observation");
        // The provider reservation: unknown, and no count anywhere.
        assert_eq!(cells[16], super::Cell::Text("unknown".to_owned()));
        for cell in &cells[17..20] {
            assert_eq!(*cell, super::Cell::Null);
        }
    }

    #[test]
    fn unknown_rows_carry_the_reason_and_never_a_count() {
        let mut record = Object::new();
        record.set("tenant_id", Value::Text("t".to_owned()));
        record.set("occurrence_id", Value::Text("occ".to_owned()));
        record.set("adapter_id", Value::Text("adapter".to_owned()));
        record.set("adapter_projection_version", Value::Text("1".to_owned()));
        record.set("usage_summary_digest", Value::Text("cd77".to_owned()));
        let mut usage = Object::new();
        usage.set("state", Value::Text("unknown".to_owned()));
        usage.set("reason", Value::Text("absent".to_owned()));
        record.set("harness_usage", Value::Object(usage));

        let cells = row_cells(&record);
        assert_eq!(cells[5], super::Cell::Text("unknown".to_owned()));
        assert_eq!(cells[6], super::Cell::Text("absent".to_owned()));
        for cell in &cells[9..16] {
            assert_eq!(*cell, super::Cell::Null, "no count beside unknown");
        }
    }

    #[test]
    fn partition_layout_fits_the_scoped_writer_grammar() {
        let tenant =
            archivist_protocol::vocabulary::TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b")
                .expect("grammar");
        let digest = "a".repeat(64);
        let key = partition_key(&tenant, &digest, "3f").expect("grammar");
        assert!(key.as_str().starts_with(&DerivedObjectKey::prefix(&tenant)));
        assert!(key.as_str().ends_with(&format!("{digest}/part-3f.parquet")));
        assert_eq!(
            key.as_str(),
            format!("tenants/{tenant}/v1/derived/inventory/1/{digest}/part-3f.parquet")
        );

        let manifest = manifest_key(&tenant, &digest).expect("grammar");
        assert_eq!(
            manifest.as_str(),
            format!("tenants/{tenant}/v1/derived/inventory/1/{digest}/manifest.json")
        );
    }

    // ---- The usage query ----

    use super::{UsageQueryError, usage_totals};
    use crate::parquet::{Cell, Table};

    /// One `measured` row over the pinned schema: the provenance spine,
    /// the named identity, and the full count family.
    fn measured_row(tenant: &str, model: &str, tier: &str, input: i64) -> Vec<Cell> {
        vec![
            Cell::Text(tenant.to_owned()),
            Cell::Text("occ".to_owned()),
            Cell::Text("adapter".to_owned()),
            Cell::Text("1".to_owned()),
            Cell::Text("ab99".to_owned()),
            Cell::Text("measured".to_owned()),
            Cell::Null,
            Cell::Text(model.to_owned()),
            Cell::Text(tier.to_owned()),
            Cell::Int(1),
            Cell::Int(input),
            Cell::Int(2),
            Cell::Int(0),
            Cell::Int(0),
            Cell::Int(0),
            Cell::Int(0),
            Cell::Text("unknown".to_owned()),
            Cell::Null,
            Cell::Null,
            Cell::Null,
        ]
    }

    /// One `unknown` row: the reason and no count anywhere.
    fn unknown_row(tenant: &str, reason: &str) -> Vec<Cell> {
        vec![
            Cell::Text(tenant.to_owned()),
            Cell::Text("occ".to_owned()),
            Cell::Text("adapter".to_owned()),
            Cell::Text("1".to_owned()),
            Cell::Text("cd77".to_owned()),
            Cell::Text("unknown".to_owned()),
            Cell::Text(reason.to_owned()),
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Null,
            Cell::Text("unknown".to_owned()),
            Cell::Null,
            Cell::Null,
            Cell::Null,
        ]
    }

    /// Encode rows over the pinned schema into one partition's bytes.
    fn partition_bytes(rows: Vec<Vec<Cell>>) -> Vec<u8> {
        let mut table = Table::new(columns());
        for row in rows {
            table.push(row).expect("row fits the pinned schema");
        }
        table.encode(&[])
    }

    /// Encode one file over a caller-supplied schema, rows empty.
    fn partition_bytes_schema(schema: Vec<crate::parquet::Column>) -> Vec<u8> {
        Table::new(schema).encode(&[])
    }

    #[test]
    fn the_query_totals_measured_rows_by_identity() {
        let bytes = partition_bytes(vec![
            measured_row("tenant-a", "model-b", "priority", 30),
            measured_row("tenant-a", "model-a", "standard", 11),
            unknown_row("tenant-a", "absent"),
            measured_row("tenant-a", "model-a", "standard", 7),
            unknown_row("tenant-a", "malformed"),
        ]);

        let totals = usage_totals(&bytes).expect("the partition answers");
        assert_eq!(
            totals.excluded_unknown_rows, 2,
            "the unknowns are disclosed"
        );
        assert_eq!(
            totals.groups,
            vec![
                super::UsageTotal {
                    tenant_id: "tenant-a".to_owned(),
                    model_id: Some("model-a".to_owned()),
                    service_tier: Some("standard".to_owned()),
                    rows: 2,
                    assistant_message_count: 2,
                    input_tokens: 18,
                    output_tokens: 4,
                    cache_read_tokens: 0,
                    cache_creation_5m_tokens: 0,
                    cache_creation_1h_tokens: 0,
                    reasoning_tokens: 0,
                },
                super::UsageTotal {
                    tenant_id: "tenant-a".to_owned(),
                    model_id: Some("model-b".to_owned()),
                    service_tier: Some("priority".to_owned()),
                    rows: 1,
                    assistant_message_count: 1,
                    input_tokens: 30,
                    output_tokens: 2,
                    cache_read_tokens: 0,
                    cache_creation_5m_tokens: 0,
                    cache_creation_1h_tokens: 0,
                    reasoning_tokens: 0,
                },
            ],
            "one group per (tenant, model, tier), in ascending key order"
        );
    }

    #[test]
    fn the_query_refuses_a_count_beside_unknown() {
        let mut lying = unknown_row("tenant-a", "absent");
        lying[10] = Cell::Int(5);
        let bytes = partition_bytes(vec![lying]);
        assert_eq!(
            usage_totals(&bytes),
            Err(UsageQueryError::RowInvariant),
            "a count beside an unknown denominator is a lie, not a total"
        );
    }

    #[test]
    fn the_query_refuses_a_measured_row_missing_a_count() {
        let mut partial = measured_row("tenant-a", "model-a", "standard", 11);
        partial[13] = Cell::Null;
        let bytes = partition_bytes(vec![partial]);
        assert_eq!(
            usage_totals(&bytes),
            Err(UsageQueryError::RowInvariant),
            "a partial measured sum would misstate the denominator"
        );
    }

    #[test]
    fn the_query_refuses_a_state_outside_the_closed_set() {
        let mut strange = measured_row("tenant-a", "model-a", "standard", 11);
        strange[5] = Cell::Text("measured-v2".to_owned());
        let bytes = partition_bytes(vec![strange]);
        assert_eq!(usage_totals(&bytes), Err(UsageQueryError::RowInvariant));
    }

    #[test]
    fn the_query_refuses_a_foreign_schema() {
        let mut renamed = columns();
        renamed[0] = crate::parquet::Column::required_text("not_tenant_id");
        let bytes = partition_bytes_schema(renamed);
        assert_eq!(usage_totals(&bytes), Err(UsageQueryError::Schema));
    }

    #[test]
    fn the_query_refuses_bytes_that_do_not_decode() {
        assert_eq!(
            usage_totals(b"not a parquet file at all"),
            Err(UsageQueryError::Partition(
                crate::parquet::TableDecodeError::Framing
            ))
        );
    }

    #[test]
    fn the_query_never_reads_the_provider_family() {
        // Even a row whose provider cells carry numbers — a shape the v1
        // writer never emits, but the optional schema permits — totals
        // through the harness columns only. No query over one column can
        // sum the two denominators, because this one reads only one.
        let mut row = measured_row("tenant-a", "model-a", "standard", 11);
        row[17] = Cell::Int(999_999);
        row[18] = Cell::Int(999_999);
        row[19] = Cell::Int(1_999_998);
        let bytes = partition_bytes(vec![row]);

        let totals = usage_totals(&bytes).expect("the partition answers");
        assert_eq!(totals.groups.len(), 1);
        assert_eq!(totals.groups[0].input_tokens, 11, "harness only");
        assert_eq!(totals.groups[0].output_tokens, 2, "harness only");
    }
}
