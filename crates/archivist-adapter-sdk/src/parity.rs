// SPDX-License-Identifier: Apache-2.0

//! The database parity oracle's comparison core (plan Phase 6, the
//! Database-adapter parity decision; AC-07 in
//! docs/security/threats/adapter-capture.md).
//!
//! Database-adapter parity means *a transactionally consistent read-only
//! snapshot and the adapter produce identical ordered allowlisted primary
//! keys, row counts, null/presence bits, and per-field SHA-256 digests.
//! Non-allowlisted columns are neither read nor hashed.* This module is
//! the oracle that decides that sentence: it compares two observations —
//! one taken by the adapter's projection path, one taken independently by
//! the parity caller's own direct reads — and names every divergence class
//! the decision owes a detection for.
//!
//! # Independent observations
//!
//! AC-07's attacker is *a parity implementation keyed to what the adapter
//! already read*: an oracle that re-derives one side from the other can
//! only ever compare the adapter against itself, so truncation, omission,
//! reordering, and corruption all pass. The oracle therefore takes both
//! sides as opaque [`DatabaseObservation`] values built by their own
//! readers — the projection side from the adapter's projected records, the
//! source side from a separate read-only connection's own queries — and
//! shares nothing between the two constructions but this vocabulary. The
//! evidence suite in `archivist-adapter-opencode`
//! (`tests/database_parity_oracle.rs`) drives both sides against a real
//! store.
//!
//! # No whole-database hashing
//!
//! The comparison is the parity tuple alone — ordered keys, presence bits,
//! per-field digests — never a hash of the database file. A whole-file
//! hash is unstable across the store's own bookkeeping and would fold
//! credential tables and unrelated caches into the verdict; the tuple
//! confines parity to the allowlist, so churn in an excluded table leaves
//! parity intact (the evidence suite plants exactly that churn).
//!
//! # The digest contract
//!
//! A field's observation is its presence bit plus a
//! [`FieldDigest`]: SHA-256 over the value's storage class, its byte
//! length, and its raw bytes. Binding the class keeps byte-equal values of
//! different classes (a text `"1"` and a blob `01`) distinct; binding the
//! length keeps a strict prefix of a large value from digesting like the
//! whole value — which is what makes export truncation of a multi-megabyte
//! field detectable as an ordinary field divergence rather than an
//! anything-goes fuzzy match.
//!
//! # The divergence vocabulary
//!
//! [`compare`] is total: every way two observations can disagree lands in
//! one closed class, named without source content — table, row, and field
//! *ordinals* only, never a table name, a key value, or field bytes. The
//! classes map onto the faults the acceptance names:
//!
//! | fault | verdict |
//! |---|---|
//! | a lost trailing run of rows (the reader stopped early) | [`Divergence::TruncatedRows`] |
//! | a row lost anywhere else | [`Divergence::OmittedRow`] |
//! | a side's rows out of canonical key order | [`Divergence::Reordered`] |
//! | a matched row's field altered, NULL-ed, filled in, or truncated | [`Divergence::CorruptedField`] |
//! | a projection row the source never observed | [`Divergence::InventedRow`] |
//! | the two sides observe different table counts | [`Divergence::TableSequence`] |
//!
//! A key-value drift on an otherwise matched row appears as an
//! [`Divergence::OmittedRow`] and [`Divergence::InventedRow`] pair — the
//! projection genuinely lost the observed key and holds one the source
//! does not vouch — rather than a speculative pairing the oracle cannot
//! prove. Out-of-order input is named before any row walking: the merge
//! assumes canonical order, and a reordering fault is reported as itself
//! instead of the cascade of spurious omissions and inventions an unsorted
//! walk would manufacture.

use std::cmp::Ordering;
use std::fmt;

use archivist_protocol::sha256::Sha256;

/// One observed cell value in the parity vocabulary: the storage classes a
/// database cell can hold, ordered canonically for key comparison.
///
/// The order is the storage-class order the plan's deterministic snapshot
/// ordering already assumes — `NULL` first, then integers and reals
/// compared numerically against each other (an integer sorts before a real
/// of equal value), then text bytewise, then blobs bytewise. The order is
/// total, so two independent readers that order their rows by these keys
/// observe one sequence whatever physical order the store serves.
///
/// [`fmt::Debug`] is content-free: it names the kind and the byte length,
/// never the bytes. Key values are session identifiers — source content —
/// and cannot reach a log through this type.
#[derive(Clone, PartialEq)]
pub enum ObservedValue {
    /// A NULL cell: the absent half of the presence bit.
    Null,
    /// A signed 64-bit integer cell.
    Integer(i64),
    /// A 64-bit float cell. A store has no `NaN` representation (`SQLite`
    /// stores `NaN` as NULL), so a NaN here is unreachable from a real
    /// read; the order nonetheless stays total, sorting any NaN after
    /// every other numeric value.
    Real(f64),
    /// A text cell's exact stored bytes, valid UTF-8 or not: the oracle
    /// observes, never decodes.
    Text(Vec<u8>),
    /// A blob cell's exact stored bytes.
    Blob(Vec<u8>),
}

impl fmt::Debug for ObservedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (kind, byte_len) = match self {
            Self::Null => ("null", 0),
            Self::Integer(value) => ("integer", std::mem::size_of_val(value)),
            Self::Real(value) => ("real", std::mem::size_of_val(value)),
            Self::Text(bytes) => ("text", bytes.len()),
            Self::Blob(bytes) => ("blob", bytes.len()),
        };
        formatter
            .debug_struct("ObservedValue")
            .field("kind", &kind)
            .field("byte_len", &byte_len)
            .finish()
    }
}

impl ObservedValue {
    /// The presence bit: `false` only for [`ObservedValue::Null`].
    #[must_use]
    pub fn is_present(&self) -> bool {
        !matches!(self, Self::Null)
    }

    /// The value's parity observation: absent for NULL, present with the
    /// digest of its class-bound bytes otherwise. This is the one place a
    /// value becomes comparable parity material.
    #[must_use]
    pub fn observe(&self) -> FieldObservation {
        match self {
            Self::Null => FieldObservation::Absent,
            Self::Integer(value) => FieldObservation::Present(FieldDigest::of(
                StorageClass::Integer,
                &value.to_be_bytes(),
            )),
            Self::Real(value) => {
                FieldObservation::Present(FieldDigest::of(StorageClass::Real, &value.to_be_bytes()))
            }
            Self::Text(bytes) => {
                FieldObservation::Present(FieldDigest::of(StorageClass::Text, bytes))
            }
            Self::Blob(bytes) => {
                FieldObservation::Present(FieldDigest::of(StorageClass::Blob, bytes))
            }
        }
    }
}

impl Ord for ObservedValue {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Null, Self::Null) => Ordering::Equal,
            // `NULL` orders before every value; beyond it, class order
            // decides first — every numeric before any text or blob,
            // whatever their bytes.
            (Self::Null, _) | (Self::Integer(_) | Self::Real(_), Self::Text(_) | Self::Blob(_)) => {
                Ordering::Less
            }
            (_, Self::Null) | (Self::Text(_) | Self::Blob(_), Self::Integer(_) | Self::Real(_)) => {
                Ordering::Greater
            }
            (Self::Integer(left), Self::Integer(right)) => left.cmp(right),
            (Self::Real(left), Self::Real(right)) => left.total_cmp(right),
            (Self::Integer(left), Self::Real(right)) => cmp_integer_real(*left, *right),
            (Self::Real(left), Self::Integer(right)) => cmp_integer_real(*right, *left).reverse(),
            (Self::Text(_), Self::Blob(_)) => Ordering::Less,
            (Self::Blob(_), Self::Text(_)) => Ordering::Greater,
            // Within one class, bytes decide.
            (Self::Text(left), Self::Text(right)) | (Self::Blob(left), Self::Blob(right)) => {
                left.cmp(right)
            }
        }
    }
}

impl PartialOrd for ObservedValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// `Eq` despite the `Real` payload: a store has no NaN representation —
// SQLite stores NaN as NULL, so a NaN real is unreachable from a real
// read and the floats the oracle observes are always reflexive. `Ord`,
// the canonical key order both readers must agree on, requires `Eq`.
impl Eq for ObservedValue {}

/// Compare an integer against a real numerically, exactly: the real's
/// integral part converts through `i128` (lossless for every finite
/// `f64` up to `i128` range, and saturating beyond), so an integer too
/// large for `f64`'s 53-bit mantissa still compares correctly against a
/// nearby real. An integer that matches the real's integral part is
/// never above the real — the real's fractional remainder can only add —
/// so integral equality (with or without a remainder) orders the integer
/// first: strictly less when a remainder exists, and the documented
/// class tiebreak when the values are numerically equal.
fn cmp_integer_real(integer: i64, real: f64) -> Ordering {
    if real.is_nan() {
        // Unreachable from a store (NaN stores as NULL); total anyway:
        // NaN sorts after every other numeric value.
        return Ordering::Less;
    }
    let wide = i128::from(integer);
    // The float-to-int cast saturates rather than wraps, and the operand
    // is a trunc() of a finite f64, so the comparison below holds every
    // value the cast can produce.
    #[allow(clippy::cast_possible_truncation)]
    let truncated = real.trunc() as i128;
    match wide.cmp(&truncated) {
        Ordering::Equal => Ordering::Less,
        other => other,
    }
}

/// The storage class bound into every field digest, so byte-equal values
/// of different classes can never digest alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StorageClass {
    /// A signed 64-bit integer.
    Integer,
    /// A 64-bit float.
    Real,
    /// Text bytes.
    Text,
    /// Blob bytes.
    Blob,
}

impl StorageClass {
    /// The digest's class tag byte. Tags are fixed distinct single bytes;
    /// the value is part of this module's digest contract, not a choice
    /// delegated to the caller.
    #[must_use]
    fn tag(self) -> u8 {
        match self {
            Self::Integer => 1,
            Self::Real => 2,
            Self::Text => 3,
            Self::Blob => 4,
        }
    }
}

/// One field's parity digest: SHA-256 over the value's storage class, its
/// byte length as big-endian `u64`, and its raw bytes.
///
/// The class and the length are what make the digest an honest witness:
/// a text `"1"`, a blob `01`, and an integer `1` digest differently even
/// where their byte renderings coincide, and no strict prefix of a value
/// digests like the whole value — the property export-truncation
/// detection rests on. The digest is one-way and content-free by
/// construction; rendering it names no source bytes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct FieldDigest([u8; 32]);

impl FieldDigest {
    /// Digest `bytes` as a value of `class`.
    #[must_use]
    pub fn of(class: StorageClass, bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&[class.tag()]);
        hasher.update(&(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes()));
        hasher.update(bytes);
        Self(hasher.finalize())
    }

    /// The digest's 32 bytes, for callers that carry verdicts into their
    /// own content-free reporting.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for FieldDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hex of a one-way digest: content-free by construction.
        write!(
            formatter,
            "FieldDigest({})",
            archivist_protocol::sha256::encode_hex(&self.0)
        )
    }
}

/// One field's parity observation: the presence bit, and for a present
/// field its [`FieldDigest`].
///
/// A flip between the variants *is* an altered presence bit — a NULL
/// filled in or a value NULL-ed — and lands as a
/// [`Divergence::CorruptedField`] like any other field drift.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum FieldObservation {
    /// The cell is NULL.
    Absent,
    /// The cell holds a value with this digest.
    Present(FieldDigest),
}

/// One row's parity observation: the ordered primary-key tuple and the
/// per-field observations, each in the caller's fixed allowlist column
/// order.
///
/// Built from observed values by [`RowObservation::observe`], which
/// digests the fields once; the key stays ordered, comparable material.
/// [`fmt::Debug`] is content-free — arities and counts only.
#[derive(Clone, PartialEq)]
pub struct RowObservation {
    key: Vec<ObservedValue>,
    fields: Vec<FieldObservation>,
}

impl fmt::Debug for RowObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RowObservation")
            .field("key_arity", &self.key.len())
            .field("field_count", &self.fields.len())
            .finish()
    }
}

impl RowObservation {
    /// Observe one row: `key` in key-column order, `fields` in the fixed
    /// allowlist column order. Both sides of a comparison must build
    /// their rows over the same column sequence for the field ordinals a
    /// [`Divergence::CorruptedField`] names to mean the same column.
    #[must_use]
    pub fn observe(key: Vec<ObservedValue>, fields: Vec<ObservedValue>) -> Self {
        Self {
            key,
            fields: fields.into_iter().map(|field| field.observe()).collect(),
        }
    }

    /// The ordered primary-key tuple, the row's identity in the merge.
    #[must_use]
    pub fn key(&self) -> &[ObservedValue] {
        &self.key
    }

    /// The per-field observations, in the caller's fixed column order.
    #[must_use]
    pub fn fields(&self) -> &[FieldObservation] {
        &self.fields
    }
}

/// One table's observation: its rows in canonical key order — the order
/// the source's own deterministic ordering and the projection's row order
/// must agree on for parity to hold.
#[derive(Clone, Debug, PartialEq)]
pub struct TableObservation {
    rows: Vec<RowObservation>,
}

impl TableObservation {
    /// Observe one table from its rows, already in the reader's canonical
    /// order. The oracle verifies that order independently: a side whose
    /// rows are out of canonical key order is named
    /// [`Divergence::Reordered`], whatever order the reader claims.
    #[must_use]
    pub fn new(rows: Vec<RowObservation>) -> Self {
        Self { rows }
    }

    /// The rows, in the reader's order.
    #[must_use]
    pub fn rows(&self) -> &[RowObservation] {
        &self.rows
    }
}

/// One side's whole observation: its tables in the fixed comparison
/// sequence. Position identifies a table — the caller's allowlist order —
/// so no table name ever enters a verdict.
#[derive(Clone, Debug, PartialEq)]
pub struct DatabaseObservation {
    tables: Vec<TableObservation>,
}

impl DatabaseObservation {
    /// Observe one side from its tables, in the fixed comparison order
    /// both sides share.
    #[must_use]
    pub fn new(tables: Vec<TableObservation>) -> Self {
        Self { tables }
    }

    /// The tables, in the comparison sequence.
    #[must_use]
    pub fn tables(&self) -> &[TableObservation] {
        &self.tables
    }
}

/// One named way two database observations disagree. Every member is
/// content-free: table, row, and field ordinals only — never a table
/// name, a column name, a key value, or field bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Divergence {
    /// The sides observe different table counts: the comparison sequence
    /// itself disagrees, so no per-table verdict exists to report.
    TableSequence,
    /// A side's rows are out of canonical key order. `row` is the first
    /// position whose key is strictly less than its predecessor's.
    Reordered {
        /// The table's position in the comparison sequence.
        table: usize,
        /// The first out-of-order row, in that side's own order.
        row: usize,
    },
    /// The projection is missing one trailing run of source rows — the
    /// shape of a reader or export that stopped early. `rows` is the
    /// count lost.
    TruncatedRows {
        /// The table's position in the comparison sequence.
        table: usize,
        /// How many trailing source rows the projection lacks.
        rows: usize,
    },
    /// The projection lacks a source row that is not part of a lost
    /// trailing run — a hole before the tail.
    OmittedRow {
        /// The table's position in the comparison sequence.
        table: usize,
        /// The missing row's position in the source observation.
        source_row: usize,
    },
    /// The projection holds a row the source never observed.
    InventedRow {
        /// The table's position in the comparison sequence.
        table: usize,
        /// The unexplained row's position in the projection observation.
        projection_row: usize,
    },
    /// A row present under the same key on both sides has a field whose
    /// presence bit or digest differs: altered bytes, a truncated export
    /// of a large field, a NULL filled in, or a value NULL-ed.
    CorruptedField {
        /// The table's position in the comparison sequence.
        table: usize,
        /// The row's position in the source observation.
        source_row: usize,
        /// The field's position in the fixed column order.
        field: usize,
    },
}

impl fmt::Display for Divergence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TableSequence => f.write_str("parity-table-sequence"),
            Self::Reordered { table, row } => write!(f, "parity-reordered table={table} row={row}"),
            Self::TruncatedRows { table, rows } => {
                write!(f, "parity-truncated-rows table={table} rows={rows}")
            }
            Self::OmittedRow { table, source_row } => write!(
                f,
                "parity-omitted-row table={table} source_row={source_row}"
            ),
            Self::InventedRow {
                table,
                projection_row,
            } => write!(
                f,
                "parity-invented-row table={table} projection_row={projection_row}"
            ),
            Self::CorruptedField {
                table,
                source_row,
                field,
            } => write!(
                f,
                "parity-corrupted-field table={table} source_row={source_row} field={field}"
            ),
        }
    }
}

/// The oracle's verdict over two whole observations.
///
/// `Equal` is the parity decision holding: identical ordered keys, row
/// counts, presence bits, and per-field digests, table by table. A
/// divergence list is the named faults — bounded by the observation
/// sizes, and content-free member by member. Rendering a verdict is the
/// caller's reporting decision; this type carries it, it does not log it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The observations agree: the parity tuple holds.
    Equal,
    /// Every named divergence, in comparison order.
    Diverges(Vec<Divergence>),
}

impl Verdict {
    /// Whether the parity tuple holds.
    #[must_use]
    pub fn is_equal(&self) -> bool {
        matches!(self, Self::Equal)
    }
}

/// Compare the source observation — the independent direct reads — with
/// the projection observation, table by table in their shared sequence,
/// naming every divergence class.
///
/// Both sides must be built over the same allowlisted column sequence; a
/// field ordinal a [`Divergence::CorruptedField`] names means the same
/// column on both sides by that contract. The comparison never reads a
/// store, hashes a file, or touches a value beyond the digests the
/// observations already carry.
#[must_use]
pub fn compare(source: &DatabaseObservation, projection: &DatabaseObservation) -> Verdict {
    let mut divergences = Vec::new();
    if source.tables.len() != projection.tables.len() {
        divergences.push(Divergence::TableSequence);
    }
    let shared = source.tables.len().min(projection.tables.len());
    for index in 0..shared {
        compare_table(
            index,
            &source.tables[index],
            &projection.tables[index],
            &mut divergences,
        );
    }
    if divergences.is_empty() {
        Verdict::Equal
    } else {
        Verdict::Diverges(divergences)
    }
}

/// Compare one table: verify both sides' canonical order, then merge the
/// ordered key sequences, comparing the fields of matched rows.
fn compare_table(
    index: usize,
    source: &TableObservation,
    projection: &TableObservation,
    divergences: &mut Vec<Divergence>,
) {
    // Order first: the merge assumes canonical order, and a reordering
    // fault is named as itself rather than the spurious omissions and
    // inventions an unsorted walk would manufacture.
    if let Some(at) = first_out_of_order(source.rows()) {
        divergences.push(Divergence::Reordered {
            table: index,
            row: at,
        });
        return;
    }
    if let Some(at) = first_out_of_order(projection.rows()) {
        divergences.push(Divergence::Reordered {
            table: index,
            row: at,
        });
        return;
    }

    let mut source_row = 0;
    let mut projection_row = 0;
    let mut missing: Vec<usize> = Vec::new();
    let mut unexplained: Vec<usize> = Vec::new();
    while source_row < source.rows.len() && projection_row < projection.rows.len() {
        match source.rows[source_row]
            .key()
            .cmp(projection.rows[projection_row].key())
        {
            Ordering::Equal => {
                compare_fields(
                    index,
                    source_row,
                    &source.rows[source_row],
                    &projection.rows[projection_row],
                    divergences,
                );
                source_row += 1;
                projection_row += 1;
            }
            Ordering::Less => {
                missing.push(source_row);
                source_row += 1;
            }
            Ordering::Greater => {
                unexplained.push(projection_row);
                projection_row += 1;
            }
        }
    }
    missing.extend(source_row..source.rows.len());
    unexplained.extend(projection_row..projection.rows.len());

    if unexplained.is_empty() && is_trailing_run(&missing, source.rows.len()) {
        // The projection is a strict prefix: one lost trailing run.
        divergences.push(Divergence::TruncatedRows {
            table: index,
            rows: missing.len(),
        });
        return;
    }
    for row in missing {
        divergences.push(Divergence::OmittedRow {
            table: index,
            source_row: row,
        });
    }
    for row in unexplained {
        divergences.push(Divergence::InventedRow {
            table: index,
            projection_row: row,
        });
    }
}

/// Compare one matched row's fields: every presence-bit or digest
/// mismatch is named at its field ordinal, and a width mismatch — the
/// observations were not built over the same column sequence — is named
/// at the first position the tuples stop sharing.
fn compare_fields(
    index: usize,
    source_row: usize,
    source: &RowObservation,
    projection: &RowObservation,
    divergences: &mut Vec<Divergence>,
) {
    let shared = source.fields.len().min(projection.fields.len());
    for field in 0..shared {
        if source.fields[field] != projection.fields[field] {
            divergences.push(Divergence::CorruptedField {
                table: index,
                source_row,
                field,
            });
        }
    }
    if source.fields.len() != projection.fields.len() {
        divergences.push(Divergence::CorruptedField {
            table: index,
            source_row,
            field: shared,
        });
    }
}

/// The first position whose key is strictly less than its predecessor's,
/// or `None` when the rows are in canonical key order.
fn first_out_of_order(rows: &[RowObservation]) -> Option<usize> {
    (1..rows.len()).find(|&at| rows[at].key() < rows[at - 1].key())
}

/// Whether `missing` — ascending source row positions — is exactly the
/// last `missing.len()` rows of a `total`-row observation.
fn is_trailing_run(missing: &[usize], total: usize) -> bool {
    !missing.is_empty() && missing[0] + missing.len() == total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One observed row from key and field values.
    fn row(key: Vec<ObservedValue>, fields: Vec<ObservedValue>) -> RowObservation {
        RowObservation::observe(key, fields)
    }

    /// One single-column table from text keys, canonical order assumed.
    fn text_table(keys: &[&str]) -> TableObservation {
        TableObservation::new(
            keys.iter()
                .map(|key| {
                    row(
                        vec![ObservedValue::Text(key.as_bytes().to_vec())],
                        vec![ObservedValue::Text(key.as_bytes().to_vec())],
                    )
                })
                .collect(),
        )
    }

    fn observation(tables: Vec<TableObservation>) -> DatabaseObservation {
        DatabaseObservation::new(tables)
    }

    #[test]
    fn the_canonical_order_is_total_and_storage_classed() {
        use ObservedValue::{Blob, Integer, Null, Real, Text};

        let null = Null;
        let integer = Integer(1);
        let real = Real(1.0);
        let text = Text(b"1".to_vec());
        let blob = Blob(b"1".to_vec());

        // NULL before every value.
        assert!(null < integer);
        assert!(null < text);
        // Integers and reals compare numerically across classes; an
        // equal numeric value orders the integer first.
        assert!(integer < Real(1.5));
        assert!(Real(1.5) < Integer(2));
        assert!(Integer(1) < real);
        // An integer beyond f64's exact mantissa still orders exactly.
        // The reals bracket `i64::MAX` with exactly representable doubles:
        // the largest below it (2^63 − 1024, the last f64 step under
        // 2^63) and one above it — a nearer literal would round up to 2^63
        // itself and cross the boundary.
        let wide = Integer(9_223_372_036_854_775_807);
        assert!(Real(9_223_372_036_854_774_784.0) < wide);
        assert!(wide < Real(9.3e18));
        // Numerics before text before blob, byte-equal or not.
        assert!(real < text);
        assert!(text < blob);
        // Text compares bytewise, blobs bytewise.
        assert!(Text(b"a".to_vec()) < Text(b"b".to_vec()));
        assert!(Blob(b"a".to_vec()) < Blob(b"b".to_vec()));
        // The order is total: every distinct pair decides.
        let mut values = [null.clone(), integer, Real(-0.5), real, text, blob];
        values.sort();
        assert_eq!(values[0], Null);
        assert_eq!(values[1], Real(-0.5));
        assert_eq!(values[2], Integer(1));
        assert_eq!(values[3], Real(1.0));
        assert_eq!(values[4], Text(b"1".to_vec()));
        assert_eq!(values[5], Blob(b"1".to_vec()));
    }

    #[test]
    fn digests_bind_class_and_length() {
        // Byte-equal values of different classes digest differently.
        let bytes = b"1".to_vec();
        assert_ne!(
            FieldDigest::of(StorageClass::Text, &bytes),
            FieldDigest::of(StorageClass::Blob, &bytes)
        );
        // A strict prefix never digests like the whole value.
        let whole = b"0123456789".to_vec();
        let prefix = whole[..5].to_vec();
        assert_ne!(
            FieldDigest::of(StorageClass::Text, &whole),
            FieldDigest::of(StorageClass::Text, &prefix)
        );
        // The empty prefix of an empty value is still class-distinct.
        assert_ne!(
            FieldDigest::of(StorageClass::Text, &[]),
            FieldDigest::of(StorageClass::Integer, &[])
        );
        // Like inputs digest alike.
        assert_eq!(
            FieldDigest::of(StorageClass::Text, &whole),
            FieldDigest::of(StorageClass::Text, &whole)
        );
        // Observing a value carries the same binding.
        assert_ne!(
            ObservedValue::Text(bytes.clone()).observe(),
            ObservedValue::Blob(bytes).observe()
        );
        assert_eq!(
            ObservedValue::Integer(7).observe(),
            ObservedValue::Integer(7).observe()
        );
        // The presence bit rides the observation.
        assert_eq!(ObservedValue::Null.observe(), FieldObservation::Absent);
        assert_ne!(
            ObservedValue::Null.observe(),
            ObservedValue::Text(vec![]).observe()
        );
    }

    #[test]
    fn identical_observations_are_equal() {
        let source = observation(vec![
            text_table(&["a", "b", "c"]),
            TableObservation::new(vec![]),
        ]);
        let projection = observation(vec![
            text_table(&["a", "b", "c"]),
            TableObservation::new(vec![]),
        ]);
        assert_eq!(compare(&source, &projection), Verdict::Equal);
        assert!(compare(&source, &projection).is_equal());
        // Empty observations on both sides are parity over nothing.
        let empty = observation(vec![]);
        assert_eq!(compare(&empty, &empty), Verdict::Equal);
    }

    #[test]
    fn a_lost_trailing_run_is_truncation() {
        let source = observation(vec![text_table(&["a", "b", "c", "d"])]);
        let projection = observation(vec![text_table(&["a", "b"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![Divergence::TruncatedRows { table: 0, rows: 2 }])
        );
    }

    #[test]
    fn an_interior_lost_row_is_omission() {
        let source = observation(vec![text_table(&["a", "b", "c", "d"])]);
        let projection = observation(vec![text_table(&["a", "c", "d"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![Divergence::OmittedRow {
                table: 0,
                source_row: 1
            }])
        );
    }

    #[test]
    fn an_interior_and_tail_loss_together_names_each_row() {
        // Not one trailing run: every lost row is named, so the tail loss
        // does not disguise the interior hole.
        let source = observation(vec![text_table(&["a", "b", "c", "d"])]);
        let projection = observation(vec![text_table(&["a", "c"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![
                Divergence::OmittedRow {
                    table: 0,
                    source_row: 1
                },
                Divergence::OmittedRow {
                    table: 0,
                    source_row: 3
                },
            ])
        );
    }

    #[test]
    fn an_out_of_order_side_is_reordering_not_a_cascade() {
        let source = observation(vec![text_table(&["a", "b", "c"])]);
        // The projection holds every row but served them out of order.
        let projection = observation(vec![text_table(&["a", "c", "b"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![Divergence::Reordered { table: 0, row: 2 }])
        );
        // A source side out of canonical order is equally named.
        let source_swapped = observation(vec![text_table(&["c", "b", "a"])]);
        assert_eq!(
            compare(&source_swapped, &projection),
            Verdict::Diverges(vec![Divergence::Reordered { table: 0, row: 1 }])
        );
    }

    #[test]
    fn digest_drift_and_presence_flips_are_field_corruption() {
        let key = vec![ObservedValue::Text(b"k".to_vec())];
        let healthy = row(
            key.clone(),
            vec![
                ObservedValue::Integer(5),
                ObservedValue::Text(b"payload".to_vec()),
                ObservedValue::Null,
            ],
        );
        let source = observation(vec![TableObservation::new(vec![healthy.clone()])]);

        // Altered bytes, same presence: digest drift.
        let drifted = row(
            key.clone(),
            vec![
                ObservedValue::Integer(5),
                ObservedValue::Text(b"payloae".to_vec()),
                ObservedValue::Null,
            ],
        );
        assert_eq!(
            compare(
                &source,
                &observation(vec![TableObservation::new(vec![drifted])])
            ),
            Verdict::Diverges(vec![Divergence::CorruptedField {
                table: 0,
                source_row: 0,
                field: 1
            }])
        );

        // A value NULL-ed: the presence bit flips at its ordinal.
        let nulled = row(
            key.clone(),
            vec![
                ObservedValue::Integer(5),
                ObservedValue::Null,
                ObservedValue::Null,
            ],
        );
        assert_eq!(
            compare(
                &source,
                &observation(vec![TableObservation::new(vec![nulled])])
            ),
            Verdict::Diverges(vec![Divergence::CorruptedField {
                table: 0,
                source_row: 0,
                field: 1
            }])
        );

        // A NULL filled in: the flip in the other direction.
        let filled = row(
            key,
            vec![
                ObservedValue::Integer(5),
                ObservedValue::Text(b"payload".to_vec()),
                ObservedValue::Integer(1),
            ],
        );
        assert_eq!(
            compare(
                &source,
                &observation(vec![TableObservation::new(vec![filled])])
            ),
            Verdict::Diverges(vec![Divergence::CorruptedField {
                table: 0,
                source_row: 0,
                field: 2
            }])
        );
    }

    #[test]
    fn a_width_mismatch_names_the_first_unshared_field() {
        let key = vec![ObservedValue::Text(b"k".to_vec())];
        let source = observation(vec![TableObservation::new(vec![row(
            key.clone(),
            vec![ObservedValue::Integer(1), ObservedValue::Integer(2)],
        )])]);
        let projection = observation(vec![TableObservation::new(vec![row(
            key,
            vec![ObservedValue::Integer(1)],
        )])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![Divergence::CorruptedField {
                table: 0,
                source_row: 0,
                field: 1
            }])
        );
    }

    #[test]
    fn unexplained_projection_rows_are_invented() {
        let source = observation(vec![text_table(&["a", "c"])]);
        // A row the source never observed, plus a longer tail of them.
        let projection = observation(vec![text_table(&["a", "b", "c", "z"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![
                Divergence::InventedRow {
                    table: 0,
                    projection_row: 1
                },
                Divergence::InventedRow {
                    table: 0,
                    projection_row: 3
                },
            ])
        );
    }

    #[test]
    fn a_key_drift_appears_as_omission_plus_invention() {
        // The same row under a drifted key: the oracle reports the two
        // facts it can prove — the observed key is gone, an unobserved
        // key is present — rather than pairing them speculatively.
        let source = observation(vec![TableObservation::new(vec![row(
            vec![ObservedValue::Text(b"k".to_vec())],
            vec![ObservedValue::Integer(9)],
        )])]);
        let projection = observation(vec![TableObservation::new(vec![row(
            vec![ObservedValue::Text(b"j".to_vec())],
            vec![ObservedValue::Integer(9)],
        )])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![
                Divergence::OmittedRow {
                    table: 0,
                    source_row: 0
                },
                Divergence::InventedRow {
                    table: 0,
                    projection_row: 0
                },
            ])
        );
    }

    #[test]
    fn a_table_count_mismatch_is_named_once() {
        let source = observation(vec![text_table(&["a"])]);
        let projection = observation(vec![text_table(&["a"]), text_table(&["b"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![Divergence::TableSequence])
        );
    }

    #[test]
    fn divergent_tables_do_not_mask_one_another() {
        // A fault in an early table does not stop the comparison from
        // naming a different class in a later one.
        let source = observation(vec![text_table(&["a", "b"]), text_table(&["x", "y"])]);
        let projection = observation(vec![text_table(&["a"]), text_table(&["x", "y", "z"])]);
        assert_eq!(
            compare(&source, &projection),
            Verdict::Diverges(vec![
                Divergence::TruncatedRows { table: 0, rows: 1 },
                Divergence::InventedRow {
                    table: 1,
                    projection_row: 2
                },
            ])
        );
    }

    #[test]
    fn every_rendering_is_content_free() {
        // Hostile bytes planted in an observed field and key: no
        // rendering of the verdicts or the observation types carries them.
        let hostile = "SECRET-HOSTILE-VALUE";
        let source = observation(vec![TableObservation::new(vec![row(
            vec![ObservedValue::Text(b"k".to_vec())],
            vec![ObservedValue::Text(hostile.as_bytes().to_vec())],
        )])]);
        let projection = observation(vec![TableObservation::new(vec![row(
            vec![ObservedValue::Text(b"k".to_vec())],
            vec![ObservedValue::Text(b"other".to_vec())],
        )])]);
        let Verdict::Diverges(divergences) = compare(&source, &projection) else {
            panic!("the drifted field must diverge");
        };
        for divergence in &divergences {
            let rendered = format!("{divergence}");
            let debugged = format!("{divergence:?}");
            assert!(!rendered.contains(hostile), "Display leaks: {rendered}");
            assert!(!debugged.contains(hostile), "Debug leaks: {debugged}");
        }
        // The observation types render shape only.
        let observed = format!("{source:?}");
        assert!(!observed.contains(hostile), "Debug leaks: {observed}");
        let value = ObservedValue::Text(hostile.as_bytes().to_vec());
        assert_eq!(
            format!("{value:?}"),
            "ObservedValue { kind: \"text\", byte_len: 20 }"
        );
    }
}
