// SPDX-License-Identifier: Apache-2.0

//! The allowlisted projection (plan Phase 6B: "Project only allowlisted
//! session, message, part, input, and task fields" into RFC 8785 JSONL;
//! requirement CAP-004's "allowlisted, versioned session projection").
//!
//! [`Projection::project`] turns a [`Snapshot`] — the transactionally
//! consistent observation — into one canonical JSON record per allowlisted
//! row, in the snapshot's deterministic order. The record shape is fixed:
//!
//! ```json
//! {"fields":{...},"key":[...],"table":"message"}
//! ```
//!
//! - `table` names one of the five allowlisted tables. Anything else —
//!   the account, credential, provider-auth, and cache tables the real
//!   store legitimately holds among its other tables — has no projection
//!   path at all: the projection iterates the snapshot's tables, and the
//!   snapshot reads [`ALLOWED_TABLES`] and nothing else, so an excluded
//!   table is neither read nor emitted (the database half of the
//!   "projection-allowlist-negatives" gate row).
//! - `fields` carries **every** allowlisted column of that table, in the
//!   canonical member order, `null` where the cell is NULL — so a record
//!   is also the row's null/presence bits, and a field the store later
//!   gains cannot appear (the schema gate refuses the store first, and
//!   the record's member set is this crate's compiled-in constants).
//! - `key` is the ordered primary-key tuple the parity oracle re-fetches
//!   the row by: the `id` column for the four tables that have one, the
//!   full allowlisted column tuple for `todo`, which has none — the same
//!   columns the snapshot's deterministic order is built on, so key order
//!   and row order are one property.
//!
//! # Faithful or failed
//!
//! A cell the canonical domain cannot represent faithfully — a `BLOB`
//! stored in an allowlisted column, text that is not valid UTF-8, a
//! non-finite float — fails the projection with
//! [`ProjectionError::Unrepresentable`] and emits nothing: no partial
//! export exists to mistake for complete. The store's own classes are
//! preserved through the projection ([`FieldValue`] keeps the integer /
//! real / text distinction), which is what makes the per-field digests
//! the parity oracle computes over projected values comparable with
//! digests over direct database reads.
//!
//! # Content-freedom and bounds
//!
//! The error type is a closed set of unit variants: no field bytes, table
//! name, or column name can reach an error body or a log. Projection is
//! pure work over the snapshot already in memory — no store access, one
//! record per row, no recursion.

use std::fmt;

use archivist_adapter_sdk::ScanClassification;

use crate::canonical::{Json, Object};
use crate::snapshot::{Cell, Row, Snapshot};

/// The projection of one store: every allowlisted row of the snapshot,
/// in the snapshot's deterministic order, as canonical records.
#[derive(Clone, Debug, PartialEq)]
pub struct Projection {
    rows: Vec<ProjectedRow>,
}

impl Projection {
    /// Project the snapshot: one canonical record per allowlisted row.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::Unrepresentable`] when a cell has no faithful
    /// canonical form (a blob in an allowlisted column, text that is not
    /// valid UTF-8, a non-finite float). The projection is then not
    /// returned at all — there is no partial export.
    pub fn project(snapshot: &Snapshot) -> Result<Projection, ProjectionError> {
        let mut rows = Vec::new();
        for table in snapshot.tables() {
            for row in table.rows() {
                rows.push(ProjectedRow::project(table.name(), table.columns(), row)?);
            }
        }
        Ok(Projection { rows })
    }

    /// The projected rows, in projection order: allowlist table order,
    /// each table's snapshot order.
    #[must_use]
    pub fn rows(&self) -> &[ProjectedRow] {
        &self.rows
    }

    /// The canonical JSONL byte stream: one newline-terminated record per
    /// row, in projection order — the artifact body CAP-004's projection
    /// emits.
    #[must_use]
    pub fn jsonl(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for row in &self.rows {
            row.record().write_canonical(&mut out);
            out.push(b'\n');
        }
        out
    }
}

/// One projected row: the table, its ordered key tuple, and every
/// allowlisted field.
#[derive(Clone, Debug, PartialEq)]
pub struct ProjectedRow {
    table: &'static str,
    key: Vec<Json>,
    fields: Vec<(&'static str, FieldValue)>,
}

impl ProjectedRow {
    /// Project one snapshot row of `table`.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::Unrepresentable`] when any cell of the row —
    /// key or field — has no faithful canonical form.
    pub fn project(
        table: &'static str,
        columns: &'static [&'static str],
        row: &Row,
    ) -> Result<ProjectedRow, ProjectionError> {
        let cells = row.cells();
        debug_assert_eq!(
            cells.len(),
            columns.len(),
            "a snapshot row carries one cell per allowlisted column"
        );
        let fields: Vec<(&'static str, FieldValue)> = columns
            .iter()
            .zip(cells)
            .map(|(name, cell)| Ok((*name, FieldValue::observe(cell)?)))
            .collect::<Result<_, _>>()?;
        let key: Vec<Json> = key_column_positions(columns)
            .map(|index| fields[index].1.to_json())
            .collect();
        Ok(ProjectedRow { table, key, fields })
    }

    /// The allowlisted table this row came from.
    #[must_use]
    pub fn table(&self) -> &'static str {
        self.table
    }

    /// The ordered primary-key tuple: the `id` value for the tables that
    /// have one, the full allowlisted column tuple for `todo`. The parity
    /// oracle re-fetches the row from the store by these values.
    #[must_use]
    pub fn key(&self) -> &[Json] {
        &self.key
    }

    /// Every allowlisted field, in allowlist order — `null` where the
    /// cell is NULL, so the record carries the presence bits too.
    #[must_use]
    pub fn fields(&self) -> &[(&'static str, FieldValue)] {
        &self.fields
    }

    /// The row's canonical record: `{"fields":{...},"key":[...],"table":"..."}`.
    #[must_use]
    pub fn record(&self) -> Json {
        let mut object = Object::new();
        let mut fields = Object::new();
        for (name, value) in &self.fields {
            fields.insert(name, value.to_json());
        }
        object.insert("fields", Json::Object(fields));
        object.insert("key", Json::Array(self.key.clone()));
        object.insert("table", Json::Text(self.table.to_owned()));
        Json::Object(object)
    }
}

/// One allowlisted field's projected value: the store cell's storage
/// class preserved through the canonical domain.
///
/// The class is the projection's digest contract: [`FieldValue::raw_bytes`]
/// follows the same recipe as the snapshot cell's raw bytes, so a digest
/// over a projected field and a digest over a direct database read of the
/// same stored value are the same digest — and the classes a naive
/// rendering would merge (integer 1, real 1.0, text "1") stay distinct.
#[derive(Clone, Debug, PartialEq)]
pub enum FieldValue {
    /// A NULL cell.
    Null,
    /// A signed 64-bit integer cell.
    Integer(i64),
    /// A finite 64-bit float cell.
    Real(f64),
    /// A text cell, valid UTF-8.
    Text(String),
}

impl FieldValue {
    /// Observe a snapshot cell into the projectable domain.
    ///
    /// # Errors
    ///
    /// [`ProjectionError::Unrepresentable`] for a blob (no canonical JSON
    /// form keeps bytes distinct from text), text that is not valid
    /// UTF-8, and a non-finite float (no RFC 8785 form exists).
    pub fn observe(cell: &Cell) -> Result<FieldValue, ProjectionError> {
        match cell {
            Cell::Null => Ok(Self::Null),
            Cell::Integer(value) => Ok(Self::Integer(*value)),
            Cell::Real(value) => {
                if value.is_finite() {
                    Ok(Self::Real(*value))
                } else {
                    Err(ProjectionError::Unrepresentable)
                }
            }
            Cell::Text(bytes) => match std::str::from_utf8(bytes) {
                Ok(text) => Ok(Self::Text(text.to_owned())),
                Err(_) => Err(ProjectionError::Unrepresentable),
            },
            Cell::Blob(_) => Err(ProjectionError::Unrepresentable),
        }
    }

    /// The digest input: integers as eight bytes big-endian, floats as
    /// IEEE-754 binary64 big-endian, text as its UTF-8 bytes, NULL as no
    /// bytes — the snapshot cell's own recipe, so the parity oracle can
    /// compare a projected digest with a digest over a direct read.
    #[must_use]
    pub fn raw_bytes(&self) -> Vec<u8> {
        match self {
            Self::Null => Vec::new(),
            Self::Integer(value) => value.to_be_bytes().to_vec(),
            Self::Real(value) => value.to_be_bytes().to_vec(),
            Self::Text(text) => text.as_bytes().to_vec(),
        }
    }

    /// The field's canonical JSON form.
    #[must_use]
    pub fn to_json(&self) -> Json {
        match self {
            Self::Null => Json::Null,
            Self::Integer(value) => Json::Integer(*value),
            Self::Real(value) => Json::Real(*value),
            Self::Text(text) => Json::Text(text.clone()),
        }
    }
}

/// Why a projection failed. A closed set of unit variants: the type
/// cannot carry a table name, a column name, or any field bytes, so no
/// formatting — [`fmt::Display`] included — can leak source content into
/// status, an error body, or a log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProjectionError {
    /// An allowlisted cell has no faithful canonical form: a blob in an
    /// allowlisted column, text that is not valid UTF-8, or a non-finite
    /// float. Nothing was projected — there is no partial export.
    Unrepresentable,
}

impl ProjectionError {
    /// The closed classification this projection outcome reports.
    #[must_use]
    pub fn classification(self) -> ScanClassification {
        // The store was read but cannot be captured correctly this pass:
        // honestly a read failure, never a degraded projection.
        ScanClassification::ReadError
    }

    /// The content-free token naming this outcome: the whole message
    /// [`fmt::Display`] renders.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Unrepresentable => "opencode-projection-unrepresentable",
        }
    }
}

impl fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

impl std::error::Error for ProjectionError {}

/// The positions of the row's key columns: the `id` column when the
/// allowlist has one, every column otherwise (`todo`, which declares no
/// primary key — its full tuple is its identity, the same tuple the
/// snapshot's deterministic order sorts on).
fn key_column_positions(columns: &'static [&'static str]) -> impl Iterator<Item = usize> {
    let id = columns.iter().position(|name| *name == "id");
    let range: Vec<usize> = match id {
        Some(at) => vec![at],
        None => (0..columns.len()).collect(),
    };
    range.into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::ALLOWED_TABLES;

    /// The key rule: `id` leads the four tables that have one, and todo's
    /// key is its full tuple.
    #[test]
    fn the_key_rule_matches_the_allowlists() {
        for (table, columns) in ALLOWED_TABLES {
            let positions: Vec<usize> = key_column_positions(columns).collect();
            if *table == "todo" {
                assert_eq!(
                    positions.len(),
                    columns.len(),
                    "todo's key is its full tuple"
                );
            } else {
                assert_eq!(positions, [0], "{table} keys on its leading id column");
                assert_eq!(columns[0], "id");
            }
        }
    }
}
