// SPDX-License-Identifier: Apache-2.0

//! A deterministic minimal Parquet writer for the derived catalog's
//! columnar projections (plan Phase 10: versioned Parquet inventories).
//!
//! The writer emits a strictly bounded subset of the Parquet file format —
//! the subset the inventory family needs, chosen so every output byte is a
//! pure function of the table's schema and rows:
//!
//! - data page v1, plain-encoded values, `UNCOMPRESSED`;
//! - optional columns carry RLE-hybrid definition levels at `bit_width`
//!   1; required columns carry no levels at all;
//! - one data page per column per row group, and row groups of at most
//!   [`ROW_GROUP_ROWS`] rows;
//! - no statistics, no dictionary pages, no bloom filters, and no nested
//!   or repeated fields — the two physical types are [`Physical::Int64`]
//!   and [`Physical::ByteArray`] (UTF-8 text);
//! - a static `created_by` token and caller-supplied key/value metadata,
//!   so no wall-clock, producer path, or run identity can enter the bytes.
//!
//! Two byte-serializations of one table would be two artifacts, so the
//! determinism rule is the derived family's: identical schema and rows
//! encode to byte-identical files, which is what makes the inventory's
//! rebuild gate (same frozen prefix and pipeline version, byte-identical
//! partitions) hold. The version discipline is the derived family's too:
//! a changed encoding is a new inventory pipeline version writing a new
//! prefix, never a silent rewrite of an old partition. The subset is
//! deliberately small enough to verify end to end — this module's tests
//! carry a structural reader that walks the emitted bytes the way an
//! independent implementation would.
//!
//! Values are bounded: text cells are short provenance tokens (digests,
//! identifiers, closed enum tokens), integer cells are signed 64-bit
//! counts. [`Table::push`] validates every row's shape before any bytes
//! exist, so a malformed row is refused, not encoded.

use archivist_protocol::sha256;

/// The largest number of rows one row group carries. A row group is the
/// file's read-parallelism unit; the inventory's partitions sit far below
/// this in the expected shapes, and the cap keeps a page's 32-bit size
/// fields honest for the bounded cell widths this writer accepts.
pub const ROW_GROUP_ROWS: usize = 8192;

/// The Parquet file's opening and closing magic.
const MAGIC: &[u8; 4] = b"PAR1";

/// The static `created_by` token. It is part of the bytes a rebuild
/// reproduces, so it changes only with a new inventory pipeline version —
/// never opportunistically.
const CREATED_BY: &str = "agent-archivist parquet writer v1";

/// The thrift compact protocol's field types this writer emits.
///
/// Values are the protocol's own type identifiers: a field header carries
/// the type beside the field id.
mod thrift {
    /// Signed 32-bit integer (zigzag varint on the wire).
    pub const I32: u8 = 0x05;
    /// Signed 64-bit integer (zigzag varint on the wire).
    pub const I64: u8 = 0x06;
    /// Byte sequence, length-prefixed.
    pub const BINARY: u8 = 0x08;
    /// A list of one element type.
    pub const LIST: u8 = 0x09;
    /// A nested struct.
    pub const STRUCT: u8 = 0x0C;
    /// The struct terminator.
    pub const STOP: u8 = 0x00;
}

/// The Parquet physical types this writer emits, with the thrift enum
/// values the metadata names them by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Physical {
    /// `INT64` — signed 64-bit integers, plain-encoded little-endian.
    Int64,
    /// `BYTE_ARRAY` — length-prefixed byte strings this writer only ever
    /// fills with UTF-8 text.
    ByteArray,
}

impl Physical {
    /// The thrift `Type` enum value.
    fn id(self) -> i32 {
        match self {
            Self::Int64 => 2,
            Self::ByteArray => 6,
        }
    }
}

/// One column's schema entry: name, physical type, and whether the column
/// is required (every row carries a value) or optional (a row may omit
/// it — how the inventory states *omitted, never invented*).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    name: String,
    physical: Physical,
    required: bool,
    /// Whether a `BYTE_ARRAY` column carries UTF-8, which pins the
    /// schema's `converted_type`.
    utf8: bool,
}

impl Column {
    /// A required 64-bit integer column.
    #[must_use]
    pub fn required_int64(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            physical: Physical::Int64,
            required: true,
            utf8: false,
        }
    }

    /// An optional 64-bit integer column: absent where the source state
    /// carries no honest count.
    #[must_use]
    pub fn optional_int64(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            physical: Physical::Int64,
            required: false,
            utf8: false,
        }
    }

    /// A required UTF-8 text column.
    #[must_use]
    pub fn required_text(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            physical: Physical::ByteArray,
            required: true,
            utf8: true,
        }
    }

    /// An optional UTF-8 text column.
    #[must_use]
    pub fn optional_text(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            physical: Physical::ByteArray,
            required: false,
            utf8: true,
        }
    }

    /// The column name, as the schema and the chunk's `path_in_schema`
    /// carry it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether every row must carry this column — a required column's
    /// cells have no definition level, an optional column's do.
    #[must_use]
    pub const fn required(&self) -> bool {
        self.required
    }
}

/// One cell value, exactly matching its column's physical type, or the
/// deliberate absence an optional column carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cell {
    /// A signed 64-bit value in an `INT64` column.
    Int(i64),
    /// A UTF-8 string value in a `BYTE_ARRAY` column.
    Text(String),
    /// No value. Legal only in an optional column — a required column's
    /// absence is a schema fault, never an encodable state.
    Null,
}

/// The two shape faults [`Table::push`] refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableError {
    /// The row's width differs from the schema's.
    RowShape {
        /// The schema's column count.
        expected: usize,
        /// The row's cell count.
        got: usize,
    },
    /// A cell's kind does not match its column's physical type, or a
    /// null sits in a required column.
    CellType {
        /// The offended column's name.
        column: String,
        /// The offending cell.
        cell: Cell,
    },
}

/// A columnar table: the closed schema and the rows to encode, in the
/// order they occupy the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    columns: Vec<Column>,
    rows: Vec<Vec<Cell>>,
}

impl Table {
    /// A table over `columns`, with no rows yet.
    #[must_use]
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            rows: Vec::new(),
        }
    }

    /// The table's schema.
    #[must_use]
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// The row count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table carries no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Append one row, refusing any shape fault before bytes exist: the
    /// cell count must match the schema, an integer cell must sit in an
    /// `INT64` column, a text cell in a `BYTE_ARRAY` column, and a
    /// [`Cell::Null`] in an optional column only.
    ///
    /// # Errors
    /// [`TableError::RowShape`] when the row's width differs from the
    /// schema's, and [`TableError::CellType`] when a cell's kind does not
    /// match its column's declared physical type and nullability.
    pub fn push(&mut self, row: Vec<Cell>) -> Result<(), TableError> {
        if row.len() != self.columns.len() {
            return Err(TableError::RowShape {
                expected: self.columns.len(),
                got: row.len(),
            });
        }
        for (column, cell) in self.columns.iter().zip(row.iter()) {
            let matches = match (column.physical, cell) {
                (Physical::Int64, Cell::Int(_)) | (Physical::ByteArray, Cell::Text(_)) => true,
                (_, Cell::Null) => !column.required,
                _ => false,
            };
            if !matches {
                return Err(TableError::CellType {
                    column: column.name.clone(),
                    cell: cell.clone(),
                });
            }
        }
        self.rows.push(row);
        Ok(())
    }

    /// Encode the whole table to one deterministic Parquet file.
    ///
    /// The bytes are a pure function of the schema, the rows, the
    /// caller's metadata, and the static creator token — nothing else.
    /// Encoding one table twice gives identical bytes; encoding two
    /// identically built tables gives identical bytes.
    #[must_use]
    pub fn encode(&self, metadata: &[(&str, &str)]) -> Vec<u8> {
        let mut file = Vec::new();
        file.extend_from_slice(MAGIC);

        // Every row group's chunks are appended to the file body in
        // order; the footer records each chunk's absolute data-page
        // offset.
        let mut row_groups: Vec<(Vec<ChunkMeta>, i64, i64)> = Vec::new();
        for group in self.rows.chunks(ROW_GROUP_ROWS) {
            let mut chunks = Vec::with_capacity(self.columns.len());
            let mut total_byte_size = 0_i64;
            for (index, column) in self.columns.iter().enumerate() {
                let meta = write_column_chunk(&mut file, column, group, index);
                total_byte_size += meta.total_size;
                chunks.push(meta);
            }
            let num_rows = i64::try_from(group.len()).unwrap_or(i64::MAX);
            row_groups.push((chunks, total_byte_size, num_rows));
        }

        let num_rows = i64::try_from(self.rows.len()).unwrap_or(i64::MAX);
        let footer = encode_file_metadata(&self.columns, num_rows, &row_groups, metadata);
        file.extend_from_slice(&footer);
        let footer_len = u32::try_from(footer.len()).unwrap_or(u32::MAX);
        file.extend_from_slice(&footer_len.to_le_bytes());
        file.extend_from_slice(MAGIC);
        file
    }
}

/// One encoded column chunk's metadata, recorded while the bytes are
/// appended so the footer can name them.
struct ChunkMeta {
    physical: Physical,
    name: String,
    num_values: i64,
    total_size: i64,
    data_page_offset: i64,
}

/// Encode and append one column's single data page for one row group,
/// returning the chunk metadata the footer carries.
fn write_column_chunk(
    file: &mut Vec<u8>,
    column: &Column,
    rows: &[Vec<Cell>],
    index: usize,
) -> ChunkMeta {
    let num_values = i64::try_from(rows.len()).unwrap_or(i64::MAX);

    // Definition levels: one per row, present only for an optional
    // column, at bit_width 1. The V1 page's level stream is the
    // u32-prefixed RLE/bit-packed hybrid; the width itself is not
    // stored — the schema's maximum definition level derives it.
    let definition_bytes = if column.required {
        Vec::new()
    } else {
        let levels: Vec<u8> = rows
            .iter()
            .map(|row| match &row[index] {
                Cell::Null => 0_u8,
                _ => 1,
            })
            .collect();
        let mut blob = Vec::with_capacity(levels.len() / 8 + 8);
        rle_hybrid_b1_into(&mut blob, &levels);
        blob
    };

    // Plain-encoded values: required columns carry one value per row;
    // optional columns carry exactly the non-null ones, in row order.
    let mut values = Vec::new();
    for row in rows {
        match &row[index] {
            Cell::Int(value) => values.extend_from_slice(&value.to_le_bytes()),
            Cell::Text(text) => {
                let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
                values.extend_from_slice(&len.to_le_bytes());
                values.extend_from_slice(text.as_bytes());
            }
            Cell::Null => {}
        }
    }

    // Data page v1 body: the definition levels length-prefixed, then the
    // values. There are no repetition levels — the writer emits no
    // repeated field.
    let mut body = Vec::with_capacity(4 + definition_bytes.len() + values.len());
    if !column.required {
        let len = u32::try_from(definition_bytes.len()).unwrap_or(u32::MAX);
        body.extend_from_slice(&len.to_le_bytes());
        body.extend_from_slice(&definition_bytes);
    }
    body.extend_from_slice(&values);

    // The page header thrift structure: type (DATA_PAGE = 0), the body
    // size twice (uncompressed and — the codec being UNCOMPRESSED — the
    // same), then the data-page header: row count and the three
    // encodings (values plain, both level streams RLE).
    let body_len = i32::try_from(body.len()).unwrap_or(i32::MAX);
    let rows_len = i32::try_from(rows.len()).unwrap_or(i32::MAX);
    let mut header = Compact::default();
    header.i32_field(1, 0);
    header.i32_field(2, body_len);
    header.i32_field(3, body_len);
    header.struct_field(5);
    header.i32_field(1, rows_len);
    header.i32_field(2, 0);
    header.i32_field(3, 3);
    header.i32_field(4, 3);
    header.struct_end();
    header.stop();

    let data_page_offset = i64::try_from(file.len()).unwrap_or(i64::MAX);
    let header_bytes = header.into_bytes();
    let total_size = i64::try_from(header_bytes.len() + body.len()).unwrap_or(i64::MAX);
    file.extend_from_slice(&header_bytes);
    file.extend_from_slice(&body);

    ChunkMeta {
        physical: column.physical,
        name: column.name.clone(),
        num_values,
        total_size,
        data_page_offset,
    }
}

/// RLE-run the definition-level sequence at `bit_width` 1 into an
/// output buffer: every run of equal levels becomes one varint run
/// header — the run count doubled, the lit bit clear, marking an RLE
/// run — followed by the single repeated level byte. Only RLE runs are
/// emitted: a literal run of one-bit values never beats repeated bytes
/// for the row-shaped streams this writer produces, and emitting one
/// encoding keeps the bytes free of any heuristic.
fn rle_hybrid_b1_into(out: &mut Vec<u8>, levels: &[u8]) {
    let mut index = 0;
    while index < levels.len() {
        let value = levels[index];
        let mut run = 1_usize;
        while index + run < levels.len() && levels[index + run] == value {
            run += 1;
        }
        let header = u64::try_from(run).unwrap_or(u64::MAX) << 1;
        write_varint(out, header);
        out.push(value);
        index += run;
    }
}

/// Write one LEB128 varint.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

/// The thrift compact protocol writer, scoped to one top-level
/// structure.
///
/// Field ids are written in ascending order inside each struct — every
/// encoder below does so by construction — and `field_header` records
/// each write so the next field's delta encoding is correct. List
/// elements carry no field ids; a struct-typed list element opens with
/// [`Compact::struct_element_begin`], which resets the delta state.
#[derive(Default)]
struct Compact {
    raw: Vec<u8>,
    last_field: i16,
    stack: Vec<i16>,
}

impl Compact {
    /// Open a struct-typed *field* (named by its id).
    fn struct_field(&mut self, id: i16) {
        self.field_header(id, thrift::STRUCT);
        self.stack.push(self.last_field);
        self.last_field = 0;
    }

    /// Open a struct-typed *list element* (no field id).
    fn struct_element_begin(&mut self) {
        self.stack.push(self.last_field);
        self.last_field = 0;
    }

    /// Write a scalar field header (the value bytes follow).
    fn field_header(&mut self, id: i16, ty: u8) {
        let delta = id - self.last_field;
        if delta > 0 && delta <= 15 {
            // The checked range is the protocol's own 4-bit delta slot;
            // the bounds above are what make the narrowing lossless.
            #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
            let delta = delta as u8;
            self.raw.push((delta << 4) | ty);
        } else {
            self.raw.push(ty);
            self.zigzag_i64(i64::from(id));
        }
        self.last_field = id;
    }

    /// Write an i32 field's zigzag varint value.
    fn zigzag_i32(&mut self, value: i32) {
        let zigzag = (value.cast_unsigned() << 1) ^ (value >> 31).cast_unsigned();
        write_varint(&mut self.raw, u64::from(zigzag));
    }

    /// Write an i64 field's zigzag varint value.
    fn zigzag_i64(&mut self, value: i64) {
        let zigzag = (value.cast_unsigned() << 1) ^ (value >> 63).cast_unsigned();
        write_varint(&mut self.raw, zigzag);
    }

    /// Write an i32 field.
    fn i32_field(&mut self, id: i16, value: i32) {
        self.field_header(id, thrift::I32);
        self.zigzag_i32(value);
    }

    /// Write an i64 field.
    fn i64_field(&mut self, id: i16, value: i64) {
        self.field_header(id, thrift::I64);
        self.zigzag_i64(value);
    }

    /// Write a binary field: header, length, bytes.
    fn binary_field(&mut self, id: i16, bytes: &[u8]) {
        self.field_header(id, thrift::BINARY);
        self.raw_binary(bytes);
    }

    /// Write a length-prefixed byte string with no field header — a
    /// list element.
    fn raw_binary(&mut self, bytes: &[u8]) {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        write_varint(&mut self.raw, len);
        self.raw.extend_from_slice(bytes);
    }

    /// Open a list field of `size` elements of one element type.
    fn list_field(&mut self, id: i16, size: usize, element_type: u8) {
        self.field_header(id, thrift::LIST);
        if size < 15 {
            // The checked range is the protocol's own 4-bit size slot.
            #[allow(clippy::cast_possible_truncation)]
            let size = size as u8;
            self.raw.push((size << 4) | element_type);
        } else {
            self.raw.push(0xF0 | element_type);
            let len = u64::try_from(size).unwrap_or(u64::MAX);
            write_varint(&mut self.raw, len);
        }
    }

    /// Write a raw zigzag varint — a list element's whole value.
    fn raw_i32_element(&mut self, value: i32) {
        self.zigzag_i32(value);
    }

    /// Close the innermost open struct.
    fn struct_end(&mut self) {
        self.raw.push(thrift::STOP);
        self.last_field = self.stack.pop().unwrap_or(0);
    }

    /// Terminate the top-level structure.
    fn stop(&mut self) {
        self.raw.push(thrift::STOP);
    }

    /// Take the encoded bytes.
    fn into_bytes(self) -> Vec<u8> {
        self.raw
    }
}

/// Encode the `FileMetaData` footer: schema, row groups, evidence
/// metadata, and the static creator token.
fn encode_file_metadata(
    columns: &[Column],
    num_rows: i64,
    row_groups: &[(Vec<ChunkMeta>, i64, i64)],
    metadata: &[(&str, &str)],
) -> Vec<u8> {
    let mut out = Compact::default();
    out.i32_field(1, 1); // version = 1 (data page v1)

    // Schema: the root element names the table and counts its children;
    // every leaf names its physical type, its repetition, and — for text
    // — the UTF-8 converted type.
    out.list_field(2, columns.len() + 1, thrift::STRUCT);
    out.struct_element_begin();
    out.binary_field(4, b"archivist_inventory");
    out.i32_field(5, i32::try_from(columns.len()).unwrap_or(i32::MAX));
    out.struct_end();
    for column in columns {
        out.struct_element_begin();
        out.i32_field(1, column.physical.id());
        out.i32_field(3, i32::from(!column.required));
        out.binary_field(4, column.name.as_bytes());
        if column.utf8 {
            out.i32_field(6, 0); // converted_type = UTF8
        }
        out.struct_end();
    }

    out.i64_field(3, num_rows);

    out.list_field(4, row_groups.len(), thrift::STRUCT);
    for (chunks, total_byte_size, group_rows) in row_groups {
        out.struct_element_begin();
        out.list_field(1, chunks.len(), thrift::STRUCT);
        for chunk in chunks {
            out.struct_element_begin();
            out.i64_field(2, chunk.data_page_offset); // file_offset
            out.struct_field(3); // meta_data
            out.i32_field(1, chunk.physical.id());
            out.list_field(2, 2, thrift::I32); // encodings: PLAIN, RLE
            out.raw_i32_element(0);
            out.raw_i32_element(3);
            out.list_field(3, 1, thrift::BINARY); // path_in_schema
            out.raw_binary(chunk.name.as_bytes());
            out.i32_field(4, 0); // codec = UNCOMPRESSED
            out.i64_field(5, chunk.num_values);
            out.i64_field(6, chunk.total_size); // total_uncompressed_size
            out.i64_field(7, chunk.total_size); // total_compressed_size
            out.i64_field(9, chunk.data_page_offset);
            out.struct_end();
            out.struct_end();
        }
        out.i64_field(2, *total_byte_size);
        out.i64_field(3, *group_rows);
        out.struct_end();
    }

    if !metadata.is_empty() {
        out.list_field(5, metadata.len(), thrift::STRUCT);
        for (key, value) in metadata {
            out.struct_element_begin();
            out.binary_field(1, key.as_bytes());
            out.binary_field(2, value.as_bytes());
            out.struct_end();
        }
    }
    out.binary_field(6, CREATED_BY.as_bytes());
    out.stop();
    out.into_bytes()
}

/// The SHA-256 of encoded bytes, lowercase hex — the determinism evidence
/// a test or an auditor compares instead of whole files. The same
/// primitive the derived family's digests use.
#[must_use]
pub fn digest_of(bytes: &[u8]) -> String {
    sha256::encode_hex(bytes)
}

#[cfg(test)]
mod tests {
    //! The writer's own proof: determinism, shape faults refused, and a
    //! structural reader that walks the emitted bytes the way an
    //! independent implementation would — envelope framing, footer
    //! length, thrift footer, column chunks, definition levels, plain
    //! values — so a regression that still produces *some*
    //! Parquet-shaped file is still caught by its values failing to
    //! round-trip.

    use super::{Cell, Column, Physical, Table, TableError, digest_of};

    /// The three-column table the tests share: one required text, one
    /// optional text, one optional int — every encoding path in one file.
    fn table() -> Table {
        let mut table = Table::new(vec![
            Column::required_text("occurrence_id"),
            Column::optional_text("model"),
            Column::optional_int64("tokens"),
        ]);
        table
            .push(vec![
                Cell::Text("aa11".to_owned()),
                Cell::Text("claude-sonnet-4".to_owned()),
                Cell::Int(37),
            ])
            .expect("shape holds");
        table
            .push(vec![Cell::Text("bb22".to_owned()), Cell::Null, Cell::Null])
            .expect("shape holds");
        table
            .push(vec![
                Cell::Text("cc33".to_owned()),
                Cell::Text("claude-haiku-4".to_owned()),
                Cell::Int(0),
            ])
            .expect("shape holds");
        table
    }

    #[test]
    fn encoding_is_deterministic() {
        let first = table().encode(&[("k", "v")]);
        let second = table().encode(&[("k", "v")]);
        assert_eq!(first, second, "one table, two encodings, one file");
        assert_eq!(digest_of(&first), digest_of(&second));
    }

    #[test]
    fn envelope_framing_is_exact() {
        let bytes = table().encode(&[]);
        assert_eq!(&bytes[..4], b"PAR1");
        assert_eq!(&bytes[bytes.len() - 4..], b"PAR1");
        // The footer length field names exactly the bytes between the
        // body and the trailing length+magic: the footer must start
        // after the leading magic, with nothing unaccounted between the
        // two magic strips, the body, the footer, and the length field.
        let body_end = bytes.len() - 8;
        let footer_len = u32::from_le_bytes(bytes[body_end..body_end + 4].try_into().expect("4"));
        let footer_start = body_end - usize::try_from(footer_len).expect("fits");
        assert!(footer_start >= 4, "the footer sits after the body");
        assert!(
            FileReader::parse(&bytes).is_some(),
            "the framing the reader walks is the framing the writer wrote"
        );
    }

    #[test]
    fn empty_table_still_encodes() {
        let table = Table::new(vec![Column::required_int64("n")]);
        let bytes = table.encode(&[]);
        let read = FileReader::parse(&bytes).expect("the empty file parses");
        assert_eq!(read.num_rows, 0);
        assert!(read.row_groups.is_empty());
        assert_eq!(read.schema.len(), 1);
        assert_eq!(read.schema[0].0, "n");
        assert_eq!(read.schema[0].1, Physical::Int64);
        assert!(read.schema[0].2);
    }

    #[test]
    fn shape_faults_are_refused_before_bytes() {
        let mut table = Table::new(vec![Column::required_int64("n")]);
        assert_eq!(
            table.push(vec![]),
            Err(TableError::RowShape {
                expected: 1,
                got: 0
            })
        );
        assert_eq!(
            table.push(vec![Cell::Text("not an int".to_owned())]),
            Err(TableError::CellType {
                column: "n".to_owned(),
                cell: Cell::Text("not an int".to_owned()),
            })
        );
        // A null in a required column is refused; the same null in an
        // optional column encodes.
        assert!(table.push(vec![Cell::Null]).is_err());
        let mut optional = Table::new(vec![Column::optional_int64("maybe")]);
        assert!(optional.push(vec![Cell::Null]).is_ok());
    }

    #[test]
    fn row_groups_bound_the_page_sizes() {
        let mut table = Table::new(vec![Column::required_int64("n")]);
        let total = super::ROW_GROUP_ROWS * 2 + 7;
        for index in 0..total {
            let value = i64::try_from(index).expect("test index fits");
            table.push(vec![Cell::Int(value)]).expect("shape holds");
        }
        let bytes = table.encode(&[]);
        let read = FileReader::parse(&bytes).expect("parses");
        assert_eq!(read.row_groups.len(), 3, "8192 + 8192 + 7");
        assert_eq!(read.num_rows, i64::try_from(total).expect("fits"));
        let last = read.row_groups.last().expect("three groups");
        assert_eq!(last.columns[0].len(), 7);
        assert_eq!(
            last.columns[0][6],
            Cell::Int(i64::try_from(super::ROW_GROUP_ROWS * 2 + 6).expect("fits"))
        );
    }

    #[test]
    fn values_round_trip_through_the_structural_reader() {
        let bytes = table().encode(&[("pipeline_id", "inventory"), ("pipeline_version", "1")]);
        let read = FileReader::parse(&bytes).expect("the file parses");
        assert_eq!(read.num_rows, 3);
        assert_eq!(read.created_by, "agent-archivist parquet writer v1");
        assert_eq!(
            read.metadata,
            vec![
                ("pipeline_id".to_owned(), "inventory".to_owned()),
                ("pipeline_version".to_owned(), "1".to_owned()),
            ]
        );
        assert_eq!(read.schema.len(), 3);
        assert_eq!(read.schema[0].0, "occurrence_id");
        assert_eq!(read.schema[0].1, Physical::ByteArray);
        assert!(read.schema[0].2, "required");
        assert!(!read.schema[1].2, "optional");
        assert_eq!(read.schema[2].1, Physical::Int64);

        let group = &read.row_groups[0];
        assert_eq!(group.num_rows, 3);
        assert_eq!(
            group.columns,
            vec![
                vec![
                    Cell::Text("aa11".to_owned()),
                    Cell::Text("bb22".to_owned()),
                    Cell::Text("cc33".to_owned()),
                ],
                vec![
                    Cell::Text("claude-sonnet-4".to_owned()),
                    Cell::Null,
                    Cell::Text("claude-haiku-4".to_owned()),
                ],
                vec![Cell::Int(37), Cell::Null, Cell::Int(0)],
            ]
        );
    }

    #[test]
    fn runs_of_equal_levels_encode_and_decode() {
        // All-present: one RLE run. All-null: one run of zeros. Mixed:
        // three runs. Every shape must decode to exactly what went in.
        for pattern in [
            vec![Cell::Int(1), Cell::Int(2), Cell::Int(3)],
            vec![Cell::Null, Cell::Null, Cell::Null],
            vec![
                Cell::Null,
                Cell::Int(9),
                Cell::Null,
                Cell::Null,
                Cell::Int(8),
            ],
        ] {
            let mut table = Table::new(vec![Column::optional_int64("maybe")]);
            for cell in &pattern {
                table.push(vec![cell.clone()]).expect("shape holds");
            }
            let bytes = table.encode(&[]);
            let read = FileReader::parse(&bytes).expect("parses");
            assert_eq!(read.row_groups[0].columns[0], pattern);
        }
    }

    // ---- The structural reader ----

    /// One parsed file: schema (name, physical, required), the file row
    /// count, key/value metadata, creator token, and the decoded groups.
    struct FileReader {
        schema: Vec<(String, Physical, bool)>,
        num_rows: i64,
        metadata: Vec<(String, String)>,
        created_by: String,
        row_groups: Vec<GroupRead>,
    }

    /// One decoded row group: its row count and one decoded value vector
    /// per column, in schema order.
    struct GroupRead {
        num_rows: i64,
        columns: Vec<Vec<Cell>>,
    }

    /// The thrift compact protocol reader, the writer's exact inverse.
    struct CompactReader<'a> {
        bytes: &'a [u8],
        pos: usize,
        last_field: i16,
        stack: Vec<i16>,
    }

    impl<'a> CompactReader<'a> {
        fn new(bytes: &'a [u8]) -> Self {
            Self {
                bytes,
                pos: 0,
                last_field: 0,
                stack: Vec::new(),
            }
        }

        fn varint(&mut self) -> Option<u64> {
            let mut value = 0_u64;
            let mut shift = 0;
            loop {
                let byte = *self.bytes.get(self.pos)?;
                self.pos += 1;
                value |= u64::from(byte & 0x7F) << shift;
                if byte & 0x80 == 0 {
                    return Some(value);
                }
                shift += 7;
            }
        }

        fn zigzag(&mut self) -> Option<i64> {
            let raw = self.varint()?;
            let magnitude = i64::try_from(raw >> 1).ok()?;
            Some(magnitude ^ -i64::from(raw & 1 == 1))
        }

        fn binary(&mut self) -> Option<Vec<u8>> {
            let len = usize::try_from(self.varint()?).ok()?;
            let slice = self.bytes.get(self.pos..self.pos + len)?.to_vec();
            self.pos += len;
            Some(slice)
        }

        /// Read the next field header in the current struct. `None` at
        /// the struct's STOP, which also restores the enclosing field
        /// state.
        fn next_field(&mut self) -> Option<(i16, u8)> {
            let byte = *self.bytes.get(self.pos)?;
            if byte == 0 {
                self.pos += 1;
                self.last_field = self.stack.pop().unwrap_or(0);
                return None;
            }
            self.pos += 1;
            let ty = byte & 0x0F;
            let delta = (byte & 0xF0) >> 4;
            let id = if delta == 0 {
                i16::try_from(self.zigzag()?).ok()?
            } else {
                self.last_field + i16::from(delta)
            };
            self.last_field = id;
            Some((id, ty))
        }

        /// Descend into a struct-typed field just consumed.
        fn enter(&mut self) {
            self.stack.push(self.last_field);
            self.last_field = 0;
        }

        /// Read a list header: `(size, element type)`.
        fn list_header(&mut self) -> Option<(usize, u8)> {
            let byte = *self.bytes.get(self.pos)?;
            self.pos += 1;
            let element_type = byte & 0x0F;
            let size = usize::from((byte & 0xF0) >> 4);
            if size == 15 {
                Some((usize::try_from(self.varint()?).ok()?, element_type))
            } else {
                Some((size, element_type))
            }
        }
    }

    impl FileReader {
        /// Parse the envelope, walk the footer, and decode every row
        /// group's chunks back into cells.
        #[allow(clippy::too_many_lines)] // one field of the footer per arm
        fn parse(bytes: &[u8]) -> Option<Self> {
            if bytes.len() < 12
                || &bytes[..4] != super::MAGIC
                || &bytes[bytes.len() - 4..] != super::MAGIC
            {
                return None;
            }
            let body_end = bytes.len() - 8;
            let footer_len = usize::try_from(u32::from_le_bytes(
                bytes[body_end..body_end + 4].try_into().ok()?,
            ))
            .ok()?;
            let footer = bytes.get(body_end - footer_len..body_end)?;

            let mut reader = CompactReader::new(footer);
            let mut schema = Vec::new();
            let mut num_rows = 0_i64;
            let mut metadata = Vec::new();
            let mut created_by = String::new();
            let mut row_groups = Vec::new();

            while let Some((id, _ty)) = reader.next_field() {
                match id {
                    1 => {
                        let _version = reader.zigzag()?;
                    }
                    2 => {
                        let (count, _) = reader.list_header()?;
                        for _ in 0..count {
                            reader.enter();
                            let mut name = String::new();
                            let mut physical = Physical::ByteArray;
                            let mut required = false;
                            let mut children = 0_i64;
                            while let Some((field, _)) = reader.next_field() {
                                match field {
                                    1 => {
                                        physical = if reader.zigzag()? == 2 {
                                            Physical::Int64
                                        } else {
                                            Physical::ByteArray
                                        }
                                    }
                                    3 => required = reader.zigzag()? == 0,
                                    4 => {
                                        name = String::from_utf8(reader.binary()?).ok()?;
                                    }
                                    5 => children = reader.zigzag()?,
                                    _ => {
                                        let _ = reader.zigzag()?;
                                    }
                                }
                            }
                            // The root element counts children and names
                            // the table, not a column; only leaves join
                            // the schema.
                            if children == 0 {
                                schema.push((name, physical, required));
                            }
                        }
                    }
                    3 => num_rows = reader.zigzag()?,
                    4 => {
                        // The schema (field 2) always precedes the row
                        // groups (field 4) in this writer's footer, so
                        // the chunk decode has the required flags.
                        let (count, _) = reader.list_header()?;
                        for _ in 0..count {
                            reader.enter();
                            let mut columns = Vec::new();
                            let mut group_rows = 0_i64;
                            while let Some((field, _)) = reader.next_field() {
                                match field {
                                    1 => {
                                        let (chunks, _) = reader.list_header()?;
                                        for (index, _) in (0..chunks).enumerate() {
                                            let column = schema.get(index)?;
                                            columns.push(read_chunk(bytes, &mut reader, column)?);
                                        }
                                    }
                                    2 => {
                                        let _total = reader.zigzag()?;
                                    }
                                    3 => group_rows = reader.zigzag()?,
                                    _ => return None,
                                }
                            }
                            row_groups.push(GroupRead {
                                num_rows: group_rows,
                                columns,
                            });
                        }
                    }
                    5 => {
                        let (count, _) = reader.list_header()?;
                        for _ in 0..count {
                            reader.enter();
                            let mut key = String::new();
                            let mut value = String::new();
                            while let Some((field, _)) = reader.next_field() {
                                match field {
                                    1 => key = String::from_utf8(reader.binary()?).ok()?,
                                    2 => value = String::from_utf8(reader.binary()?).ok()?,
                                    _ => return None,
                                }
                            }
                            metadata.push((key, value));
                        }
                    }
                    6 => created_by = String::from_utf8(reader.binary()?).ok()?,
                    _ => return None,
                }
            }
            Some(Self {
                schema,
                num_rows,
                metadata,
                created_by,
                row_groups,
            })
        }
    }

    /// Read one `ColumnChunk` — its metadata struct, then the data page
    /// at the recorded offset — and decode the values back. The schema's
    /// entry for this column (its physical type and required flag)
    /// decides how the body decodes.
    fn read_chunk(
        bytes: &[u8],
        reader: &mut CompactReader,
        column: &(String, Physical, bool),
    ) -> Option<Vec<Cell>> {
        let (_, physical, required) = column;
        // The chunk is a struct-typed *list element*: descend into it,
        // exactly as the writer's `struct_element_begin` did.
        reader.enter();
        let mut data_page_offset = 0_i64;
        while let Some((id, _ty)) = reader.next_field() {
            match id {
                2 => data_page_offset = reader.zigzag()?,
                3 => {
                    reader.enter();
                    while let Some((field, _)) = reader.next_field() {
                        match field {
                            2 => {
                                // encodings: raw zigzag i32 elements.
                                let (count, _) = reader.list_header()?;
                                for _ in 0..count {
                                    let _ = reader.zigzag()?;
                                }
                            }
                            3 => {
                                // path_in_schema: list of binary; the
                                // single element names the column.
                                let (count, _) = reader.list_header()?;
                                for _ in 0..count {
                                    let _name = reader.binary()?;
                                }
                            }
                            // The physical type and every other scalar
                            // member are single zigzag values this
                            // reader can skip uniformly.
                            _ => {
                                let _ = reader.zigzag()?;
                            }
                        }
                    }
                }
                _ => return None,
            }
        }

        // Walk the page: PageHeader thrift, then the body.
        let mut page_header = CompactReader {
            bytes,
            pos: usize::try_from(data_page_offset).ok()?,
            last_field: 0,
            stack: Vec::new(),
        };
        let mut compressed = 0_i64;
        while let Some((field, ty)) = page_header.next_field() {
            match (field, ty) {
                (1 | 2, _) => {
                    let _ = page_header.zigzag()?;
                }
                (3, _) => compressed = page_header.zigzag()?,
                (5, super::thrift::STRUCT) => {
                    page_header.enter();
                    while page_header.next_field().is_some() {
                        let _ = page_header.zigzag()?;
                    }
                }
                _ => return None,
            }
        }
        let body =
            bytes.get(page_header.pos..page_header.pos + usize::try_from(compressed).ok()?)?;

        // Decode: a required column's body is values only; an optional
        // column's body leads with the u32-prefixed level blob, and the
        // levels say which rows carry values — the values begin where
        // the level blob ends.
        let mut cells = Vec::new();
        if *required {
            let mut cursor = body;
            while !cursor.is_empty() {
                cells.push(read_plain(*physical, &mut cursor)?);
            }
        } else {
            let (definitions, consumed) = split_levels(body)?;
            let mut cursor = &body[consumed..];
            for level in &definitions {
                if *level == 0 {
                    cells.push(Cell::Null);
                } else {
                    cells.push(read_plain(*physical, &mut cursor)?);
                }
            }
        }
        Some(cells)
    }

    /// Decode the definition-level blob that opens an optional column's
    /// page body: a u32 length prefix, then the hybrid stream — the
    /// width is not stored, the schema derives it — of run headers
    /// (bit 0 set: literal bit-packed run of `count` groups; clear: RLE
    /// run of `count` repeats). Returns the levels and the blob's total
    /// consumed byte count, so the caller finds the plain values
    /// exactly where the levels end.
    fn split_levels(body: &[u8]) -> Option<(Vec<u8>, usize)> {
        let len = usize::try_from(u32::from_le_bytes(body[..4].try_into().ok()?)).ok()?;
        let run_blob = body.get(4..4 + len)?;
        let mut levels = Vec::new();
        let mut pos = 0;
        while pos < run_blob.len() {
            let mut value = 0_u64;
            let mut shift = 0;
            loop {
                let byte = *run_blob.get(pos)?;
                pos += 1;
                value |= u64::from(byte & 0x7F) << shift;
                if byte & 0x80 == 0 {
                    break;
                }
                shift += 7;
            }
            let count = usize::try_from(value >> 1).ok()?;
            if value & 1 == 0 {
                let level = *run_blob.get(pos)?;
                pos += 1;
                levels.extend(std::iter::repeat_n(level, count));
            } else {
                // One byte per group at bit width 1, LSB-first; the
                // final group may pad past the real levels.
                for _ in 0..count {
                    let byte = *run_blob.get(pos)?;
                    pos += 1;
                    for bit in 0..8 {
                        levels.push((byte >> bit) & 1);
                    }
                }
            }
        }
        Some((levels, 4 + len))
    }

    /// Advance a byte cursor by `n`, returning the consumed slice.
    fn take<'a>(cursor: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
        if cursor.len() < n {
            return None;
        }
        let (head, tail) = cursor.split_at(n);
        *cursor = tail;
        Some(head)
    }

    /// Read one plain-encoded value.
    fn read_plain(physical: Physical, cursor: &mut &[u8]) -> Option<Cell> {
        match physical {
            Physical::Int64 => {
                let slice = take(cursor, 8)?;
                let array: [u8; 8] = slice.try_into().ok()?;
                Some(Cell::Int(i64::from_le_bytes(array)))
            }
            Physical::ByteArray => {
                let head = take(cursor, 4)?;
                let array: [u8; 4] = head.try_into().ok()?;
                let len = usize::try_from(u32::from_le_bytes(array)).ok()?;
                let text = String::from_utf8(take(cursor, len)?.to_vec()).ok()?;
                Some(Cell::Text(text))
            }
        }
    }
}
