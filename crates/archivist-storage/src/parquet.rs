// SPDX-License-Identifier: Apache-2.0

//! A deterministic minimal Parquet writer and reader for the derived
//! catalog's columnar projections (plan Phase 10: versioned Parquet
//! inventories).
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
//! deliberately small enough to verify end to end: [`Table::decode`] is
//! the writer's exact inverse, a fail-closed structural reader that walks
//! the emitted bytes the way an independent implementation would, so a
//! query surface can read a landed partition — and verify the file-level
//! identity in its footer metadata — before it trusts a row.
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

/// Why a byte sequence is not a readable file of this module's subset.
/// Every variant is a refusal, never a partial decode: a query surface
/// gets the whole table or an error naming the layer that refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TableDecodeError {
    /// The envelope is wrong: truncated, or the leading/trailing magic
    /// strips are missing or misplaced.
    Framing,
    /// The footer's thrift did not walk as this writer writes it — a
    /// field, type, or pinned token outside the emitted shape.
    Footer,
    /// A data page did not decode back into the declared cells.
    Page,
    /// The decoded rows failed the schema's own shape contract —
    /// [`Table::push`]'s rules.
    Shape(TableError),
}

/// One decoded file: the [`Table`] it carries plus the footer's
/// caller-supplied key/value metadata and creator token — the file-level
/// identity a query verifies before it trusts rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedFile {
    table: Table,
    metadata: Vec<(String, String)>,
    created_by: String,
}

impl DecodedFile {
    /// The decoded table, schema first and rows in file order.
    #[must_use]
    pub fn table(&self) -> &Table {
        &self.table
    }

    /// The footer's key/value metadata, in file order.
    #[must_use]
    pub fn metadata(&self) -> &[(String, String)] {
        &self.metadata
    }

    /// The creator token the footer names.
    #[must_use]
    pub fn created_by(&self) -> &str {
        &self.created_by
    }
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

    /// The table's rows, in file order, one cell vector per row in
    /// schema order.
    #[must_use]
    pub fn rows(&self) -> &[Vec<Cell>] {
        &self.rows
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

    /// Decode a file this module encoded back into its table and footer
    /// identity: the exact inverse of [`Table::encode`], fail-closed on
    /// every input outside the emitted shape. For any file this writer
    /// produces, `decode(bytes).table().encode(metadata)` reproduces
    /// `bytes`; for anything else the error names the layer that refused.
    ///
    /// # Errors
    /// [`TableDecodeError::Framing`] when the envelope is wrong,
    /// [`TableDecodeError::Footer`] when the footer's thrift, schema, or
    /// pinned tokens leave the emitted shape, [`TableDecodeError::Page`]
    /// when a data page does not decode back into its declared cells,
    /// and [`TableDecodeError::Shape`] when the decoded rows fail
    /// [`Table::push`]'s contract.
    pub fn decode(bytes: &[u8]) -> Result<DecodedFile, TableDecodeError> {
        decode_file(bytes)
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

// ---- The reader: the writer's exact inverse, fail-closed ----

/// Lift an `Option` from the thrift walk into a footer refusal.
fn footer<T>(value: Option<T>) -> Result<T, TableDecodeError> {
    value.ok_or(TableDecodeError::Footer)
}

/// Lift an `Option` from a page-body decode into a page refusal.
fn page<T>(value: Option<T>) -> Result<T, TableDecodeError> {
    value.ok_or(TableDecodeError::Page)
}

/// Decode the envelope, walk the footer strictly, decode every chunk, and
/// reassemble the rows through [`Table::push`]'s own contract.
fn decode_file(bytes: &[u8]) -> Result<DecodedFile, TableDecodeError> {
    if bytes.len() < 12 || &bytes[..4] != MAGIC || &bytes[bytes.len() - 4..] != MAGIC {
        return Err(TableDecodeError::Framing);
    }
    let body_end = bytes.len() - 8;
    let footer_len = usize::try_from(u32::from_le_bytes(
        bytes[body_end..body_end + 4]
            .try_into()
            .map_err(|_| TableDecodeError::Framing)?,
    ))
    .map_err(|_| TableDecodeError::Framing)?;
    let footer_bytes = bytes
        .get(
            body_end
                .checked_sub(footer_len)
                .ok_or(TableDecodeError::Framing)?..body_end,
        )
        .ok_or(TableDecodeError::Framing)?;

    let mut reader = CompactReader::new(footer_bytes);
    let mut schema: Vec<Column> = Vec::new();
    let mut num_rows: Option<i64> = None;
    let mut groups: Vec<GroupCells> = Vec::new();
    let mut metadata = Vec::new();
    let mut created_by = String::new();

    while let Some((id, _ty)) = reader.next_field() {
        match id {
            1 => {
                let version = footer(reader.zigzag())?;
                if version != 1 {
                    return Err(TableDecodeError::Footer);
                }
            }
            2 => decode_schema(&mut reader, &mut schema)?,
            3 => {
                let rows = footer(reader.zigzag())?;
                if rows < 0 {
                    return Err(TableDecodeError::Footer);
                }
                num_rows = Some(rows);
            }
            4 => decode_row_groups(&mut reader, bytes, &schema, &mut groups)?,
            5 => decode_metadata(&mut reader, &mut metadata)?,
            6 => {
                created_by = String::from_utf8(footer(reader.binary())?)
                    .map_err(|_| TableDecodeError::Footer)?;
            }
            _ => return Err(TableDecodeError::Footer),
        }
    }

    // The pinned creator token is part of the format: a file whose
    // creator token differs is not this module's output.
    if created_by != CREATED_BY {
        return Err(TableDecodeError::Footer);
    }
    let num_rows = num_rows.ok_or(TableDecodeError::Footer)?;
    let total = groups
        .iter()
        .map(|group| group.rows)
        .try_fold(0_i64, |sum, rows| {
            sum.checked_add(rows).ok_or(TableDecodeError::Footer)
        })?;
    if total != num_rows {
        return Err(TableDecodeError::Footer);
    }

    // Transpose the per-column cells back into rows and re-validate each
    // one through the same contract `push` enforces at write time.
    let mut table = Table::new(schema);
    for group in &groups {
        let local = usize::try_from(group.rows).map_err(|_| TableDecodeError::Footer)?;
        for row_index in 0..local {
            let row: Vec<Cell> = group
                .columns
                .iter()
                .map(|cells| cells[row_index].clone())
                .collect();
            table.push(row).map_err(TableDecodeError::Shape)?;
        }
    }
    Ok(DecodedFile {
        table,
        metadata,
        created_by,
    })
}

/// One decoded row group: the rows it declares and each column's cells.
struct GroupCells {
    rows: i64,
    /// One cell vector per schema column, in schema order.
    columns: Vec<Vec<Cell>>,
}

/// Walk the schema list: one root element naming the table and counting
/// its children, then one leaf element per column.
fn decode_schema(
    reader: &mut CompactReader<'_>,
    schema: &mut Vec<Column>,
) -> Result<(), TableDecodeError> {
    let (count, _) = footer(reader.list_header())?;
    for index in 0..count {
        reader.enter().ok_or(TableDecodeError::Footer)?;
        let mut name = String::new();
        let mut physical = Physical::ByteArray;
        let mut required = false;
        let mut utf8 = false;
        let mut children: i64 = 0;
        while let Some((field, _)) = reader.next_field() {
            match field {
                1 => {
                    let id = footer(reader.zigzag())?;
                    physical = match id {
                        2 => Physical::Int64,
                        6 => Physical::ByteArray,
                        _ => return Err(TableDecodeError::Footer),
                    };
                }
                3 => {
                    required = match footer(reader.zigzag())? {
                        0 => true,
                        1 => false,
                        _ => return Err(TableDecodeError::Footer),
                    };
                }
                4 => {
                    name = String::from_utf8(footer(reader.binary())?)
                        .map_err(|_| TableDecodeError::Footer)?;
                }
                5 => children = footer(reader.zigzag())?,
                6 => {
                    // converted_type: this writer emits only UTF8 (0).
                    if footer(reader.zigzag())? != 0 {
                        return Err(TableDecodeError::Footer);
                    }
                    utf8 = true;
                }
                _ => return Err(TableDecodeError::Footer),
            }
        }
        if index == 0 {
            // The root names the table and counts its children; it is
            // not a column.
            if children < 0 || name != "archivist_inventory" {
                return Err(TableDecodeError::Footer);
            }
        } else {
            if children != 0 {
                return Err(TableDecodeError::Footer);
            }
            if utf8 && physical != Physical::ByteArray {
                return Err(TableDecodeError::Footer);
            }
            schema.push(Column {
                name,
                physical,
                required,
                utf8,
            });
        }
    }
    Ok(())
}

/// Walk one row group's chunk list and decode each chunk's data page
/// back into per-column cells.
fn decode_row_groups(
    reader: &mut CompactReader<'_>,
    bytes: &[u8],
    schema: &[Column],
    groups: &mut Vec<GroupCells>,
) -> Result<(), TableDecodeError> {
    let (count, _) = footer(reader.list_header())?;
    for _ in 0..count {
        reader.enter().ok_or(TableDecodeError::Footer)?;
        let mut columns = Vec::with_capacity(schema.len());
        let mut rows: i64 = 0;
        while let Some((field, _)) = reader.next_field() {
            match field {
                1 => {
                    let (chunks, _) = footer(reader.list_header())?;
                    if chunks != schema.len() {
                        return Err(TableDecodeError::Footer);
                    }
                    for column in schema {
                        columns.push(read_chunk(bytes, reader, column)?);
                    }
                }
                2 => {
                    let total = footer(reader.zigzag())?;
                    if total < 0 {
                        return Err(TableDecodeError::Footer);
                    }
                }
                3 => {
                    rows = footer(reader.zigzag())?;
                    if rows < 0 {
                        return Err(TableDecodeError::Footer);
                    }
                }
                _ => return Err(TableDecodeError::Footer),
            }
        }
        if i64::try_from(columns.first().map_or(0, Vec::len)).unwrap_or(i64::MAX) != rows {
            return Err(TableDecodeError::Footer);
        }
        groups.push(GroupCells { rows, columns });
    }
    Ok(())
}

/// Walk the key/value metadata list.
fn decode_metadata(
    reader: &mut CompactReader<'_>,
    metadata: &mut Vec<(String, String)>,
) -> Result<(), TableDecodeError> {
    let (count, _) = footer(reader.list_header())?;
    for _ in 0..count {
        reader.enter().ok_or(TableDecodeError::Footer)?;
        let mut key: Option<String> = None;
        let mut value: Option<String> = None;
        while let Some((field, _)) = reader.next_field() {
            let text = |reader: &mut CompactReader<'_>| {
                String::from_utf8(reader.binary().ok_or(TableDecodeError::Footer)?)
                    .map_err(|_| TableDecodeError::Footer)
            };
            match field {
                1 => key = Some(text(reader)?),
                2 => value = Some(text(reader)?),
                _ => return Err(TableDecodeError::Footer),
            }
        }
        metadata.push((
            key.ok_or(TableDecodeError::Footer)?,
            value.ok_or(TableDecodeError::Footer)?,
        ));
    }
    Ok(())
}

/// Read one `ColumnChunk` — its metadata struct, then the data page at
/// the recorded offset — and decode the values back, refusing any field
/// or encoding this writer does not emit.
fn read_chunk(
    bytes: &[u8],
    reader: &mut CompactReader<'_>,
    column: &Column,
) -> Result<Vec<Cell>, TableDecodeError> {
    // The chunk is a struct-typed *list element*: descend into it,
    // exactly as the writer's `struct_element_begin` did.
    reader.enter().ok_or(TableDecodeError::Footer)?;
    let mut data_page_offset: i64 = -1;
    let mut file_offset: Option<i64> = None;
    while let Some((id, _ty)) = reader.next_field() {
        match id {
            2 => file_offset = Some(footer(reader.zigzag())?),
            3 => {
                reader.enter().ok_or(TableDecodeError::Footer)?;
                let mut encodings: Option<Vec<i64>> = None;
                let mut path: Option<String> = None;
                let mut codec: i64 = -1;
                let mut physical_id: i64 = -1;
                let mut num_values: i64 = -1;
                while let Some((field, _)) = reader.next_field() {
                    match field {
                        1 => physical_id = footer(reader.zigzag())?,
                        2 => {
                            let (count, _) = footer(reader.list_header())?;
                            let mut seen = Vec::with_capacity(count);
                            for _ in 0..count {
                                seen.push(footer(reader.zigzag())?);
                            }
                            encodings = Some(seen);
                        }
                        3 => {
                            let (count, _) = footer(reader.list_header())?;
                            if count != 1 {
                                return Err(TableDecodeError::Footer);
                            }
                            let named = String::from_utf8(footer(reader.binary())?)
                                .map_err(|_| TableDecodeError::Footer)?;
                            path = Some(named);
                        }
                        4 => codec = footer(reader.zigzag())?,
                        5 => num_values = footer(reader.zigzag())?,
                        6 | 7 => {
                            let size = footer(reader.zigzag())?;
                            if size < 0 {
                                return Err(TableDecodeError::Footer);
                            }
                        }
                        9 => data_page_offset = footer(reader.zigzag())?,
                        _ => return Err(TableDecodeError::Footer),
                    }
                }
                // The chunk's own metadata must state exactly what the
                // writer emits: its physical type, PLAIN values with RLE
                // levels, its own column name, UNCOMPRESSED, and the row
                // count it declared.
                if physical_id != i64::from(column.physical.id()) {
                    return Err(TableDecodeError::Footer);
                }
                if encodings.as_deref() != Some(&[0, 3][..]) {
                    return Err(TableDecodeError::Footer);
                }
                if path.as_deref() != Some(column.name()) {
                    return Err(TableDecodeError::Footer);
                }
                if codec != 0 {
                    return Err(TableDecodeError::Footer);
                }
                if num_values < 0 {
                    return Err(TableDecodeError::Footer);
                }
            }
            _ => return Err(TableDecodeError::Footer),
        }
    }
    // The writer states the same offset twice — the chunk's file offset
    // and the metadata's data-page offset — and both must agree and be
    // inside the file body.
    if file_offset.is_some_and(|offset| offset != data_page_offset) || data_page_offset < 4 {
        return Err(TableDecodeError::Footer);
    }

    read_data_page(bytes, data_page_offset, column)
}

/// Walk one data page's header and decode its body into the column's
/// cells, one per declared row.
fn read_data_page(
    bytes: &[u8],
    data_page_offset: i64,
    column: &Column,
) -> Result<Vec<Cell>, TableDecodeError> {
    let start = usize::try_from(data_page_offset).map_err(|_| TableDecodeError::Page)?;
    let mut header = CompactReader {
        bytes,
        pos: start,
        last_field: 0,
        stack: Vec::new(),
    };
    let mut page_type: i64 = -1;
    let mut uncompressed: i64 = -1;
    let mut compressed: i64 = -1;
    let mut declared: i64 = -1;
    while let Some((field, ty)) = header.next_field() {
        match field {
            1 => page_type = footer(header.zigzag())?,
            2 => uncompressed = footer(header.zigzag())?,
            3 => compressed = footer(header.zigzag())?,
            5 if ty == thrift::STRUCT => {
                header.enter().ok_or(TableDecodeError::Page)?;
                let mut num_values: i64 = -1;
                while let Some((inner, _)) = header.next_field() {
                    match inner {
                        1 => num_values = footer(header.zigzag())?,
                        2 => {
                            if footer(header.zigzag())? != 0 {
                                return Err(TableDecodeError::Page);
                            }
                        }
                        3 | 4 => {
                            if footer(header.zigzag())? != 3 {
                                return Err(TableDecodeError::Page);
                            }
                        }
                        _ => return Err(TableDecodeError::Page),
                    }
                }
                if num_values < 0 {
                    return Err(TableDecodeError::Page);
                }
                declared = num_values;
            }
            _ => return Err(TableDecodeError::Page),
        }
    }
    if page_type != 0 || uncompressed != compressed || compressed < 0 || declared < 0 {
        return Err(TableDecodeError::Page);
    }
    let body = page(
        bytes.get(
            header.pos
                ..header
                    .pos
                    .checked_add(usize::try_from(compressed).map_err(|_| TableDecodeError::Page)?)
                    .ok_or(TableDecodeError::Page)?,
        ),
    )?;

    // A required column's body is values only; an optional column's body
    // leads with the u32-prefixed level blob, and the levels say which
    // rows carry values — the values begin where the levels end.
    let mut cells = Vec::new();
    if column.required {
        let mut cursor = body;
        for _ in 0..declared {
            cells.push(page(read_plain(column.physical, &mut cursor))?);
        }
        if !cursor.is_empty() {
            return Err(TableDecodeError::Page);
        }
    } else {
        let (definitions, consumed) = page(split_levels(body))?;
        if i64::try_from(definitions.len()).unwrap_or(i64::MAX) != declared {
            return Err(TableDecodeError::Page);
        }
        let mut cursor = &body[consumed..];
        for level in &definitions {
            if *level == 0 {
                cells.push(Cell::Null);
            } else {
                cells.push(page(read_plain(column.physical, &mut cursor))?);
            }
        }
        if !cursor.is_empty() {
            return Err(TableDecodeError::Page);
        }
    }
    Ok(cells)
}

/// Decode the definition-level blob that opens an optional column's page
/// body: a u32 length prefix, then the hybrid stream — the width is not
/// stored, the schema derives it — of run headers (bit 0 set: literal
/// bit-packed run of `count` groups; clear: RLE run of `count` repeats).
/// Returns the levels and the blob's total consumed byte count, so the
/// caller finds the plain values exactly where the levels end.
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
            // One byte per group at bit width 1, LSB-first; the final
            // group may pad past the real levels.
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

    /// Read the next field header in the current struct. `None` at the
    /// struct's STOP, which also restores the enclosing field state.
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

    /// Descend into a struct-typed field just consumed. Fails (`None`)
    /// when the stack is deeper than the writer ever nests.
    fn enter(&mut self) -> Option<()> {
        if self.stack.len() >= 8 {
            return None;
        }
        self.stack.push(self.last_field);
        self.last_field = 0;
        Some(())
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

#[cfg(test)]
mod tests {
    //! The writer's own proof: determinism, shape faults refused, and
    //! [`Table::decode`] walking the emitted bytes the way an
    //! independent implementation would — envelope framing, footer
    //! length, thrift footer, column chunks, definition levels, plain
    //! values — so a regression that still produces *some*
    //! Parquet-shaped file is still caught by its values failing to
    //! round-trip, and a query can trust what it reads back.

    use super::{Cell, Column, Table, TableError, digest_of};

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
            Table::decode(&bytes).is_ok(),
            "the framing the reader walks is the framing the writer wrote"
        );
    }

    #[test]
    fn empty_table_still_encodes() {
        let table = Table::new(vec![Column::required_int64("n")]);
        let bytes = table.encode(&[]);
        let read = Table::decode(&bytes).expect("the empty file parses");
        assert!(read.table().is_empty());
        assert_eq!(
            read.table().columns(),
            vec![Column::required_int64("n")],
            "the schema decodes with its physical type and required flag"
        );
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
        let read = Table::decode(&bytes).expect("parses");
        assert_eq!(
            read.table().len(),
            total,
            "every row of all three row groups decodes back"
        );
        let rows = read.table().rows();
        assert_eq!(
            rows[rows.len() - 1][0],
            Cell::Int(i64::try_from(super::ROW_GROUP_ROWS * 2 + 6).expect("fits")),
            "the last row of the last group is the last value written"
        );
        // Re-encoding the decoded table reproduces the file byte for
        // byte — the group boundaries were honored, not just survived.
        assert_eq!(read.table().encode(&[]), bytes);
    }

    #[test]
    fn values_round_trip_through_the_structural_reader() {
        let source = table();
        let bytes = source.encode(&[("pipeline_id", "inventory"), ("pipeline_version", "1")]);
        let read = Table::decode(&bytes).expect("the file parses");
        assert_eq!(read.created_by(), "agent-archivist parquet writer v1");
        assert_eq!(
            read.metadata(),
            &[
                ("pipeline_id".to_owned(), "inventory".to_owned()),
                ("pipeline_version".to_owned(), "1".to_owned()),
            ]
        );
        // The decoded table is the table that encoded: schema, rows,
        // and value-for-value, so a query reads what the writer wrote.
        assert_eq!(read.table(), &source);
        assert_eq!(
            read.table().columns(),
            vec![
                Column::required_text("occurrence_id"),
                Column::optional_text("model"),
                Column::optional_int64("tokens"),
            ]
        );
        assert_eq!(
            read.table().rows(),
            &[
                vec![
                    Cell::Text("aa11".to_owned()),
                    Cell::Text("claude-sonnet-4".to_owned()),
                    Cell::Int(37),
                ],
                vec![Cell::Text("bb22".to_owned()), Cell::Null, Cell::Null],
                vec![
                    Cell::Text("cc33".to_owned()),
                    Cell::Text("claude-haiku-4".to_owned()),
                    Cell::Int(0),
                ],
            ]
        );
        // And the inverse is exact: decoding then re-encoding with the
        // same metadata reproduces the file's bytes.
        let metadata: Vec<(&str, &str)> = read
            .metadata()
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(read.table().encode(&metadata), bytes);
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
            let read = Table::decode(&bytes).expect("parses");
            let rows: Vec<Vec<Cell>> = pattern.iter().map(|cell| vec![cell.clone()]).collect();
            assert_eq!(read.table().rows(), &rows[..]);
        }
    }

    #[test]
    fn decode_refuses_bytes_outside_the_envelope() {
        let bytes = table().encode(&[]);
        // Truncations at both ends and a shifted or damaged magic strip.
        let damaged = {
            let mut copy = bytes.clone();
            copy[0] = b'X';
            copy
        };
        for candidate in [
            &bytes[..bytes.len() - 1],
            &bytes[..8],
            &bytes[1..],
            damaged.as_slice(),
        ] {
            assert_eq!(
                Table::decode(candidate),
                Err(super::TableDecodeError::Framing),
                "truncated or magic-damaged bytes are refused at the envelope"
            );
        }
        assert_eq!(
            Table::decode(&[]),
            Err(super::TableDecodeError::Framing),
            "the empty byte sequence is refused"
        );
    }

    #[test]
    fn decode_refuses_an_altered_creator_token() {
        // The creator token is pinned; a file whose token differs is
        // not this writer's output, however well-formed its thrift.
        let mut bytes = table().encode(&[]);
        let token = b"agent-archivist parquet writer v1";
        let at = bytes
            .windows(token.len())
            .position(|window| window == token)
            .expect("the token appears in the file");
        bytes[at] ^= b'x' ^ b'y';
        assert_eq!(
            Table::decode(&bytes),
            Err(super::TableDecodeError::Footer),
            "an altered creator token is a footer refusal"
        );
    }

    #[test]
    fn decode_refuses_a_corrupted_footer_length() {
        let mut bytes = table().encode(&[]);
        let body_end = bytes.len() - 8;
        bytes[body_end..body_end + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            matches!(
                Table::decode(&bytes),
                Err(super::TableDecodeError::Framing | super::TableDecodeError::Footer)
            ),
            "a footer length that cannot name a region inside the file is refused"
        );
    }
}
