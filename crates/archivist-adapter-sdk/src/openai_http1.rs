// SPDX-License-Identifier: Apache-2.0

//! The first-party HTTP/1.1 wire transport for the OpenAI-compatible
//! integration ([`crate::openai_compat`]).
//!
//! [`Http1Transport`] is the actual client transport the integration
//! speaks: a bounded, blocking HTTP/1.1 client over TCP that sends the
//! provider request, reads the response head, and either buffers the
//! decoded body or yields it as transfer-decoded chunks behind an
//! [`SseDecoder`] for `text/event-stream` responses. The conformance
//! suite ([`crate::openai_conformance`]) drives this same transport
//! against a real loopback server, so the events the observer records
//! are proven at the wire boundary, not around an in-process stub.
//!
//! The transport is deliberately bounded: a response body may not exceed
//! its configured cap, header blocks and chunk-size lines are bounded,
//! and every I/O failure is mapped onto the protocol's closed
//! [`TransportErrorClass`] vocabulary — never onto an error string that
//! could carry endpoint, header, or payload material.
//!
//! One request owns one connection end to end: the request is rendered
//! with `connection: close`, and the response body is read to its
//! framing end on that same connection. The head is parsed straight off
//! the socket one byte at a time (head lines are bounded and short), and
//! the body is read in chunk-sized pulls from the same socket, so bytes
//! that arrive in the head's TCP segments are never lost between the
//! two parse phases.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use archivist_protocol::vocabulary::TransportErrorClass;

/// Default cap on one response's decoded body bytes.
pub const DEFAULT_MAX_BODY_BYTES: usize = archivist_protocol::envelope::CANONICAL_MAX_BYTES;

/// Bound on one header block or chunk-size line, so a hostile peer
/// cannot grow the reader's buffer without bound.
const HEAD_LINE_MAX_BYTES: usize = 16 * 1024;

/// Bound on the response head as a whole (status line plus headers).
const RESPONSE_HEAD_MAX_BYTES: usize = 32 * 1024;

/// Largest single read pulled from the socket per chunk.
const READ_CHUNK_BYTES: usize = 8 * 1024;

/// The wire-level address a transport connects to: a hostname or IP and
/// a TCP port. This is the transport's whole view of an endpoint — no
/// path, scheme, or credential reaches this layer, because none of them
/// change how bytes are framed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireEndpoint {
    host: String,
    port: u16,
}

impl WireEndpoint {
    /// A wire endpoint for `host` and `port`.
    ///
    /// # Errors
    /// [`WireEndpointError::InvalidHost`] when the host is empty, longer
    /// than 253 bytes, or carries a character outside the hostname
    /// alphabet (alphanumerics, `.`, `-`).
    pub fn new(host: String, port: u16) -> Result<Self, WireEndpointError> {
        if host.is_empty() || host.len() > 253 {
            return Err(WireEndpointError::InvalidHost);
        }
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        {
            return Err(WireEndpointError::InvalidHost);
        }
        Ok(Self { host, port })
    }

    /// The host this endpoint connects to.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port this endpoint connects to.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The `host:` header value HTTP requires on the request line.
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Why a wire endpoint was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireEndpointError {
    /// The host is empty, oversized, or outside the hostname alphabet.
    InvalidHost,
}

impl std::fmt::Display for WireEndpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("wire endpoint host is not a bounded hostname")
    }
}

impl std::error::Error for WireEndpointError {}

/// Why the transport failed, in the protocol's closed class vocabulary.
///
/// The failure carries the class and the timeout that applied, and
/// nothing else: no endpoint, no header, no payload bytes, and no
/// free-text detail — transport error strings are a known
/// credential-leak route (plan Section 11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportFailure {
    /// The closed transport-failure class.
    pub class: TransportErrorClass,
    /// The observed timeout in milliseconds, when a deadline elapsed.
    pub timeout_ms: Option<u64>,
}

impl TransportFailure {
    /// A failure of `class` with no observed timeout.
    #[must_use]
    pub const fn of(class: TransportErrorClass) -> Self {
        Self {
            class,
            timeout_ms: None,
        }
    }

    /// Classify an I/O error against the direction it occurred in. The
    /// timeout, when present, is the deadline that elapsed or applied.
    #[must_use]
    pub fn from_io(error: &std::io::Error, direction: Direction, timeout_ms: Option<u64>) -> Self {
        let class = match error.kind() {
            ErrorKind::TimedOut | ErrorKind::WouldBlock => match direction {
                Direction::Read => TransportErrorClass::ReadTimeout,
                Direction::Write => TransportErrorClass::WriteTimeout,
            },
            ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof => TransportErrorClass::ConnectionReset,
            ErrorKind::ConnectionRefused => TransportErrorClass::Connect,
            _ => TransportErrorClass::Other,
        };
        Self { class, timeout_ms }
    }
}

/// The direction an I/O failure occurred in; it decides which closed
/// timeout class a deadline maps onto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A read from the provider connection.
    Read,
    /// A write to the provider connection.
    Write,
}

/// One provider wire request, already transfer-encoded-free: `body` is
/// the exact decoded payload the boundary observed, and the transport
/// adds only the framing HTTP requires (`host`, `content-length`,
/// `connection`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireRequest {
    /// Absolute path, beginning with `/`.
    pub path: String,
    /// Request headers as lowercase `(name, value)` pairs, in order.
    /// Credential headers ride here and are never captured — the capture
    /// boundary sees payload bytes and allowlisted response metadata
    /// only.
    pub headers: Vec<(String, String)>,
    /// The decoded request body bytes (the serialized JSON document).
    pub body: Vec<u8>,
}

/// A response body: fully buffered, or streaming behind the SSE decoder.
#[derive(Debug)]
pub enum WireBody {
    /// The complete decoded body, within the configured cap.
    Full(Vec<u8>),
    /// A `text/event-stream` body: transfer-decoded events on demand.
    Stream(EventStream),
}

impl WireBody {
    /// Whether this body is a decoded event stream.
    #[must_use]
    pub const fn is_stream(&self) -> bool {
        matches!(self, Self::Stream(_))
    }
}

/// One provider wire response: the decoded head plus the body reader.
#[derive(Debug)]
pub struct WireResponse {
    /// The HTTP status code.
    pub status: u16,
    /// Response headers as lowercase `(name, value)` pairs, in arrival
    /// order. The metadata mapping — never this raw block — decides what
    /// is captured.
    pub headers: Vec<(String, String)>,
    /// The body, buffered or streaming.
    pub body: WireBody,
}

impl WireResponse {
    /// The first header value carried for lowercase `name`.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name == name)
            .map(|(_, value)| value.as_str())
    }
}

/// The bounded blocking HTTP/1.1 client transport.
#[derive(Clone, Debug)]
pub struct Http1Transport {
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl Http1Transport {
    /// A transport with the default timeouts (five seconds to connect,
    /// thirty seconds per I/O step).
    #[must_use]
    pub fn new() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
        }
    }

    /// A transport with explicit connect and per-I/O timeouts.
    #[must_use]
    pub const fn with_timeouts(connect_timeout: Duration, io_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            io_timeout,
        }
    }

    /// Execute one request on a fresh connection and read the response
    /// head. The connection is close-delimited (`connection: close`), so
    /// one request owns one connection end to end.
    ///
    /// # Errors
    /// [`TransportFailure`] when resolution, connection, the write, the
    /// response head read, or the body read fails, or when a buffered
    /// body would exceed `max_body_bytes`.
    pub fn execute(
        &self,
        endpoint: &WireEndpoint,
        request: &WireRequest,
        max_body_bytes: usize,
    ) -> Result<WireResponse, TransportFailure> {
        let mut stream = self.connect(endpoint)?;
        let timeout_ms = Some(u64::try_from(self.io_timeout.as_millis()).unwrap_or(u64::MAX));
        stream
            .set_write_timeout(Some(self.io_timeout))
            .map_err(|_| TransportFailure::of(TransportErrorClass::Other))?;
        stream
            .set_read_timeout(Some(self.io_timeout))
            .map_err(|_| TransportFailure::of(TransportErrorClass::Other))?;
        let request_bytes = render_request(endpoint, request);
        stream
            .write_all(&request_bytes)
            .map_err(|error| TransportFailure::from_io(&error, Direction::Write, timeout_ms))?;
        let head = read_head(&mut stream, timeout_ms)?;
        finish_response(stream, head, max_body_bytes)
    }

    fn connect(&self, endpoint: &WireEndpoint) -> Result<TcpStream, TransportFailure> {
        let address = format!("{}:{}", endpoint.host(), endpoint.port());
        let mut resolved = address
            .to_socket_addrs()
            .map_err(|_| TransportFailure::of(TransportErrorClass::Dns))?;
        let address = resolved
            .next()
            .ok_or(TransportFailure::of(TransportErrorClass::Dns))?;
        TcpStream::connect_timeout(&address, self.connect_timeout).map_err(|error| {
            let timeout_ms = (error.kind() == ErrorKind::TimedOut)
                .then(|| u64::try_from(self.connect_timeout.as_millis()).unwrap_or(u64::MAX));
            TransportFailure {
                class: TransportErrorClass::Connect,
                timeout_ms,
            }
        })
    }
}

impl Default for Http1Transport {
    fn default() -> Self {
        Self::new()
    }
}

fn render_request(endpoint: &WireEndpoint, request: &WireRequest) -> Vec<u8> {
    let mut head = String::new();
    head.push_str("POST ");
    head.push_str(&request.path);
    head.push_str(" HTTP/1.1\r\n");
    head.push_str("host: ");
    head.push_str(&endpoint.authority());
    head.push_str("\r\n");
    for (name, value) in &request.headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("content-length: ");
    head.push_str(&request.body.len().to_string());
    head.push_str("\r\nconnection: close\r\n\r\n");
    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&request.body);
    bytes
}

/// Read one CRLF-terminated line into `line`, bounded by
/// [`HEAD_LINE_MAX_BYTES`]. An EOF where a line was required is a reset
/// stream, not a clean end (the caller distinguishes the response head's
/// terminator by content).
fn read_line(
    stream: &mut TcpStream,
    line: &mut Vec<u8>,
    timeout_ms: Option<u64>,
    eof_is_reset: bool,
) -> Result<(), TransportFailure> {
    line.clear();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                if eof_is_reset {
                    return Err(TransportFailure::of(TransportErrorClass::ConnectionReset));
                }
                return Ok(());
            }
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > HEAD_LINE_MAX_BYTES {
                    return Err(TransportFailure::of(TransportErrorClass::Other));
                }
                if byte[0] == b'\n' {
                    return Ok(());
                }
            }
            Err(error) => {
                return Err(TransportFailure::from_io(
                    &error,
                    Direction::Read,
                    timeout_ms,
                ));
            }
        }
    }
}

struct ResponseHead {
    status: u16,
    headers: Vec<(String, String)>,
}

fn read_head(
    stream: &mut TcpStream,
    timeout_ms: Option<u64>,
) -> Result<ResponseHead, TransportFailure> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        read_line(stream, &mut line, timeout_ms, true)?;
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
        if head.len() > RESPONSE_HEAD_MAX_BYTES {
            return Err(TransportFailure::of(TransportErrorClass::Other));
        }
    }
    parse_head(&head)
}

fn parse_head(head: &[u8]) -> Result<ResponseHead, TransportFailure> {
    let text = std::str::from_utf8(head)
        .map_err(|_| TransportFailure::of(TransportErrorClass::TransferDecode))?;
    let mut lines = text.split('\n');
    let status_line = lines
        .next()
        .ok_or(TransportFailure::of(TransportErrorClass::TransferDecode))?
        .trim_end_matches('\r');
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .filter(|code| (100..=599).contains(code))
        .ok_or(TransportFailure::of(TransportErrorClass::TransferDecode))?;
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r');
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(TransportFailure::of(TransportErrorClass::TransferDecode));
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    Ok(ResponseHead { status, headers })
}

/// Complete a response after its head: decide the body framing, then
/// buffer it or hand back the streaming reader. The same socket spans
/// both phases, so nothing read ahead of the body is ever lost.
fn finish_response(
    stream: TcpStream,
    head: ResponseHead,
    max_body_bytes: usize,
) -> Result<WireResponse, TransportFailure> {
    let chunked = head
        .headers
        .iter()
        .any(|(name, value)| name == "transfer-encoding" && value.contains("chunked"));
    let content_length = head
        .headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<u64>().ok());
    let streaming = head
        .headers
        .iter()
        .any(|(name, value)| name == "content-type" && value.starts_with("text/event-stream"));

    let status = head.status;
    let headers = head.headers;
    let body_reader = if chunked {
        BodyReader::Chunked {
            stream,
            state: ChunkedState::Size,
        }
    } else if let Some(length) = content_length {
        if !streaming && length > max_body_bytes as u64 {
            return Err(TransportFailure::of(TransportErrorClass::Other));
        }
        BodyReader::Length {
            stream,
            remaining: length,
        }
    } else {
        BodyReader::Eof {
            stream,
            complete: false,
        }
    };

    if streaming {
        Ok(WireResponse {
            status,
            headers,
            body: WireBody::Stream(EventStream::new(body_reader, max_body_bytes)),
        })
    } else {
        let mut body_reader = body_reader;
        let mut body = Vec::new();
        while let Some(chunk) = body_reader.next_chunk(max_body_bytes)? {
            body.extend_from_slice(&chunk);
            if body.len() > max_body_bytes {
                return Err(TransportFailure::of(TransportErrorClass::Other));
            }
        }
        Ok(WireResponse {
            status,
            headers,
            body: WireBody::Full(body),
        })
    }
}

enum ChunkedState {
    Size,
    Data { remaining: u64 },
    DataCrlf,
    Trailers,
    Done,
}

/// The transfer-decoded body reader: content-length, EOF-delimited, or
/// chunked framing, pulled in bounded chunks.
enum BodyReader {
    Length {
        stream: TcpStream,
        remaining: u64,
    },
    Eof {
        stream: TcpStream,
        complete: bool,
    },
    Chunked {
        stream: TcpStream,
        state: ChunkedState,
    },
}

impl BodyReader {
    /// Pull the next decoded chunk, or `None` at the end of the body.
    /// `cap_remaining` bounds the returned chunk for callers tracking a
    /// cumulative cap.
    ///
    /// # Errors
    /// [`TransportFailure`] on any read or framing failure.
    fn next_chunk(&mut self, cap_remaining: usize) -> Result<Option<Vec<u8>>, TransportFailure> {
        match self {
            Self::Length { stream, remaining } => {
                if *remaining == 0 {
                    return Ok(None);
                }
                let want = usize::try_from(
                    (*remaining)
                        .min(READ_CHUNK_BYTES as u64)
                        .min(cap_remaining as u64),
                )
                .map_err(|_| TransportFailure::of(TransportErrorClass::Other))?;
                if want == 0 {
                    return Err(TransportFailure::of(TransportErrorClass::Other));
                }
                let mut chunk = vec![0_u8; want];
                read_exact(stream, &mut chunk)?;
                *remaining -= want as u64;
                Ok(Some(chunk))
            }
            Self::Eof { stream, complete } => {
                if *complete {
                    return Ok(None);
                }
                let mut chunk = vec![0_u8; READ_CHUNK_BYTES.min(cap_remaining.max(1))];
                let read = read_some(stream, &mut chunk)?;
                if read == 0 {
                    *complete = true;
                    return Ok(None);
                }
                chunk.truncate(read);
                Ok(Some(chunk))
            }
            Self::Chunked { stream, state } => loop {
                match state {
                    ChunkedState::Size => {
                        let mut line = Vec::new();
                        read_chunk_line(stream, &mut line)?;
                        let text = std::str::from_utf8(&line).map_err(|_| {
                            TransportFailure::of(TransportErrorClass::TransferDecode)
                        })?;
                        let digits = text.split(';').next().unwrap_or("").trim();
                        let size = u64::from_str_radix(digits, 16).map_err(|_| {
                            TransportFailure::of(TransportErrorClass::TransferDecode)
                        })?;
                        *state = if size == 0 {
                            ChunkedState::Trailers
                        } else {
                            ChunkedState::Data { remaining: size }
                        };
                    }
                    ChunkedState::Data { remaining } => {
                        let want = usize::try_from(
                            (*remaining)
                                .min(READ_CHUNK_BYTES as u64)
                                .min(cap_remaining as u64),
                        )
                        .map_err(|_| TransportFailure::of(TransportErrorClass::Other))?;
                        if want == 0 {
                            return Err(TransportFailure::of(TransportErrorClass::Other));
                        }
                        let mut chunk = vec![0_u8; want];
                        read_exact(stream, &mut chunk)?;
                        *remaining -= want as u64;
                        if *remaining == 0 {
                            *state = ChunkedState::DataCrlf;
                        }
                        return Ok(Some(chunk));
                    }
                    ChunkedState::DataCrlf => {
                        let mut line = Vec::new();
                        read_chunk_line(stream, &mut line)?;
                        if line != b"\r\n" && line != b"\n" {
                            return Err(TransportFailure::of(TransportErrorClass::TransferDecode));
                        }
                        *state = ChunkedState::Size;
                    }
                    ChunkedState::Trailers => {
                        let mut line = Vec::new();
                        read_chunk_line(stream, &mut line)?;
                        if line == b"\r\n" || line == b"\n" || line.is_empty() {
                            *state = ChunkedState::Done;
                        }
                    }
                    ChunkedState::Done => return Ok(None),
                }
            },
        }
    }
}

fn read_exact(stream: &mut TcpStream, chunk: &mut [u8]) -> Result<(), TransportFailure> {
    stream
        .read_exact(chunk)
        .map_err(|error| TransportFailure::from_io(&error, Direction::Read, None))
}

fn read_some(stream: &mut TcpStream, chunk: &mut [u8]) -> Result<usize, TransportFailure> {
    stream
        .read(chunk)
        .map_err(|error| TransportFailure::from_io(&error, Direction::Read, None))
}

/// Read one line for chunked framing, bounded by
/// [`HEAD_LINE_MAX_BYTES`]. An EOF where a line was required is a reset
/// stream, not a clean end.
fn read_chunk_line(stream: &mut TcpStream, line: &mut Vec<u8>) -> Result<(), TransportFailure> {
    line.clear();
    let mut byte = [0_u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => return Err(TransportFailure::of(TransportErrorClass::ConnectionReset)),
            Ok(_) => {
                line.push(byte[0]);
                if line.len() > HEAD_LINE_MAX_BYTES {
                    return Err(TransportFailure::of(TransportErrorClass::TransferDecode));
                }
                if byte[0] == b'\n' {
                    return Ok(());
                }
            }
            Err(error) => {
                return Err(TransportFailure::from_io(&error, Direction::Read, None));
            }
        }
    }
}

/// The streaming SSE reader over a transfer-decoded body: complete
/// `data:`-payload events, bounded by the body cap.
pub struct EventStream {
    reader: Option<BodyReader>,
    decoder: SseDecoder,
    body_cap: usize,
    observed_bytes: usize,
}

impl std::fmt::Debug for EventStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EventStream")
            .field("body_cap", &self.body_cap)
            .field("observed_bytes", &self.observed_bytes)
            .finish_non_exhaustive()
    }
}

impl EventStream {
    fn new(reader: BodyReader, body_cap: usize) -> Self {
        Self {
            reader: Some(reader),
            decoder: SseDecoder::new(),
            body_cap,
            observed_bytes: 0,
        }
    }

    /// The next complete decoded event's bytes, or `None` when the
    /// stream ended. A final unterminated event with data is emitted at
    /// end of body, so nothing observed is silently dropped.
    ///
    /// # Errors
    /// [`TransportFailure`] when the body read or framing fails, or when
    /// the cumulative decoded bytes exceed the body cap.
    pub fn next_event(&mut self) -> Result<Option<Vec<u8>>, TransportFailure> {
        loop {
            if let Some(event) = self.decoder.take_complete_event() {
                return Ok(Some(event));
            }
            let Some(reader) = self.reader.as_mut() else {
                return Ok(self.decoder.finish());
            };
            let cap_remaining = self.body_cap.saturating_sub(self.observed_bytes);
            match reader.next_chunk(cap_remaining.max(1))? {
                Some(chunk) => {
                    self.observed_bytes = self.observed_bytes.saturating_add(chunk.len());
                    if self.observed_bytes > self.body_cap {
                        self.reader = None;
                        return Err(TransportFailure::of(TransportErrorClass::Other));
                    }
                    self.decoder.feed(&chunk);
                }
                None => {
                    self.reader = None;
                }
            }
        }
    }
}

/// The SSE event assembler: turns decoded body chunks into complete
/// event payloads (the joined `data:` lines of one event block).
///
/// Only the `data` field carries payload bytes. `event:`, `id:`,
/// `retry:`, and comment lines are framing the boundary never captures;
/// a single leading space after the colon is stripped per SSE framing.
/// A blank line dispatches the event block that carried data; blocks
/// without data are framing and never become events.
#[derive(Debug, Default)]
pub struct SseDecoder {
    buffer: Vec<u8>,
    data_lines: Vec<Vec<u8>>,
    event_ready: bool,
}

impl SseDecoder {
    /// An empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one transfer-decoded chunk; the completed events it closes
    /// are retrieved one at a time through [`Self::take_complete_event`].
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buffer.extend_from_slice(chunk);
        let mut consumed = 0_usize;
        while let Some(newline) = self.buffer[consumed..]
            .iter()
            .position(|byte| *byte == b'\n')
        {
            // The line is copied out before dispatch: `accept_line`
            // mutates the decoder the slice would borrow from.
            let line: Vec<u8> = self.buffer[consumed..consumed + newline].to_vec();
            consumed += newline + 1;
            self.accept_line(&line);
        }
        self.buffer.drain(..consumed);
    }

    /// The final event when the body ended mid-event with data lines
    /// pending; SSE framing otherwise drops it.
    pub fn finish(&mut self) -> Option<Vec<u8>> {
        if !self.buffer.is_empty() {
            let line = std::mem::take(&mut self.buffer);
            self.accept_line(&line);
        }
        if self.data_lines.is_empty() {
            return None;
        }
        let joined = self.data_lines.join(&b'\n');
        self.data_lines.clear();
        Some(joined)
    }

    fn accept_line(&mut self, line: &[u8]) {
        let trimmed = if line.ends_with(b"\r") {
            &line[..line.len() - 1]
        } else {
            line
        };
        if trimmed.is_empty() {
            // A blank line dispatches the block, when it carried data.
            if !self.data_lines.is_empty() {
                self.event_ready = true;
            }
            return;
        }
        let (field, value) = match trimmed.iter().position(|byte| *byte == b':') {
            Some(colon) => (
                &trimmed[..colon],
                if trimmed[colon + 1..].first() == Some(&b' ') {
                    &trimmed[colon + 2..]
                } else {
                    &trimmed[colon + 1..]
                },
            ),
            None => (trimmed, &trimmed[trimmed.len()..]),
        };
        if field == b"data" {
            self.data_lines.push(value.to_vec());
        }
    }

    /// Take the completed event when a blank line has ended a block that
    /// carried data.
    pub fn take_complete_event(&mut self) -> Option<Vec<u8>> {
        if self.event_ready {
            self.event_ready = false;
            let joined = self.data_lines.join(&b'\n');
            self.data_lines.clear();
            return Some(joined);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_decoder_joins_data_lines_and_skips_framing() {
        let mut decoder = SseDecoder::new();
        decoder.feed(b"event: delta\r\ndata: one\r\n: comment\r\nid: 7\r\n\r\n");
        let event = decoder.take_complete_event().expect("dispatched event");
        assert_eq!(event, b"one");

        // Multi-line data joins with newlines; a field with no space
        // after the colon keeps the value whole.
        decoder.feed(b"data: alpha\ndata:beta\ndata: \r\n\r\n");
        let event = decoder.take_complete_event().expect("second event");
        // Each data line contributes its newline (the empty line too);
        // dispatch strips exactly one, so the payload keeps the last.
        assert_eq!(event, b"alpha\nbeta\n");

        // A blank line with no pending data dispatches nothing.
        decoder.feed(b"event: ping\r\n\r\n");
        assert_eq!(decoder.take_complete_event(), None);
    }

    #[test]
    fn sse_decoder_emits_unterminated_final_event_exactly_once() {
        let mut decoder = SseDecoder::new();
        decoder.feed(b"data: done-1\r\n\r\ndata: tail");
        let first = decoder.take_complete_event().expect("terminated event");
        assert_eq!(first, b"done-1");
        // finish() flushes the unterminated tail line and dispatches it.
        let tail = decoder.finish().expect("unterminated tail event");
        assert_eq!(tail, b"tail");
        // Idempotent: nothing remains.
        assert_eq!(decoder.finish(), None);
        assert_eq!(decoder.take_complete_event(), None);
    }

    #[test]
    fn wire_endpoint_validates_host() {
        assert!(WireEndpoint::new("127.0.0.1".to_owned(), 8080).is_ok());
        assert!(WireEndpoint::new(String::new(), 8080).is_err());
        assert!(WireEndpoint::new("bad host".to_owned(), 8080).is_err());
        assert!(WireEndpoint::new("a".repeat(254), 8080).is_err());
    }
}
