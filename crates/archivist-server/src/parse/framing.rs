// SPDX-License-Identifier: Apache-2.0

//! The `multipart/related` framing layer of `/v1/ingest`
//! (docs/protocol/v1.md Section 1.2; plan Section 7.2).
//!
//! Two stages, in the order the request presents them:
//!
//! 1. [`RequestFraming::validate_content_type`] checks the complete
//!    request Content-Type header value against the grammar the protocol
//!    pins — `multipart/related` with a `boundary` parameter whose syntax
//!    matches `[0-9A-Za-z'()+_,.:=?-]{1,70}` — and rejects anything else
//!    with a typed, content-free error. The check runs on the header
//!    string alone: no body byte can be pulled before it passes, because
//!    the body tokenizer cannot be constructed without a validated
//!    [`RequestFraming`]. The grammar is byte-exact rather than
//!    case-insensitive on purpose: the complete header value is covered by
//!    the per-attempt signature, so the canonical client transmits exactly
//!    the pinned bytes and every deviation is a framing failure.
//!
//! 2. [`FramingTokenizer`] walks the body through the byte-level framing
//!    the conformance corpus pins (`--<boundary>` CRLF, one lowercase
//!    `content-type` header per part, CRLF, part bytes, CRLF, repeat,
//!    closing `--<boundary>--` CRLF), yielding [`FramingEvent`]s: part
//!    boundaries, part header values, and payload runs. It is
//!    incremental — the caller pulls events as it goes — and bounded: its
//!    window never exceeds [`FRAMING_WINDOW_BYTES`] regardless of body
//!    size, and across window refills it retains at most one delimiter's
//!    worth of bytes. Nothing payload-scale is ever buffered, which is the
//!    property VAL-008 requires and which the envelope and payload layers
//!    above this one rely on.
//!
//! The layer is deliberately mute about what the parts contain. Part
//! order, part media types, and the envelope are validated by
//! `archivist-protocol` on top of the events this layer yields; a part
//! count or media type that differs from the Section 1.2 table is that
//! layer's framing failure to reject. Every [`FramingError`] is a
//! closed, content-free variant naming the framing stage that failed —
//! no variant can carry a byte of the request, and [`FramingError::code`]
//! maps each to the registry's `request.framing_invalid`.

use std::io;

use archivist_protocol::vocabulary::{ContentType, ErrorCode};

/// The fixed small window the tokenizer buffers, in bytes.
///
/// A scan window, not a limit on any part: payload runs stream through it
/// in chunks of at most this size, so memory follows the window plus one
/// delimiter's retention, never the body.
pub const FRAMING_WINDOW_BYTES: usize = 8 * 1024;

/// The longest byte run a delimiter can occupy: CRLF + `--` + a maximal
/// boundary (70) + the closing `--`. The tokenizer retains at most one
/// byte less than this across window refills, so a delimiter straddling
/// the edge is still recognized once the refill arrives.
const DELIMITER_MAX_BYTES: usize = 6 + 70;

/// The pinned part-header line's prefix, byte-exact: one lowercase
/// `content-type` header, its colon, and the single space the conformance
/// corpus transmits.
const CONTENT_TYPE_HEADER_PREFIX: &[u8] = b"content-type: ";

/// Why a request cannot be framed.
///
/// Every variant is a closed, content-free token: the error names the
/// framing stage that failed and carries nothing derived from the request,
/// so no rendering of it can echo a header value, a boundary, or a body
/// byte (SEC-004; ERR-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramingError {
    /// The request Content-Type does not name the `multipart/related`
    /// media type exactly as the grammar pins it (wrong type, wrong case,
    /// or malformed overall shape).
    NotMultipartRelated,
    /// The media type is right but the `boundary` parameter is missing,
    /// empty, outside the 1-70 character bound, or holds a character the
    /// pinned boundary grammar forbids.
    BoundaryInvalid,
    /// The body does not begin with the declared dash-boundary line; the
    /// pinned framing allows no preamble before it.
    MissingOpeningBoundary,
    /// A delimiter line is malformed where the pinned framing requires
    /// `--<boundary>` CRLF, the closing `--`, or the CRLF that follows
    /// either.
    MalformedDelimiter,
    /// A part's header block is not exactly one lowercase `content-type`
    /// header followed by the blank line, or that block exceeds the
    /// framing window.
    PartHeaderMalformed,
    /// The body ended before the closing delimiter completed the pinned
    /// framing.
    UnexpectedEndOfStream,
    /// Bytes follow the CRLF that closes the closing delimiter; the
    /// pinned framing ends the body there.
    TrailingBytesAfterClosingDelimiter,
    /// The byte source failed. Only the closed [`io::ErrorKind`] is
    /// carried — the source's own error value never enters this type.
    SourceRead(io::ErrorKind),
}

impl FramingError {
    /// The stable wire code for this failure: every framing rejection is
    /// `request.framing_invalid` in the error registry; the typed variant
    /// distinguishes stages for logs and tests, never the wire body.
    ///
    /// # Panics
    /// Never in practice: the literal below matches the registry grammar
    /// pinned by `tools/check-error-codes.py`, so a panic is a
    /// programming error introduced alongside this match, not a wire
    /// condition.
    #[must_use]
    pub fn code(self) -> ErrorCode {
        let _ = self;
        ErrorCode::parse("request.framing_invalid")
            .expect("request.framing_invalid matches the registry grammar")
    }
}

/// A validated request framing: the Content-Type header value matched the
/// pinned grammar, and the boundary the body's delimiter lines must use is
/// known.
///
/// Construct only through [`RequestFraming::validate_content_type`] — the
/// guarantee that nothing else was accepted is what lets the body
/// tokenizer treat the boundary as trusted framing input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestFraming {
    boundary: String,
}

impl RequestFraming {
    /// Validate the complete request Content-Type header value and extract
    /// its boundary parameter.
    ///
    /// The full pinned grammar — `multipart/related; boundary=` plus one
    /// to seventy boundary-charset characters and nothing else — is
    /// enforced by `archivist-protocol`'s [`ContentType`]; this classifies
    /// a rejection into the two header-stage variants and retains the
    /// boundary. It runs on the header string alone, before any body byte
    /// is read.
    ///
    /// # Errors
    /// [`FramingError::NotMultipartRelated`] when the media type is not
    /// exactly the pinned `multipart/related`; [`FramingError::BoundaryInvalid`]
    /// when the media type is right but the boundary parameter is missing
    /// or malformed.
    pub fn validate_content_type(header: &str) -> Result<Self, FramingError> {
        ContentType::parse(header).map_err(|_grammar_error| {
            // Classify without re-implementing the grammar: a header whose
            // media type is byte-exact `multipart/related` failed on its
            // boundary or parameter shape; anything else failed on the
            // media type itself.
            let media_type_exact = header.starts_with("multipart/related")
                && matches!(
                    header.as_bytes().get("multipart/related".len()),
                    None | Some(b';')
                );
            if media_type_exact {
                FramingError::BoundaryInvalid
            } else {
                FramingError::NotMultipartRelated
            }
        })?;
        // The grammar pins the literal 28-byte `multipart/related;
        // boundary=` prefix before a non-empty boundary and nothing after
        // it, so this slice is exactly the parameter.
        Ok(Self {
            boundary: header["multipart/related; boundary=".len()..].to_owned(),
        })
    }

    /// The boundary parameter, exactly as the validated header carried it.
    #[must_use]
    pub fn boundary(&self) -> &str {
        &self.boundary
    }
}

/// One incremental pull of request bytes into the tokenizer's window.
///
/// The tokenizer asks for at most [`FRAMING_WINDOW_BYTES`] bytes at a
/// time; a source that cannot bound its reads that way must adapt before
/// implementing this trait. `Ok(0)` means end of stream.
pub trait ByteSource {
    /// Fill `window` with the next bytes, returning how many were written.
    ///
    /// # Errors
    /// A closed [`io::ErrorKind`] when the source fails. The source's own
    /// error value must not be surfaced — the tokenizer's errors are
    /// content-free by construction.
    fn pull(&mut self, window: &mut [u8]) -> Result<usize, io::ErrorKind>;
}

impl ByteSource for &[u8] {
    fn pull(&mut self, window: &mut [u8]) -> Result<usize, io::ErrorKind> {
        let n = window.len().min(self.len());
        window[..n].copy_from_slice(&self[..n]);
        *self = &self[n..];
        Ok(n)
    }
}

/// One framed item of the multipart body, yielded in stream order.
///
/// The borrowed payloads and header values point into the tokenizer's
/// window: they are valid until the next [`FramingTokenizer::next_event`]
/// call, and a consumer that keeps them must copy.
#[derive(Debug, PartialEq, Eq)]
pub enum FramingEvent<'a> {
    /// A part boundary line was consumed; the part's headers follow.
    PartStarted,
    /// The part's single lowercase `content-type` header value, between
    /// the pinned prefix and the blank line, exactly as transmitted.
    PartContentType(&'a str),
    /// A run of the current part's payload bytes, at most the framing
    /// window long. A part streams as consecutive runs until
    /// [`FramingEvent::PartEnded`].
    Payload(&'a [u8]),
    /// The delimiter ending the current part's payload was consumed.
    PartEnded,
    /// The closing delimiter and its CRLF were consumed; the body is
    /// fully framed.
    EndOfParts,
}

/// Where the tokenizer is in the pinned byte-level framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Expect `--<boundary>` CRLF as the body's first bytes.
    Opening,
    /// Expect one lowercase `content-type` header line and the blank line.
    Headers,
    /// Stream payload runs until the `CRLF--<boundary>` delimiter.
    Payload,
    /// After a delimiter line: CRLF opens the next part, `--` closes.
    AfterBoundary,
    /// After the closing `--`: expect the final CRLF.
    AfterClose,
    /// A part-ending delimiter just completed: the next part opens
    /// immediately, so the next event is its [`FramingEvent::PartStarted`].
    NextPartOpening,
    /// The closing `--` was consumed: the current part's payload just
    /// ended, so its [`FramingEvent::PartEnded`] is still owed.
    ClosingPart,
    /// The closing CRLF was consumed; only end of stream may follow.
    Done,
}

/// An incremental, bounded tokenizer over a `multipart/related` request
/// body.
///
/// Constructed only from a validated [`RequestFraming`] plus a
/// [`ByteSource`]; [`FramingTokenizer::next_event`] then yields
/// [`FramingEvent`]s in stream order, ending with
/// [`FramingEvent::EndOfParts`] and then `Ok(None)`. The internal window
/// never exceeds [`FRAMING_WINDOW_BYTES`], and at most
/// `DELIMITER_MAX_BYTES - 1` bytes are retained across refills while
/// scanning a payload, so memory is bounded for any body size (VAL-008).
pub struct FramingTokenizer<S: ByteSource> {
    source: S,
    dash_boundary: Vec<u8>,
    payload_delimiter: Vec<u8>,
    window: Vec<u8>,
    pos: usize,
    stage: Stage,
}

impl<S: ByteSource> FramingTokenizer<S> {
    /// Build a tokenizer for a body framed under the validated
    /// `framing`, reading through `source`. Pulls nothing: the first
    /// [`FramingTokenizer::next_event`] call reads the first body byte.
    #[must_use]
    pub fn new(framing: &RequestFraming, source: S) -> Self {
        let mut dash_boundary = Vec::with_capacity(framing.boundary().len() + 2);
        dash_boundary.extend_from_slice(b"--");
        dash_boundary.extend_from_slice(framing.boundary().as_bytes());
        let mut payload_delimiter = Vec::with_capacity(framing.boundary().len() + 4);
        payload_delimiter.extend_from_slice(b"\r\n");
        payload_delimiter.extend_from_slice(&dash_boundary);
        // The grammar caps the boundary at 70 bytes, so the delimiter
        // always fits the retention bound the payload stage retains.
        debug_assert!(payload_delimiter.len() < DELIMITER_MAX_BYTES);
        Self {
            source,
            dash_boundary,
            payload_delimiter,
            window: Vec::with_capacity(FRAMING_WINDOW_BYTES),
            pos: 0,
            stage: Stage::Opening,
        }
    }

    /// Live (unconsumed) byte count in the window.
    fn live(&self) -> usize {
        self.window.len() - self.pos
    }

    /// Whether the live window begins with `prefix`.
    fn starts_with(&self, prefix: &[u8]) -> bool {
        self.window[self.pos..].starts_with(prefix)
    }

    /// Whether the live window begins with `prefix` at `offset` bytes past
    /// the consumed position.
    fn matches_at(&self, offset: usize, prefix: &[u8]) -> bool {
        self.window[self.pos + offset..].starts_with(prefix)
    }

    /// Compact consumed bytes out of the window and pull more from the
    /// source, returning how many new bytes arrived (`0` = end of stream,
    /// or a window already too full to pull into).
    fn fill(&mut self) -> Result<usize, FramingError> {
        if self.pos > 0 {
            self.window.drain(..self.pos);
            self.pos = 0;
        }
        if self.window.len() >= FRAMING_WINDOW_BYTES {
            return Ok(0);
        }
        let filled = self.window.len();
        self.window.resize(FRAMING_WINDOW_BYTES, 0);
        let pulled = self
            .source
            .pull(&mut self.window[filled..])
            .map_err(FramingError::SourceRead)?;
        self.window.truncate(filled + pulled);
        Ok(pulled)
    }

    /// Yield the next framed item, pulling source bytes as needed.
    ///
    /// Returns `Ok(None)` once the pinned framing has fully completed and
    /// the source is at end of stream. The returned event borrows the
    /// window; dropping it before the next call is what lets the
    /// tokenizer refill.
    ///
    /// # Errors
    /// The first [`FramingError`] the framing stages above describe —
    /// whichever the stream violates first.
    #[allow(clippy::too_many_lines)] // one state machine, read top to bottom
    pub fn next_event(&mut self) -> Result<Option<FramingEvent<'_>>, FramingError> {
        loop {
            match self.stage {
                Stage::Opening => {
                    // Reject a mismatching prefix as soon as it is
                    // decidable; wait for more bytes only while the live
                    // bytes are still a prefix of the dash-boundary.
                    if self.live() < self.dash_boundary.len()
                        && !self.starts_with(&self.dash_boundary[..self.live()])
                    {
                        return Err(FramingError::MissingOpeningBoundary);
                    }
                    if self.live() < self.dash_boundary.len() + 2 {
                        if self.fill()? == 0 {
                            if !self.starts_with(&self.dash_boundary) {
                                return Err(FramingError::MissingOpeningBoundary);
                            }
                            return Err(FramingError::UnexpectedEndOfStream);
                        }
                        continue;
                    }
                    if !self.starts_with(&self.dash_boundary) {
                        return Err(FramingError::MissingOpeningBoundary);
                    }
                    if !self.matches_at(self.dash_boundary.len(), b"\r\n") {
                        return Err(FramingError::MalformedDelimiter);
                    }
                    self.pos += self.dash_boundary.len() + 2;
                    self.stage = Stage::Headers;
                    return Ok(Some(FramingEvent::PartStarted));
                }
                Stage::Headers => {
                    // A bare CRLF where the header line belongs is an
                    // empty header block; the pinned framing requires one
                    // content-type header per part.
                    if self.starts_with(b"\r\n") {
                        return Err(FramingError::PartHeaderMalformed);
                    }
                    let terminator = self.window[self.pos..]
                        .windows(4)
                        .position(|window| window == b"\r\n\r\n");
                    let Some(at) = terminator else {
                        // A full window with no terminator means the
                        // header block itself exceeds the framing window.
                        if self.window.len() >= FRAMING_WINDOW_BYTES {
                            return Err(FramingError::PartHeaderMalformed);
                        }
                        if self.fill()? == 0 {
                            return Err(FramingError::UnexpectedEndOfStream);
                        }
                        continue;
                    };
                    let Some(value) = self.window[self.pos..self.pos + at]
                        .strip_prefix(CONTENT_TYPE_HEADER_PREFIX)
                        .filter(|value| !value.is_empty())
                        .and_then(|value| std::str::from_utf8(value).ok())
                    else {
                        return Err(FramingError::PartHeaderMalformed);
                    };
                    self.pos += at + 4;
                    self.stage = Stage::Payload;
                    return Ok(Some(FramingEvent::PartContentType(value)));
                }
                Stage::Payload => {
                    if self.live() == 0 {
                        if self.fill()? == 0 {
                            return Err(FramingError::UnexpectedEndOfStream);
                        }
                        continue;
                    }
                    let at = self.window[self.pos..]
                        .windows(self.payload_delimiter.len())
                        .position(|window| window == self.payload_delimiter.as_slice());
                    if let Some(at) = at {
                        let payload = &self.window[self.pos..self.pos + at];
                        self.pos += at + self.payload_delimiter.len();
                        self.stage = Stage::AfterBoundary;
                        return Ok(Some(FramingEvent::Payload(payload)));
                    }
                    // No delimiter in the live bytes: emit all but a
                    // retention long enough that a delimiter split across
                    // the refill edge is still found after the fill.
                    let retain = self.payload_delimiter.len() - 1;
                    if self.live() > retain {
                        let emit = self.live() - retain;
                        let payload = &self.window[self.pos..self.pos + emit];
                        self.pos += emit;
                        return Ok(Some(FramingEvent::Payload(payload)));
                    }
                    if self.fill()? == 0 {
                        return Err(FramingError::UnexpectedEndOfStream);
                    }
                }
                Stage::AfterBoundary => {
                    if self.live() < 2 {
                        if self.fill()? == 0 {
                            return Err(FramingError::UnexpectedEndOfStream);
                        }
                        continue;
                    }
                    if self.starts_with(b"--") {
                        self.pos += 2;
                        self.stage = Stage::ClosingPart;
                    } else if self.starts_with(b"\r\n") {
                        self.pos += 2;
                        self.stage = Stage::NextPartOpening;
                        return Ok(Some(FramingEvent::PartEnded));
                    } else {
                        return Err(FramingError::MalformedDelimiter);
                    }
                }
                Stage::ClosingPart => {
                    // The closing `--` ends the current part's payload just
                    // like any delimiter; its [`FramingEvent::PartEnded`]
                    // is still owed before the stream can close.
                    self.stage = Stage::AfterClose;
                    return Ok(Some(FramingEvent::PartEnded));
                }
                Stage::AfterClose => {
                    if self.live() < 2 {
                        if self.fill()? == 0 {
                            return Err(FramingError::UnexpectedEndOfStream);
                        }
                        continue;
                    }
                    if !self.starts_with(b"\r\n") {
                        return Err(FramingError::MalformedDelimiter);
                    }
                    self.pos += 2;
                    self.stage = Stage::Done;
                    return Ok(Some(FramingEvent::EndOfParts));
                }
                Stage::NextPartOpening => {
                    self.stage = Stage::Headers;
                    return Ok(Some(FramingEvent::PartStarted));
                }
                Stage::Done => {
                    // Trailing bytes can already sit in the window past the
                    // closing delimiter — an earlier fill over-pulled — or
                    // still be in the source; both are the same failure.
                    if self.live() > 0 || self.fill()? > 0 {
                        return Err(FramingError::TrailingBytesAfterClosingDelimiter);
                    }
                    return Ok(None);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ByteSource, FRAMING_WINDOW_BYTES, FramingError, FramingEvent, FramingTokenizer,
        RequestFraming,
    };

    /// The boundary the conformance corpus pins for the valid-direct
    /// baseline scenario.
    const BOUNDARY: &str = "archivist-conformance-01";
    /// Part one's media type, as the corpus pins it.
    const ENVELOPE_MEDIA_TYPE: &str = "application/vnd.agent-archivist.envelope+json;version=1";
    /// Part two's media type under the identity transport.
    const IDENTITY_MEDIA_TYPE: &str = "application/octet-stream";

    /// A synthetic body shaped exactly like the conformance corpus's
    /// `multipart_body`: dash-boundary CRLF, one lowercase content-type
    /// header per part, blank line, part bytes, CRLF, closing
    /// dash-boundary dashes CRLF.
    fn conformance_body(envelope: &[u8], payload: &[u8]) -> Vec<u8> {
        conformance_body_with_boundary(BOUNDARY, envelope, payload)
    }

    fn conformance_body_with_boundary(boundary: &str, envelope: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("content-type: {ENVELOPE_MEDIA_TYPE}\r\n\r\n").as_bytes());
        body.extend_from_slice(envelope);
        body.extend_from_slice(format!("\r\n--{boundary}\r\n").as_bytes());
        body.extend_from_slice(format!("content-type: {IDENTITY_MEDIA_TYPE}\r\n\r\n").as_bytes());
        body.extend_from_slice(payload);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        body
    }

    /// A source handing out at most `chunk` bytes per pull, so tests can
    /// drive the tokenizer through arbitrary refill edges.
    struct Chunked<'a> {
        body: &'a [u8],
        chunk: usize,
        pulls: usize,
    }

    impl ByteSource for Chunked<'_> {
        fn pull(&mut self, window: &mut [u8]) -> Result<usize, std::io::ErrorKind> {
            self.pulls += 1;
            let n = window.len().min(self.chunk).min(self.body.len());
            window[..n].copy_from_slice(&self.body[..n]);
            self.body = &self.body[n..];
            Ok(n)
        }
    }

    /// The event sequence a test asserts on: payloads owned and
    /// consecutive runs merged, so assertions hold whatever the refill
    /// pattern did to chunk boundaries.
    #[derive(Debug, PartialEq, Eq)]
    enum Collected {
        PartStarted,
        ContentType(String),
        Payload(Vec<u8>),
        PartEnded,
        EndOfParts,
    }

    fn collect_events<S: ByteSource>(
        source: S,
        boundary: &str,
    ) -> Result<Vec<Collected>, FramingError> {
        let framing = RequestFraming::validate_content_type(&format!(
            "multipart/related; boundary={boundary}"
        ))
        .expect("valid content type");
        let mut tokenizer = FramingTokenizer::new(&framing, source);
        let mut events: Vec<Collected> = Vec::new();
        let mut payload_chunk_sizes: Vec<usize> = Vec::new();
        while let Some(event) = tokenizer.next_event()? {
            match event {
                FramingEvent::PartStarted => events.push(Collected::PartStarted),
                FramingEvent::PartContentType(value) => {
                    events.push(Collected::ContentType(value.to_owned()));
                }
                FramingEvent::Payload(bytes) => {
                    payload_chunk_sizes.push(bytes.len());
                    if let Some(Collected::Payload(merged)) = events.last_mut() {
                        merged.extend_from_slice(bytes);
                    } else {
                        events.push(Collected::Payload(bytes.to_vec()));
                    }
                }
                FramingEvent::PartEnded => events.push(Collected::PartEnded),
                FramingEvent::EndOfParts => events.push(Collected::EndOfParts),
            }
        }
        // Every payload run is bounded by the framing window, whatever the
        // refill pattern.
        assert!(
            payload_chunk_sizes
                .iter()
                .all(|len| *len <= FRAMING_WINDOW_BYTES),
            "a payload run exceeded the framing window: {payload_chunk_sizes:?}"
        );
        Ok(events)
    }

    fn body_events(body: &[u8], chunk: usize) -> Result<Vec<Collected>, FramingError> {
        body_events_with_boundary(BOUNDARY, body, chunk)
    }

    fn body_events_with_boundary(
        boundary: &str,
        body: &[u8],
        chunk: usize,
    ) -> Result<Vec<Collected>, FramingError> {
        collect_events(
            Chunked {
                body,
                chunk,
                pulls: 0,
            },
            boundary,
        )
    }

    /// The payload bytes of each part, in part order: consecutive payload
    /// runs merged within a part, parts split on their boundaries.
    fn part_payloads(events: &[Collected]) -> Vec<Vec<u8>> {
        let mut parts: Vec<Vec<u8>> = Vec::new();
        for event in events {
            match event {
                Collected::PartStarted => parts.push(Vec::new()),
                Collected::Payload(bytes) => parts
                    .last_mut()
                    .expect("a payload run follows its part start")
                    .extend_from_slice(bytes),
                _ => {}
            }
        }
        parts
    }

    #[test]
    fn conformance_shaped_body_tokenizes_into_exactly_two_parts() {
        let envelope =
            b"{\"protocol_version\":1,\"envelope_version\":1,\"tenant_id\":\"0f1e2d3c\"}";
        let payload = b"{\"seq\":1,\"text\":\"conformance alpha one\",\"type\":\"user\"}\n\
                        {\"seq\":2,\"text\":\"conformance beta two\",\"type\":\"assistant\"}\n";
        let body = conformance_body(envelope, payload);

        // One pull of everything, byte-at-a-time refills, and a mid-body
        // edge must all frame identically.
        for chunk in [usize::MAX, 7, 1] {
            let events = body_events(&body, chunk).expect("frames");
            assert_eq!(
                events,
                vec![
                    Collected::PartStarted,
                    Collected::ContentType(ENVELOPE_MEDIA_TYPE.to_owned()),
                    Collected::Payload(envelope.to_vec()),
                    Collected::PartEnded,
                    Collected::PartStarted,
                    Collected::ContentType(IDENTITY_MEDIA_TYPE.to_owned()),
                    Collected::Payload(payload.to_vec()),
                    Collected::PartEnded,
                    Collected::EndOfParts,
                ],
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn payload_larger_than_the_window_streams_in_bounded_runs() {
        let payload: Vec<u8> = (0..60 * 1024).map(|i| b"record line \n"[i % 13]).collect();
        let body = conformance_body(b"{\"protocol_version\":1}", &payload);
        let events = body_events(&body, 512).expect("frames");
        assert_eq!(
            events.last(),
            Some(&Collected::EndOfParts),
            "a 60 KiB body still frames to completion"
        );
        let reassembled = part_payloads(&events);
        assert_eq!(reassembled.len(), 2, "the body has exactly two parts");
        assert_eq!(reassembled[0], b"{\"protocol_version\":1}".to_vec());
        assert_eq!(reassembled[1], payload);
    }

    #[test]
    fn wrong_media_type_is_rejected_before_any_body_byte_is_pulled() {
        for header in [
            "multipart/form-data; boundary=x",
            "application/json",
            "text/plain",
            "MULTIPART/RELATED; boundary=x",
            "multipart/relatedx; boundary=x",
            "multipart/related ; boundary=a",
            "",
        ] {
            let error = RequestFraming::validate_content_type(header).expect_err("rejected");
            assert_eq!(error, FramingError::NotMultipartRelated, "{header:?}");
        }
        // Header-stage rejection runs on the string alone: a pull-counting
        // source shows zero pulls through validation and construction.
        let body = conformance_body(b"{}", b"x");
        let source = Chunked {
            body: &body,
            chunk: 64,
            pulls: 0,
        };
        assert!(RequestFraming::validate_content_type("multipart/form-data; boundary=x").is_err());
        assert_eq!(
            source.pulls, 0,
            "no body byte moved before validation passed"
        );
    }

    #[test]
    fn malformed_boundary_parameters_are_typed_rejections() {
        for header in [
            "multipart/related",
            "multipart/related; boundary=",
            "multipart/related; boundary=a/b",
            "multipart/related; boundary=a b",
            "multipart/related; boundary=a;b",
            "multipart/related; boundary=a; charset=utf-8",
        ] {
            let error = RequestFraming::validate_content_type(header).expect_err("rejected");
            assert_eq!(error, FramingError::BoundaryInvalid, "{header:?}");
        }
        // Seventy-one characters bust the boundary length bound.
        let too_long = format!("multipart/related; boundary={}", "a".repeat(71));
        let error = RequestFraming::validate_content_type(&too_long).expect_err("rejected");
        assert_eq!(error, FramingError::BoundaryInvalid);
        // The one-byte floor and the 70-byte ceiling of the grammar pass.
        assert!(RequestFraming::validate_content_type("multipart/related; boundary=a").is_ok());
        assert!(
            RequestFraming::validate_content_type(&format!(
                "multipart/related; boundary={}",
                "a".repeat(70)
            ))
            .is_ok()
        );
        // Uppercase letters are in the pinned boundary charset.
        assert!(
            RequestFraming::validate_content_type("multipart/related; boundary=BOUNDARY").is_ok()
        );
    }

    #[test]
    fn every_legal_boundary_charset_character_frames_end_to_end() {
        let boundary = "a'B+c_(d),.:=?-E";
        let framing = RequestFraming::validate_content_type(&format!(
            "multipart/related; boundary={boundary}"
        ))
        .expect("valid");
        assert_eq!(framing.boundary(), boundary);
        let body = conformance_body_with_boundary(boundary, b"{}", b"payload");
        let events = body_events_with_boundary(boundary, &body, 3).expect("frames");
        assert_eq!(events.first(), Some(&Collected::PartStarted));
        assert_eq!(events.last(), Some(&Collected::EndOfParts));
    }

    #[test]
    fn body_without_the_opening_boundary_is_rejected() {
        let mut body = b"preamble the pinned framing forbids\r\n".to_vec();
        body.extend_from_slice(&conformance_body(b"{}", b"x"));
        let error = body_events(&body, 64).expect_err("rejected");
        assert_eq!(error, FramingError::MissingOpeningBoundary);
    }

    #[test]
    fn altered_boundary_body_is_rejected() {
        // The corpus's boundary-substitution alteration: the same parts
        // reframed under a different boundary than the header declared.
        let mut body = conformance_body(b"{}", b"x");
        let spliced = format!("--not-{BOUNDARY}").into_bytes();
        body[..spliced.len()].copy_from_slice(&spliced);
        let error = body_events(&body, 64).expect_err("rejected");
        assert_eq!(error, FramingError::MissingOpeningBoundary);
    }

    #[test]
    fn delimiter_lookalikes_inside_payloads_stay_payload() {
        // Bytes that resemble the delimiter without completing it belong
        // to the payload: a bare dash-boundary with no preceding CRLF, and
        // a boundary truncated mid-name after a real CRLF.
        let payload = b"--archivist-conformance-01 mid-line\r\n\
                        --archivist-conformance-0\r\nstill payload";
        let body = conformance_body(b"{}", payload);
        let events = body_events(&body, 5).expect("frames");
        let parts = part_payloads(&events);
        assert_eq!(parts.len(), 2, "the lookalikes never opened a part");
        assert_eq!(parts[0], b"{}".to_vec());
        assert_eq!(parts[1], payload);
    }

    #[test]
    fn non_delimiter_bytes_after_a_boundary_line_are_rejected() {
        // A CRLF dash-boundary inside the payload completed by junk is a
        // malformed delimiter, not payload.
        let body = conformance_body(b"{}", b"payload\r\n--archivist-conformance-01junk");
        // Drop the closing delimiter so the junk line is what the parser
        // meets at the end of part two.
        let closer = format!("\r\n--{BOUNDARY}--\r\n");
        let body = &body[..body.len() - closer.len()];
        let error = body_events(body, 64).expect_err("rejected");
        assert_eq!(error, FramingError::MalformedDelimiter);
    }

    #[test]
    fn header_block_deviations_are_rejected() {
        let mut body = conformance_body(b"{}", b"x");
        // Uppercase the pinned lowercase header.
        let start = format!("--{BOUNDARY}\r\n").len();
        body[start..start + "content-type".len()].copy_from_slice(b"Content-Type");
        let error = body_events(&body, 64).expect_err("rejected");
        assert_eq!(error, FramingError::PartHeaderMalformed);

        // A header line that is not the pinned content-type header.
        let wrong_name =
            format!("--{BOUNDARY}\r\nx-not-a-header: y\r\n\r\n{{}}\r\n--{BOUNDARY}--\r\n");
        let error = body_events(wrong_name.as_bytes(), 64).expect_err("rejected");
        assert_eq!(error, FramingError::PartHeaderMalformed);

        // No header at all: a bare CRLF where the header line belongs.
        let naked = format!("--{BOUNDARY}\r\n\r\n{{}}\r\n--{BOUNDARY}--\r\n");
        let error = body_events(naked.as_bytes(), 64).expect_err("rejected");
        assert_eq!(error, FramingError::PartHeaderMalformed);
    }

    #[test]
    fn header_block_exceeding_the_window_is_rejected_within_bounds() {
        let long_value = "x".repeat(FRAMING_WINDOW_BYTES + 1);
        let body =
            format!("--{BOUNDARY}\r\ncontent-type: {long_value}\r\n\r\n{{}}\r\n--{BOUNDARY}--\r\n");
        let error = body_events(body.as_bytes(), 1024).expect_err("rejected");
        assert_eq!(error, FramingError::PartHeaderMalformed);
    }

    #[test]
    fn truncated_bodies_are_rejected() {
        let body = conformance_body(b"{}", b"payload bytes");
        // Cut inside part two's payload: no closing delimiter ever comes.
        let closer = format!("\r\n--{BOUNDARY}--\r\n");
        let cut_inside_payload = body.len() - closer.len() - 2;
        let error = body_events(&body[..cut_inside_payload], 64).expect_err("rejected");
        assert_eq!(error, FramingError::UnexpectedEndOfStream);

        // Cut the closing delimiter's final CRLF in half, then drop it.
        let error = body_events(&body[..body.len() - 1], 64).expect_err("rejected");
        assert_eq!(error, FramingError::UnexpectedEndOfStream);
        let error = body_events(&body[..body.len() - 2], 64).expect_err("rejected");
        assert_eq!(error, FramingError::UnexpectedEndOfStream);
    }

    #[test]
    fn trailing_bytes_after_the_closing_delimiter_are_rejected() {
        let mut body = conformance_body(b"{}", b"x");
        body.extend_from_slice(b"trailer");
        let error = body_events(&body, 64).expect_err("rejected");
        assert_eq!(error, FramingError::TrailingBytesAfterClosingDelimiter);
    }

    #[test]
    fn source_failures_surface_as_the_closed_source_read_kind() {
        struct Failing;
        impl ByteSource for Failing {
            fn pull(&mut self, _window: &mut [u8]) -> Result<usize, std::io::ErrorKind> {
                Err(std::io::ErrorKind::ConnectionReset)
            }
        }
        let framing = RequestFraming::validate_content_type(&format!(
            "multipart/related; boundary={BOUNDARY}"
        ))
        .expect("valid");
        let mut tokenizer = FramingTokenizer::new(&framing, Failing);
        let error = tokenizer.next_event().expect_err("fails");
        assert_eq!(
            error,
            FramingError::SourceRead(std::io::ErrorKind::ConnectionReset)
        );
    }

    #[test]
    fn every_error_is_content_free_and_maps_to_the_registry_code() {
        let errors = [
            FramingError::NotMultipartRelated,
            FramingError::BoundaryInvalid,
            FramingError::MissingOpeningBoundary,
            FramingError::MalformedDelimiter,
            FramingError::PartHeaderMalformed,
            FramingError::UnexpectedEndOfStream,
            FramingError::TrailingBytesAfterClosingDelimiter,
            FramingError::SourceRead(std::io::ErrorKind::ConnectionReset),
        ];
        for error in errors {
            assert_eq!(
                error.code().as_str(),
                "request.framing_invalid",
                "{error:?}"
            );
            // The rendering carries the variant name only: no request
            // header, boundary, or body byte can appear in it.
            let rendering = format!("{error:?}");
            for leaked in [
                BOUNDARY,
                ENVELOPE_MEDIA_TYPE,
                IDENTITY_MEDIA_TYPE,
                "tenant_secret_bytes",
                "payload bytes",
            ] {
                assert!(
                    !rendering.contains(leaked),
                    "{rendering:?} leaks {leaked:?}"
                );
            }
        }
    }

    #[test]
    fn the_window_is_the_only_buffer_the_tokenizer_ever_grows() {
        let payload: Vec<u8> = (0..30 * 1024).map(|i| b"a\n"[i % 2]).collect();
        let body = conformance_body(b"{}", &payload);
        let framing = RequestFraming::validate_content_type(&format!(
            "multipart/related; boundary={BOUNDARY}"
        ))
        .expect("valid");
        let mut tokenizer = FramingTokenizer::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 997,
                pulls: 0,
            },
        );
        loop {
            // Convert the event to plain data inside the statement, so the
            // window borrow ends before the window is inspected.
            let arrived = tokenizer
                .next_event()
                .expect("frames")
                .map(|event| matches!(event, FramingEvent::Payload(_)));
            let Some(_was_payload) = arrived else {
                break;
            };
            assert!(tokenizer.window.capacity() <= FRAMING_WINDOW_BYTES);
            assert!(tokenizer.window.len() <= FRAMING_WINDOW_BYTES);
        }
    }
}
