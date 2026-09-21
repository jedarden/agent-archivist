// SPDX-License-Identifier: Apache-2.0

//! The two-part policy over the framing tokenizer (protocol Section 1.2;
//! plan Section 7.2).
//!
//! `POST /v1/ingest` carries exactly two parts: part one the canonical
//! envelope, part two the payload. [`TwoPartRequest`] turns the byte-level
//! [`crate::parse::framing::FramingTokenizer`] events into that policy:
//!
//! 1. [`TwoPartRequest::envelope`] consumes part one. The part's
//!    `content-type` header must be byte-exactly
//!    [`ENVELOPE_PART_MEDIA_TYPE`] — that is what identifies "the envelope
//!    part" and what enforces part order; a first part declaring anything
//!    else is rejected before any of its bytes are kept. The part's bytes
//!    accumulate up to the configured cap — the registry default
//!    [`crate::config::DEFAULT_ENVELOPE_MAX_BYTES`], overridable with
//!    [`TwoPartRequest::with_envelope_cap`] — and the run that would cross
//!    the cap is rejected with [`TwoPartError::EnvelopeExceedsCap`] at the
//!    cap: the accumulator stops there and no further body bytes are
//!    pulled, whatever the part actually contained. Canonical form (RFC
//!    8785) and the envelope schema stay with `archivist-protocol`'s
//!    envelope parser, which this layer feeds: the corpus scenario
//!    `valid-reordered-envelope-framing`, whose envelope part is
//!    transmitted non-canonically, still splits here.
//!
//! 2. [`TwoPartRequest::payload`] consumes the handle and hands back
//!    [`PayloadStream`], a [`std::io::Read`] over part two. Reads copy out
//!    of the tokenizer's fixed window plus at most one retained run, so
//!    memory is bounded by fixed buffers regardless of body size (VAL-008)
//!    — a multi-mebibyte payload streams through the same allocation a
//!    one-byte payload would. The part's transmitted `content-type` is
//!    exposed verbatim ([`PayloadStream::media_type`]) for the caller that
//!    checks it against the envelope's declared transport: comparing the
//!    two needs the parsed envelope, so it belongs to the pipeline above,
//!    not to framing.
//!
//! 3. [`PayloadStream::finish`] drains any unread payload and verifies the
//!    body closes exactly — the closing delimiter and nothing after it; a
//!    third part or trailing bytes is a part-order violation.
//!
//! Part-order violations (a payload part first, a body with no payload
//! part, a third part), cap overruns, and every underlying framing failure
//! are closed, content-free [`TwoPartError`] variants:
//! [`TwoPartError::code`] maps part order and framing shape to the
//! registry's `request.framing_invalid` and the cap overrun to
//! `envelope.size_exceeded`, and no variant can carry a byte of the request
//! (SEC-004; ERR-003).

use std::fmt;
use std::io;

use archivist_protocol::vocabulary::ErrorCode;

use super::framing::{ByteSource, FramingError, FramingEvent, FramingTokenizer, RequestFraming};
use crate::config::DEFAULT_ENVELOPE_MAX_BYTES;

/// Part one's pinned media type (`schemas/v1/ingest-request.json`
/// `partOneMediaType`; plan Section 7.2), byte-exact as the conformance
/// corpus transmits it and as the per-attempt signature covers it.
pub const ENVELOPE_PART_MEDIA_TYPE: &str =
    "application/vnd.agent-archivist.envelope+json;version=1";

/// Why the pinned two-part split cannot proceed.
///
/// Every variant is a closed, content-free token: the error names the part
/// stage that failed and carries nothing derived from the request, so no
/// rendering of it can echo a media type, a boundary, or a body byte
/// (SEC-004; ERR-003).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TwoPartError {
    /// The body's first part declares a media type other than the pinned
    /// envelope type ([`ENVELOPE_PART_MEDIA_TYPE`]): it is not the envelope
    /// part, so the pinned part order is already violated.
    EnvelopeNotFirst,
    /// The envelope part crossed the configured canonical-envelope cap.
    /// `limit_bytes` is the server's configured cap — a configuration
    /// value, never request content.
    EnvelopeExceedsCap {
        /// The cap that was exceeded, in bytes.
        limit_bytes: u64,
    },
    /// The body closed after the envelope part: the pinned framing needs a
    /// second part, and none followed.
    PayloadPartMissing,
    /// A third part, or bytes past the closing delimiter: the pinned
    /// framing is exactly two parts.
    TrailingPart,
    /// The underlying body framing failed; the wrapped variant names the
    /// stage. Content-free like every
    /// [`FramingError`](crate::parse::framing::FramingError).
    Framing(FramingError),
}

impl From<FramingError> for TwoPartError {
    fn from(error: FramingError) -> Self {
        Self::Framing(error)
    }
}

impl TwoPartError {
    /// The stable wire code for this failure: the cap overrun is
    /// `envelope.size_exceeded`, every part-order and framing shape
    /// failure `request.framing_invalid`; the typed variant distinguishes
    /// stages for logs and tests, never the wire body.
    ///
    /// # Panics
    /// Never in practice: both literals below match the registry grammar
    /// pinned by `tools/check-error-codes.py`, so a panic is a programming
    /// error introduced alongside this match, not a wire condition.
    #[must_use]
    pub fn code(self) -> ErrorCode {
        match self {
            Self::EnvelopeExceedsCap { .. } => ErrorCode::parse("envelope.size_exceeded"),
            Self::EnvelopeNotFirst
            | Self::PayloadPartMissing
            | Self::TrailingPart
            | Self::Framing(_) => ErrorCode::parse("request.framing_invalid"),
        }
        .expect("the two-part error codes match the registry grammar")
    }
}

/// The pinned two-part split of a `multipart/related` request body.
///
/// Constructed only from a validated
/// [`RequestFraming`](crate::parse::framing::RequestFraming) plus a
/// [`ByteSource`]; consumed in order — [`TwoPartRequest::envelope`] for
/// part one, then [`TwoPartRequest::payload`] for part two. Pulls nothing:
/// the first [`TwoPartRequest::envelope`] call reads the first body byte.
pub struct TwoPartRequest<S: ByteSource> {
    tokenizer: FramingTokenizer<S>,
    envelope_cap: u64,
}

impl<S: ByteSource> TwoPartRequest<S> {
    /// Split the body framed under the validated `framing`, reading
    /// through `source`, with the registry default envelope cap
    /// ([`DEFAULT_ENVELOPE_MAX_BYTES`]).
    #[must_use]
    pub fn new(framing: &RequestFraming, source: S) -> Self {
        Self::with_envelope_cap(framing, source, DEFAULT_ENVELOPE_MAX_BYTES)
    }

    /// Like [`TwoPartRequest::new`], with an explicit canonical-envelope
    /// cap in bytes — the validated `server.envelope_max_bytes` the
    /// configuration builder carries.
    #[must_use]
    pub fn with_envelope_cap(framing: &RequestFraming, source: S, envelope_cap: u64) -> Self {
        Self {
            tokenizer: FramingTokenizer::new(framing, source),
            envelope_cap,
        }
    }

    /// Consume part one: the envelope part's bytes, exactly as transmitted.
    ///
    /// The part's media type must be exactly byte-for-byte
    /// [`ENVELOPE_PART_MEDIA_TYPE`] ([`TwoPartError::EnvelopeNotFirst`]
    /// otherwise), and its byte count must fit the configured cap —
    /// [`TwoPartError::EnvelopeExceedsCap`] fires at the run that crosses
    /// it, before the crossing bytes are kept and before any further body
    /// byte is read. The bytes are returned as transmitted: canonical-form
    /// and schema validation belong to the envelope parser above this
    /// layer, so an envelope part transmitted non-canonically still splits
    /// and is judged downstream.
    ///
    /// The handle is single-use per phase: once this returns, the next
    /// call is [`TwoPartRequest::payload`].
    ///
    /// # Errors
    /// The first [`TwoPartError`] the split meets.
    pub fn envelope(&mut self) -> Result<Vec<u8>, TwoPartError> {
        match self.tokenizer.next_event()? {
            Some(FramingEvent::PartStarted) => {}
            // Every well-formed body opens with a part boundary; anything
            // else the tokenizer can yield here is the delimiter stage
            // failing.
            Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
            None => return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream)),
        }
        match self.tokenizer.next_event()? {
            Some(FramingEvent::PartContentType(media_type))
                if media_type == ENVELOPE_PART_MEDIA_TYPE => {}
            // A first part declaring anything else is not the envelope
            // part — the violation stands wherever the body put it.
            Some(FramingEvent::PartContentType(_)) => return Err(TwoPartError::EnvelopeNotFirst),
            Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
            None => return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream)),
        }
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            match self.tokenizer.next_event()? {
                Some(FramingEvent::Payload(run)) => {
                    // Reject at the cap: the crossing run is not kept and
                    // no further event — no further source byte — is
                    // pulled.
                    if bytes.len() as u64 + run.len() as u64 > self.envelope_cap {
                        return Err(TwoPartError::EnvelopeExceedsCap {
                            limit_bytes: self.envelope_cap,
                        });
                    }
                    bytes.extend_from_slice(run);
                }
                Some(FramingEvent::PartEnded) => return Ok(bytes),
                Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
                None => return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream)),
            }
        }
    }

    /// Consume the handle: part two, the payload, as a streaming reader.
    ///
    /// The part's transmitted media type is exposed on the returned
    /// [`PayloadStream`]; whether it matches the envelope's declared
    /// transport is the pipeline's check, not a framing one.
    ///
    /// # Errors
    /// [`TwoPartError::PayloadPartMissing`] when the body closed after the
    /// envelope part; [`TwoPartError::Framing`] when the body framing
    /// failed first.
    pub fn payload(mut self) -> Result<PayloadStream<S>, TwoPartError> {
        match self.tokenizer.next_event()? {
            Some(FramingEvent::PartStarted) => {}
            Some(FramingEvent::EndOfParts) => return Err(TwoPartError::PayloadPartMissing),
            Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
            None => return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream)),
        }
        let media_type = match self.tokenizer.next_event()? {
            Some(FramingEvent::PartContentType(media_type)) => media_type.to_owned(),
            Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
            None => return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream)),
        };
        Ok(PayloadStream {
            tokenizer: self.tokenizer,
            remainder: Vec::new(),
            remainder_pos: 0,
            media_type,
            ended: false,
        })
    }
}

/// The streaming reader over part two of the pinned two-part split.
///
/// Reads copy out of the framing window plus at most one retained run
/// tail, so buffering is fixed ([`PayloadStream::buffered_bytes`]) for any
/// body size (VAL-008). When a read returns `Ok(0)`, part two's delimiter
/// has been consumed; [`PayloadStream::finish`] then verifies the body
/// closes exactly. Dropping the stream without finishing abandons the
/// body — the caller's deadline and connection layers own that path.
pub struct PayloadStream<S: ByteSource> {
    tokenizer: FramingTokenizer<S>,
    /// The unread tail of the last payload run, when a read copied less
    /// than the run held. Bounded by one framing-window run.
    remainder: Vec<u8>,
    /// The read offset into `remainder`.
    remainder_pos: usize,
    media_type: String,
    /// Whether part two's delimiter has been consumed (reads returned
    /// end-of-part).
    ended: bool,
}

impl<S: ByteSource> fmt::Debug for PayloadStream<S> {
    /// A structural rendering: buffered byte counts and stream position
    /// only. Hand-written rather than derived because the stream's state
    /// includes retained request bytes and its transmitted media type —
    /// content a log line must never echo (SEC-004), so nothing
    /// request-derived appears in the output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PayloadStream")
            .field("buffered_bytes", &self.buffered_bytes())
            .field("ended", &self.ended)
            .finish_non_exhaustive()
    }
}

impl<S: ByteSource> PayloadStream<S> {
    /// Part two's `content-type` header value, exactly as transmitted.
    #[must_use]
    pub fn media_type(&self) -> &str {
        &self.media_type
    }

    /// Body bytes currently held across the framing window and the
    /// retained run tail.
    ///
    /// At most twice
    /// [`FRAMING_WINDOW_BYTES`](crate::parse::framing::FRAMING_WINDOW_BYTES),
    /// whatever the body weighs — the observable half of the fixed-buffer
    /// streaming property (VAL-008).
    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.tokenizer.window_len() + self.remainder.len() - self.remainder_pos
    }

    /// Drain any unread payload bytes and verify the body closes exactly:
    /// the closing delimiter of the pinned framing, and nothing after it.
    ///
    /// Unread payload bytes are streamed through the framing window and
    /// discarded — never buffered.
    ///
    /// # Errors
    /// [`TwoPartError::TrailingPart`] when a third part or trailing bytes
    /// follow the payload part; [`TwoPartError::Framing`] when the closing
    /// framing itself is malformed or truncated.
    pub fn finish(mut self) -> Result<(), TwoPartError> {
        if !self.ended {
            loop {
                match self.tokenizer.next_event()? {
                    Some(FramingEvent::Payload(_)) => {}
                    Some(FramingEvent::PartEnded) => break,
                    Some(_) => return Err(TwoPartError::Framing(FramingError::MalformedDelimiter)),
                    None => {
                        return Err(TwoPartError::Framing(FramingError::UnexpectedEndOfStream));
                    }
                }
            }
        }
        match self.tokenizer.next_event()? {
            Some(FramingEvent::EndOfParts) => {}
            // A third part began where only the closing delimiter may
            // follow: a part-order violation.
            Some(FramingEvent::PartStarted | FramingEvent::PartContentType(_)) => {
                return Err(TwoPartError::TrailingPart);
            }
            // The tokenizer cannot yield a payload run or a second part end
            // past the one that closed part two; treat it as the delimiter
            // stage failing.
            Some(FramingEvent::Payload(_) | FramingEvent::PartEnded) | None => {
                return Err(TwoPartError::Framing(FramingError::MalformedDelimiter));
            }
        }
        match self.tokenizer.next_event()? {
            None => Ok(()),
            Some(_) => Err(TwoPartError::TrailingPart),
        }
    }
}

impl<S: ByteSource> io::Read for PayloadStream<S> {
    /// Copy the next payload bytes into `buf`.
    ///
    /// Returns `Ok(0)` once part two's delimiter has been consumed — the
    /// caller then verifies closure with [`PayloadStream::finish`]. Each
    /// read returns at most one framing-window run, independent of how
    /// large `buf` is.
    ///
    /// # Errors
    /// Closed [`io::ErrorKind`] values only — `UnexpectedEof` when the
    /// body ends mid-payload, the source's own kind on source failure,
    /// `InvalidData` for any other framing violation — so no rendering of
    /// the error can carry request bytes.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.ended {
            return Ok(0);
        }
        if self.remainder_pos < self.remainder.len() {
            let unread = self.remainder[self.remainder_pos..].len();
            let n = unread.min(buf.len());
            buf[..n].copy_from_slice(&self.remainder[self.remainder_pos..][..n]);
            self.remainder_pos += n;
            return Ok(n);
        }
        loop {
            match self.tokenizer.next_event() {
                Ok(Some(FramingEvent::Payload(run))) => {
                    // A part ending flushes a final empty run; it is not
                    // end-of-part.
                    if run.is_empty() {
                        continue;
                    }
                    let n = run.len().min(buf.len());
                    buf[..n].copy_from_slice(&run[..n]);
                    if n < run.len() {
                        self.remainder.clear();
                        self.remainder.extend_from_slice(&run[n..]);
                        self.remainder_pos = 0;
                    }
                    return Ok(n);
                }
                Ok(Some(FramingEvent::PartEnded)) => {
                    self.ended = true;
                    return Ok(0);
                }
                // No other event exists between a part's header and its
                // end; skip defensively rather than panic on a stream.
                Ok(Some(_)) => {}
                Ok(None) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                Err(FramingError::SourceRead(kind)) => return Err(io::Error::from(kind)),
                Err(FramingError::UnexpectedEndOfStream) => {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                Err(_) => return Err(io::Error::from(io::ErrorKind::InvalidData)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::io::Read;
    use std::path::{Path, PathBuf};

    use archivist_protocol::json::{self, Object, Value};

    use super::{
        ByteSource, DEFAULT_ENVELOPE_MAX_BYTES, ENVELOPE_PART_MEDIA_TYPE, FramingError,
        RequestFraming, TwoPartError, TwoPartRequest,
    };
    use crate::parse::framing::FRAMING_WINDOW_BYTES;

    /// The boundary the conformance corpus pins for the valid-direct
    /// baseline scenario.
    const BOUNDARY: &str = "archivist-conformance-01";
    /// Part two's media type under the identity transport the v1 vectors pin.
    const IDENTITY_MEDIA_TYPE: &str = "application/octet-stream";

    /// A body framed exactly as the conformance corpus pins: one lowercase
    /// `content-type` header per part, blank line, part bytes, CRLF, parts
    /// repeated in order, closing dash-boundary dashes CRLF.
    fn framed_body(parts: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (media_type, bytes) in parts {
            body.extend_from_slice(
                format!("--{BOUNDARY}\r\ncontent-type: {media_type}\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(bytes);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());
        body
    }

    fn request_framing() -> RequestFraming {
        RequestFraming::validate_content_type(&format!("multipart/related; boundary={BOUNDARY}"))
            .expect("valid content type")
    }

    /// A source handing out at most `chunk` bytes per pull, so tests can
    /// drive the split through arbitrary refill edges.
    struct Chunked<'a> {
        body: &'a [u8],
        chunk: usize,
    }

    impl ByteSource for Chunked<'_> {
        fn pull(&mut self, window: &mut [u8]) -> Result<usize, std::io::ErrorKind> {
            let n = window.len().min(self.chunk).min(self.body.len());
            window[..n].copy_from_slice(&self.body[..n]);
            self.body = &self.body[n..];
            Ok(n)
        }
    }

    /// A counting [`Chunked`]: the shared cell records every pull, so a
    /// test can prove the split stopped pulling.
    struct Counting<'a> {
        body: &'a [u8],
        chunk: usize,
        pulls: std::rc::Rc<Cell<usize>>,
    }

    impl ByteSource for Counting<'_> {
        fn pull(&mut self, window: &mut [u8]) -> Result<usize, std::io::ErrorKind> {
            self.pulls.set(self.pulls.get() + 1);
            let n = window.len().min(self.chunk).min(self.body.len());
            window[..n].copy_from_slice(&self.body[..n]);
            self.body = &self.body[n..];
            Ok(n)
        }
    }

    /// A source that serves until `fail_after` bytes have crossed, then
    /// fails, so tests can drive a mid-payload source failure.
    struct FailingAfter<'a> {
        body: &'a [u8],
        chunk: usize,
        served: usize,
        fail_after: usize,
    }

    impl ByteSource for FailingAfter<'_> {
        fn pull(&mut self, window: &mut [u8]) -> Result<usize, std::io::ErrorKind> {
            if self.served >= self.fail_after {
                return Err(std::io::ErrorKind::ConnectionReset);
            }
            let n = window.len().min(self.chunk).min(self.body.len());
            window[..n].copy_from_slice(&self.body[..n]);
            self.body = &self.body[n..];
            self.served += n;
            Ok(n)
        }
    }

    /// The conformance corpus directory, reached the way every corpus
    /// test reaches it: relative to this crate's manifest.
    fn corpus_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../schemas/v1/examples/conformance")
    }

    /// One corpus manifest member's path text.
    fn json_text<'a>(value: &'a Value, name: &str) -> Option<&'a str> {
        let Value::Object(object) = value else {
            return None;
        };
        match object.get(name) {
            Some(Value::Text(text)) => Some(text),
            _ => None,
        }
    }

    /// One corpus manifest member's object value.
    fn json_object<'a>(value: &'a Value, name: &str) -> Option<&'a Object> {
        let Value::Object(object) = value else {
            return None;
        };
        match object.get(name) {
            Some(Value::Object(inner)) => Some(inner),
            _ => None,
        }
    }

    /// Read one scenario file the manifest names.
    fn corpus_file(dir: &Path, id: &str, files: &Object, name: &str) -> Vec<u8> {
        let Some(Value::Text(relative)) = files.get(name) else {
            panic!("{id}: manifest files.{name} is a path");
        };
        fs::read(dir.join(relative)).unwrap_or_else(|error| panic!("{id}: {relative}: {error}"))
    }

    /// The manifest's scenario entries: `manifest.json` is an object whose
    /// `scenarios` member is the array the generator writes.
    fn corpus_scenarios(manifest: &Value) -> &[Value] {
        let Value::Object(object) = manifest else {
            panic!("manifest.json is an object");
        };
        match object.get("scenarios") {
            Some(Value::Array(scenarios)) => scenarios,
            other => panic!("manifest.json scenarios is an array, found {other:?}"),
        }
    }

    /// One scenario's framing, body, and pinned part bytes, walked from
    /// the manifest the generator writes.
    fn corpus_scenario(id: &str) -> (RequestFraming, Vec<u8>, Vec<u8>, Vec<u8>) {
        let dir = corpus_dir();
        let manifest_bytes = fs::read(dir.join("manifest.json")).expect("manifest.json reads");
        let manifest = json::parse(&manifest_bytes).expect("manifest.json parses");
        let scenarios = corpus_scenarios(&manifest);
        let scenario = scenarios
            .iter()
            .find(|scenario| json_text(scenario, "id") == Some(id))
            .unwrap_or_else(|| panic!("{id} is in the corpus manifest"));
        let files = json_object(scenario, "files").unwrap_or_else(|| panic!("{id}: files"));
        let attempt_bytes = corpus_file(&dir, id, files, "attempt");
        let attempt = json::parse(&attempt_bytes).expect("attempt parses");
        let content_type = json_text(&attempt, "content_type")
            .unwrap_or_else(|| panic!("{id}: attempt.content_type"));
        let framing = RequestFraming::validate_content_type(content_type)
            .unwrap_or_else(|error| panic!("{id}: {content_type}: {error:?}"));
        let body = corpus_file(&dir, id, files, "request_body");
        let envelope = corpus_file(&dir, id, files, "envelope");
        let payload = corpus_file(&dir, id, files, "payload");
        (framing, body, envelope, payload)
    }

    /// Split one well-formed corpus body and assert both parts match the
    /// pinned files byte for byte. `buffer` is the caller-side read size,
    /// so the payload stream's run-tail retention is exercised too.
    fn assert_corpus_body_splits(
        id: &str,
        framing: &RequestFraming,
        body: &[u8],
        envelope_file: &[u8],
        payload_file: &[u8],
        chunk: usize,
        buffer: usize,
    ) {
        let mut request = TwoPartRequest::new(framing, Chunked { body, chunk });
        let envelope = request
            .envelope()
            .unwrap_or_else(|error| panic!("{id}: envelope part: {error:?}"));
        assert_eq!(envelope, envelope_file, "{id}: part one at chunk {chunk}");
        let mut stream = request
            .payload()
            .unwrap_or_else(|error| panic!("{id}: payload part: {error:?}"));
        assert_eq!(
            stream.media_type(),
            IDENTITY_MEDIA_TYPE,
            "{id} at chunk {chunk}"
        );
        let mut payload = Vec::new();
        let mut buffer = vec![0u8; buffer];
        loop {
            let n = stream
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("{id}: payload streams: {error}"));
            if n == 0 {
                break;
            }
            payload.extend_from_slice(&buffer[..n]);
        }
        stream
            .finish()
            .unwrap_or_else(|error| panic!("{id}: closes: {error:?}"));
        assert_eq!(payload, payload_file, "{id}: part two at chunk {chunk}");
    }

    #[test]
    fn every_conformance_corpus_body_splits_into_the_pinned_two_parts() {
        let dir = corpus_dir();
        let manifest_bytes = fs::read(dir.join("manifest.json")).expect("manifest.json reads");
        let manifest = json::parse(&manifest_bytes).expect("manifest.json parses");
        let scenarios = corpus_scenarios(&manifest);
        assert!(
            scenarios.len() >= 15,
            "the corpus carries its full scenario set, found {}",
            scenarios.len()
        );
        for scenario in scenarios {
            let id = json_text(scenario, "id").expect("scenario id").to_owned();
            let (framing, body, envelope_file, payload_file) = corpus_scenario(&id);
            if id == "invalid-altered-framing-boundary" {
                // The body's delimiter lines were cut under a longer
                // boundary than the signed header declares: the opening
                // line matches the declared dash-boundary's prefix but
                // extends past it, so the delimiter itself is malformed
                // — at any refill pattern, before any part exists.
                for chunk in [usize::MAX, 1] {
                    let mut request = TwoPartRequest::new(&framing, Chunked { body: &body, chunk });
                    let error = request
                        .envelope()
                        .expect_err("the boundary alteration never frames");
                    assert_eq!(
                        error,
                        TwoPartError::Framing(FramingError::MalformedDelimiter),
                        "{id} at chunk {chunk}"
                    );
                }
                continue;
            }
            for (chunk, buffer) in [(usize::MAX, 8192), (1, 33)] {
                assert_corpus_body_splits(
                    &id,
                    &framing,
                    &body,
                    &envelope_file,
                    &payload_file,
                    chunk,
                    buffer,
                );
            }
        }
    }

    #[test]
    fn the_reordered_envelope_scenario_splits_despite_non_canonical_part_bytes() {
        // Part order is a framing property; envelope canonical form is the
        // envelope parser's. The corpus transmits this scenario's envelope
        // part reverse-sorted and indented, and the split must still
        // hand the exact bytes through.
        let (framing, body, envelope_file, payload_file) =
            corpus_scenario("valid-reordered-envelope-framing");
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 7,
            },
        );
        let envelope = request.envelope().expect("the reordered part splits");
        assert_eq!(envelope, envelope_file);
        let parsed = json::parse(&envelope).expect("the part is still protocol JSON");
        assert_ne!(
            parsed.canonical_bytes(),
            envelope,
            "the scenario is the corpus's deliberate non-canonical one"
        );
        let mut stream = request.payload().expect("payload part");
        let mut drained = Vec::new();
        stream.read_to_end(&mut drained).expect("streams");
        stream.finish().expect("closes");
        assert_eq!(drained, payload_file);
    }

    #[test]
    fn an_envelope_part_crossing_the_cap_is_rejected_at_the_cap_before_further_reads() {
        let cap = usize::try_from(DEFAULT_ENVELOPE_MAX_BYTES).expect("cap fits usize");
        // Part one carries just over the cap; part two is multi-MiB, so a
        // split that kept reading would need hundreds of window pulls.
        let envelope = vec![b'e'; cap + 16];
        let padding = vec![b'p'; 4 * 1024 * 1024];
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, &envelope),
            (IDENTITY_MEDIA_TYPE, &padding),
        ]);
        let framing = request_framing();
        let pulls = std::rc::Rc::new(Cell::new(0usize));
        let mut request = TwoPartRequest::new(
            &framing,
            Counting {
                body: &body,
                chunk: FRAMING_WINDOW_BYTES,
                pulls: std::rc::Rc::clone(&pulls),
            },
        );
        let error = request.envelope().expect_err("the part crosses the cap");
        assert_eq!(
            error,
            TwoPartError::EnvelopeExceedsCap {
                limit_bytes: DEFAULT_ENVELOPE_MAX_BYTES
            }
        );
        assert_eq!(error.code().as_str(), "envelope.size_exceeded");
        // Rejection happened within a window or two of the cap: about one
        // pull per window the cap spans, versus the hundreds a full read
        // of the padded body would need.
        let cap_windows = (cap + 2 * FRAMING_WINDOW_BYTES) / FRAMING_WINDOW_BYTES;
        assert!(
            pulls.get() <= cap_windows,
            "the split kept reading past the cap: {} pulls",
            pulls.get()
        );
    }

    #[test]
    fn the_configured_cap_bounds_the_envelope_part_exactly() {
        // At the cap the part is kept; one byte over it is not.
        for (envelope_len, fits) in [(15, true), (16, true), (17, false)] {
            let envelope = vec![b'e'; envelope_len];
            let body = framed_body(&[
                (ENVELOPE_PART_MEDIA_TYPE, &envelope),
                (IDENTITY_MEDIA_TYPE, b"x"),
            ]);
            let framing = request_framing();
            let mut request = TwoPartRequest::with_envelope_cap(&framing, &body[..], 16);
            match request.envelope() {
                Ok(bytes) => {
                    assert!(fits, "{envelope_len} bytes fits a 16-byte cap");
                    assert_eq!(bytes.len(), envelope_len);
                }
                Err(TwoPartError::EnvelopeExceedsCap { limit_bytes }) => {
                    assert!(!fits, "{envelope_len} bytes exceeds a 16-byte cap");
                    assert_eq!(limit_bytes, 16);
                }
                Err(error) => panic!("unexpected {error:?} at {envelope_len} bytes"),
            }
        }
    }

    #[test]
    fn part_order_violations_are_rejected() {
        let framing = request_framing();

        // The payload part first: part one is not the envelope part.
        let body = framed_body(&[
            (IDENTITY_MEDIA_TYPE, b"payload bytes"),
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
        ]);
        let mut request = TwoPartRequest::new(&framing, &body[..]);
        assert_eq!(
            request.envelope().expect_err("payload first"),
            TwoPartError::EnvelopeNotFirst
        );

        // A first part that is neither pinned media type.
        let body = framed_body(&[
            ("application/json", b"{}"),
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
        ]);
        let mut request = TwoPartRequest::new(&framing, &body[..]);
        assert_eq!(
            request.envelope().expect_err("wrong media type"),
            TwoPartError::EnvelopeNotFirst
        );

        // The body closes after the envelope part: no payload part.
        let body = framed_body(&[(ENVELOPE_PART_MEDIA_TYPE, b"{}")]);
        let mut request = TwoPartRequest::new(&framing, &body[..]);
        let envelope = request.envelope().expect("the envelope part splits");
        assert_eq!(envelope, b"{}");
        assert_eq!(
            request.payload().expect_err("no second part"),
            TwoPartError::PayloadPartMissing
        );

        // A third part: rejected at finish, after the payload streams.
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, b"payload"),
            (IDENTITY_MEDIA_TYPE, b"extra"),
        ]);
        let mut request = TwoPartRequest::new(&framing, &body[..]);
        request.envelope().expect("envelope");
        let stream = request.payload().expect("payload");
        assert_eq!(
            stream.finish().expect_err("a third part follows"),
            TwoPartError::TrailingPart
        );
    }

    #[test]
    fn finish_drains_unread_payload_and_verifies_exact_closure() {
        let payload = vec![b'r'; 50 * 1024];
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, &payload),
        ]);
        let framing = request_framing();
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 511,
            },
        );
        request.envelope().expect("envelope");
        // Nothing was read: finish streams the payload through the window
        // and discards it, then accepts the clean closing delimiter.
        request
            .payload()
            .expect("payload")
            .finish()
            .expect("closes");

        // Bytes after the closing delimiter are a framing failure.
        let mut trailing = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, b"payload"),
        ]);
        trailing.extend_from_slice(b"trailer");
        let mut request = TwoPartRequest::new(&framing, &trailing[..]);
        request.envelope().expect("envelope");
        let stream = request.payload().expect("payload");
        assert_eq!(
            stream.finish().expect_err("trailing bytes"),
            TwoPartError::Framing(FramingError::TrailingBytesAfterClosingDelimiter)
        );
    }

    #[test]
    fn a_multi_mib_payload_streams_within_fixed_buffers() {
        let line = b"archivist streaming payload line 0123456789\n";
        let payload: Vec<u8> = (0..4 * 1024 * 1024).map(|i| line[i % line.len()]).collect();
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{\"protocol_version\":1}"),
            (IDENTITY_MEDIA_TYPE, &payload),
        ]);
        let framing = request_framing();
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 997,
            },
        );
        let envelope = request.envelope().expect("envelope");
        assert_eq!(envelope, b"{\"protocol_version\":1}");
        let mut stream = request.payload().expect("payload part");
        let mut buffer = [0u8; 1024];
        let mut streamed = 0usize;
        loop {
            assert!(
                stream.buffered_bytes() <= 2 * FRAMING_WINDOW_BYTES,
                "{} body bytes held for a {}-byte payload",
                stream.buffered_bytes(),
                payload.len()
            );
            let n = stream.read(&mut buffer).expect("streams");
            if n == 0 {
                break;
            }
            assert_eq!(
                &buffer[..n],
                &payload[streamed..streamed + n],
                "stream order preserved at byte {streamed}"
            );
            streamed += n;
        }
        assert_eq!(streamed, payload.len(), "the whole payload streams");
        stream.finish().expect("closes");
    }

    #[test]
    fn byte_at_a_time_refills_stream_a_quarter_mib_payload() {
        let payload: Vec<u8> = (0..256 * 1024).map(|i| b"ab\n"[i % 3]).collect();
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, &payload),
        ]);
        let framing = request_framing();
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 1,
            },
        );
        request.envelope().expect("envelope");
        let mut stream = request.payload().expect("payload part");
        let mut streamed = Vec::new();
        let mut one = [0u8; 1];
        loop {
            let n = stream.read(&mut one).expect("streams");
            if n == 0 {
                break;
            }
            streamed.push(one[0]);
        }
        assert_eq!(streamed, payload);
        stream.finish().expect("closes");
    }

    #[test]
    fn read_surfaces_closed_kinds_only() {
        let framing = request_framing();

        // A body cut mid-payload: the read reports UnexpectedEof.
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, b"payload bytes"),
        ]);
        let cut = body.len() - 10;
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body[..cut],
                chunk: 64,
            },
        );
        request.envelope().expect("envelope");
        let mut stream = request.payload().expect("payload part");
        let mut buffer = [0u8; 4];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => panic!("the truncated body never reaches end of part"),
                Ok(_) => {}
                Err(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
                    break;
                }
            }
        }
        // The truncation is not end-of-part — no delimiter was seen — so
        // the end-of-part zero the doc pins never arrives: the closed
        // error repeats, and `finish` remains the caller's way out.
        assert_eq!(
            stream
                .read(&mut buffer)
                .expect_err("still truncated")
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );

        // A source failing mid-payload: the read reports the source's own
        // closed kind. The framing before part two's payload is under 200
        // bytes of this body shape, so a 400-byte budget fails inside
        // part two; runs pulled before the failure stream out first, and
        // the error surfaces once the retained window is drained.
        let long = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, &vec![b'x'; 4096]),
        ]);
        let mut request = TwoPartRequest::new(
            &framing,
            FailingAfter {
                body: &long,
                chunk: 50,
                served: 0,
                fail_after: 400,
            },
        );
        request.envelope().expect("envelope");
        let mut stream = request.payload().expect("payload part");
        let mut served_before_failure = 0usize;
        let mut reads = 0usize;
        loop {
            reads += 1;
            assert!(reads <= 100, "the source failure never surfaced");
            match stream.read(&mut buffer) {
                Ok(n) => served_before_failure += n,
                Err(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
                    break;
                }
            }
        }
        assert!(
            served_before_failure > 0 && served_before_failure < 4096,
            "{served_before_failure} payload bytes crossed before the failure"
        );
    }

    #[test]
    fn every_two_part_error_is_content_free_and_maps_to_the_registry_code() {
        let errors = [
            TwoPartError::EnvelopeNotFirst,
            TwoPartError::EnvelopeExceedsCap {
                limit_bytes: DEFAULT_ENVELOPE_MAX_BYTES,
            },
            TwoPartError::PayloadPartMissing,
            TwoPartError::TrailingPart,
            TwoPartError::Framing(FramingError::MalformedDelimiter),
            TwoPartError::Framing(FramingError::SourceRead(
                std::io::ErrorKind::ConnectionReset,
            )),
        ];
        for error in errors {
            let rendering = format!("{error:?}");
            for leaked in [
                BOUNDARY,
                ENVELOPE_PART_MEDIA_TYPE,
                IDENTITY_MEDIA_TYPE,
                "payload bytes",
                "tenant_secret_bytes",
            ] {
                assert!(
                    !rendering.contains(leaked),
                    "{rendering:?} leaks {leaked:?}"
                );
            }
            let expected = match error {
                TwoPartError::EnvelopeExceedsCap { .. } => "envelope.size_exceeded",
                _ => "request.framing_invalid",
            };
            assert_eq!(error.code().as_str(), expected, "{error:?}");
        }
    }

    #[test]
    fn an_empty_envelope_part_splits_to_empty_bytes() {
        // The framing layer is mute about content: a zero-byte part one
        // splits to zero bytes and the envelope parser judges it.
        let body = framed_body(&[(ENVELOPE_PART_MEDIA_TYPE, b""), (IDENTITY_MEDIA_TYPE, b"x")]);
        let framing = request_framing();
        let mut request = TwoPartRequest::new(&framing, &body[..]);
        let envelope = request.envelope().expect("the empty part splits");
        assert!(envelope.is_empty());
        let stream = request.payload().expect("payload part");
        assert_eq!(stream.media_type(), IDENTITY_MEDIA_TYPE);
        stream.finish().expect("closes");
    }

    #[test]
    fn the_payload_handle_reports_the_bound_across_a_window_edge() {
        // A payload a little over one window: at least one run tail is
        // retained across reads, and the bound still holds.
        let payload = vec![b's'; FRAMING_WINDOW_BYTES + 100];
        let body = framed_body(&[
            (ENVELOPE_PART_MEDIA_TYPE, b"{}"),
            (IDENTITY_MEDIA_TYPE, &payload),
        ]);
        let framing = request_framing();
        let mut request = TwoPartRequest::new(
            &framing,
            Chunked {
                body: &body,
                chunk: 4096,
            },
        );
        request.envelope().expect("envelope");
        let mut stream = request.payload().expect("payload part");
        let mut buffer = [0u8; 17];
        let mut streamed = 0usize;
        loop {
            assert!(stream.buffered_bytes() <= 2 * FRAMING_WINDOW_BYTES);
            let n = stream.read(&mut buffer).expect("streams");
            if n == 0 {
                break;
            }
            streamed += n;
        }
        assert_eq!(streamed, payload.len());
        stream.finish().expect("closes");
    }
}
