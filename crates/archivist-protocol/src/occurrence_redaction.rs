// SPDX-License-Identifier: Apache-2.0

//! The per-occurrence `redaction-v1` transformation (plan Phase 10; the
//! second stage of the derived-episode pipeline after the policy seam):
//! the pure function from one validated, supported raw occurrence, through
//! the pinned allowlist and the ordered detector registry
//! ([`crate::redaction_policy`]), to the redacted occurrence data and typed
//! irreversible markers the episode-composition stage later assembles into
//! a canonical episode.
//!
//! Ownership sits here by the layering rules
//! ([docs/notes/crate-ownership.md], boundary rule 8): the redacted
//! record's shape, its censuses, and the replacement extents are layer-0
//! wire material — the episode schema's `records` entries are exactly what
//! this module produces — so the transformation core is a pure function of
//! this crate. Reading harness-specific raw bytes is the adapter
//! projections' job: they hand this module a [`SourceRecord`], and the
//! keyed pseudonym rendering stays outside on purpose — the composition
//! stage supplies the tenant-HMAC renderer ([`PSEUDONYM_FORMAT`] pins its
//! output shape), so no key material ever enters this module.
//!
//! # The transformation contract
//!
//! 1. **Validate, fail closed.** The record's structured fields are
//!    checked against the episode schema's shapes in a fixed first-fault
//!    order (domain bounds, then semantic shape). Anything the pipeline
//!    cannot vouch for — a role token outside the closed four-role set, a
//!    `source_time` off the shared UTC shape, a parent-ordinal that points
//!    forward or repeats, any bound exceeded — is a [`RedactionGap`], never
//!    a best-effort copy. A gap carries no payload at all: the caller gets
//!    a reason class and nothing else, so no episode material exists to
//!    leak from an unsupported record.
//! 2. **Project through the allowlist.** Exactly the pinned structured
//!    fields ([`StructuredField`]: role, ordinal, source time, parent
//!    ordinals) survive; everything else of the source record is dropped
//!    by construction, because [`RedactedOccurrence`] has nowhere else to
//!    put it.
//! 3. **Apply the registry in pinned order.** Each detector of
//!    [`RedactionCorpus::detectors`] runs in ascending `order` over the
//!    text that earlier detectors have not already claimed; the first
//!    detector whose pattern matches a region decides its treatment, and a
//!    claimed region is opaque to every later detector. Marker matches are
//!    replaced by the class's [`MarkerClass::marker_text`]; pseudonym
//!    matches are handed to the supplied renderer with the *original*
//!    matched bytes and its output inserted as the replacement. No
//!    mapping of removed to replacement text is ever built — repeats of
//!    one secret each re-run the renderer, so the irreversibility of the
//!    pipeline is structural: there is no lookup map in existence to
//!    store, return, or leak.
//! 4. **Stay bounded.** Content over the byte cap is a gap, not a partial
//!    redaction; replacement and probe budgets ([`MAX_REPLACEMENTS`],
//!    [`MAX_ENTROPY_PROBES`]) turn resource-exhausting inputs into
//!    [`RedactionGap::ResourceExhausted`] instead of unbounded work. Every
//!    detector below is a hand-rolled linear scan over ASCII classes — no
//!    regex engine, no backtracking, no dependency.
//!
//! Determinism: the output is a function of the record and the renderer
//! alone. The detectors are byte-classified scans with fixed thresholds
//! (the entropy measure is a pinned integer fixed-point log₂
//! approximation, so the verdict cannot drift across platforms), matches
//! are taken left to right and longest at a position, and no wall-clock,
//! run, or environment input exists. Identical inputs and an identical
//! renderer redact byte-identically, which is what the episode rebuild
//! gate rests on.
//!
//! The v1 replacement extents are part of the pipeline version this
//! module implements, and they are deliberately conservative — every
//! ambiguity is resolved in the over-redaction direction:
//!
//! - **Pinned credential formats** — a credential-shaped token from the
//!   pinned prefix table (AWS, GitHub, GitLab, Stripe, Slack, Google,
//!   Shopify, npm), claimed whole including its prefix, only at a token
//!   boundary; a match glued into a longer alphanumeric run is refused
//!   (the entropy detector is its safety net).
//! - **Authorization headers** — the *value* of an `Authorization` or
//!   `Proxy-Authorization` header line, from after the colon to end of
//!   line; the header name survives so analysis keeps the fact a
//!   credential header existed.
//! - **Private key blocks** — a whole `-----BEGIN … PRIVATE KEY-----` …
//!   `-----END … PRIVATE KEY-----` block; an unterminated block is
//!   destroyed to the end of the content rather than leaked.
//! - **Environment secret assignments** — the value of a shell-style
//!   assignment whose name carries a pinned secret-bearing segment
//!   (`SECRET`, `TOKEN`, `KEY`, …), name and `=` surviving.
//! - **High-entropy token candidates** — a run of ≥
//!   [`ENTROPY_MIN_TOKEN_CHARS`] token characters (no `-`: hyphenated
//!   prose must not form runs) with at least one digit, one letter, and a
//!   pinned entropy floor; long runs are probed over a pinned window.
//! - **Absolute paths, hostnames, usernames, email addresses, IP
//!   addresses** — pinned ASCII shapes with word boundaries. Because the
//!   registry order is pinned, overlaps resolve deterministically: a
//!   credential inside an authorization header is claimed by the
//!   credential detector first, a hostname inside an email address is
//!   left for the email detector (the hostname scan refuses names
//!   preceded by `@`), and a high-entropy path is marked rather than
//!   pseudonymized.
//!
//! [`PSEUDONYM_FORMAT`]: crate::redaction_policy::PSEUDONYM_FORMAT
//! [`StructuredField`]: crate::redaction_policy::StructuredField
//! [`MarkerClass::marker_text`]: crate::redaction_policy::MarkerClass::marker_text
//! [`RedactionCorpus::detectors`]: crate::redaction_policy::RedactionCorpus::detectors
//! [docs/notes/crate-ownership.md]: ../../../docs/notes/crate-ownership.md

use crate::json::{Object, Value};
use crate::redaction_policy::{
    DetectorEmit, DetectorEntry, MarkerClass, PseudonymClass, RedactionCorpus,
};
use crate::vocabulary::Timestamp;

/// The largest content this transformation accepts, in bytes: the episode
/// schema's own `content` ceiling. Anything larger is
/// [`RedactionGap::Oversized`] — the pipeline never truncates, because a
/// truncated redaction is a partial redaction.
pub const MAX_CONTENT_BYTES: usize = 1_048_576;

/// The largest `parent_ordinals` array accepted: the episode schema's own
/// bound for the relationship field.
pub const MAX_PARENT_ORDINALS: usize = 64;

/// The largest number of replacements (markers plus pseudonyms) one
/// occurrence may produce. A record that fires more than this is treated
/// as resource-exhausting input and fails closed with
/// [`RedactionGap::ResourceExhausted`] — the census of an input crafted to
/// replace unboundedly is not evidence, it is an attack surface.
pub const MAX_REPLACEMENTS: usize = 4_096;

/// The largest number of entropy candidate probes one occurrence may
/// cost. An input whose shape walks this many candidates is failing the
/// transformation on purpose (probe cost is the only super-linear-looking
/// work in the pipeline); it gets [`RedactionGap::ResourceExhausted`],
/// never a slow scan.
pub const MAX_ENTROPY_PROBES: usize = 8_192;

/// The shortest run the entropy detector considers. Below this a token
/// run is ordinary prose punctuation distance, not a secret.
pub const ENTROPY_MIN_TOKEN_CHARS: usize = 20;

/// The byte window the entropy measure evaluates for any candidate,
/// however long the run: bounded work, pinned input, deterministic
/// verdict.
pub const ENTROPY_PROBE_WINDOW: usize = 256;

/// The entropy floor in fixed-point units (see [`entropy_eighths_floor`]
/// neighborhood in [`entropy_fires`]): the pinned v1 threshold of 3.5
/// bits per byte over the probe window, expressed so the verdict is pure
/// integer arithmetic and cannot drift across platforms.
const ENTROPY_FLOOR_SCALED: u64 = 224; // 3.5 bits * 64 (the log2 scale)

/// The closed v1 episode role set ([`schemas/v1/derived-episode.json`]
/// `episode-role`): the four harness-agnostic roles adapters map their
/// harness's roles onto. A token outside the set is
/// [`RedactionGap::Unsupported`] — the schema's fail-closed rule, not a
/// compatibility surface.
///
/// [`schemas/v1/derived-episode.json`]: ../../../schemas/v1/derived-episode.json
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EpisodeRole {
    /// The harness's assistant turn.
    Assistant,
    /// The harness's system or instruction turn.
    System,
    /// A tool call or tool result turn.
    Tool,
    /// The human turn.
    User,
}

impl EpisodeRole {
    /// Every role, in schema enum order.
    pub const ALL: [Self; 4] = [
        crate::occurrence_redaction::EpisodeRole::Assistant,
        crate::occurrence_redaction::EpisodeRole::System,
        crate::occurrence_redaction::EpisodeRole::Tool,
        crate::occurrence_redaction::EpisodeRole::User,
    ];

    /// The wire token the episode record carries.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Assistant => "assistant",
            Self::System => "system",
            Self::Tool => "tool",
            Self::User => "user",
        }
    }

    /// The role a source role token names, or `None` when the token is
    /// outside the closed v1 set.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.token() == token)
    }
}

/// One raw occurrence record as the adapter projection normalized it —
/// the transformation's whole view of the source. The projection's view
/// is never pre-censored: `role` and `source_time` arrive verbatim and
/// are validated here, so an unsupported or malformed record fails closed
/// in this module rather than being smoothed over upstream.
#[derive(Clone, Debug)]
pub struct SourceRecord<'a> {
    /// The harness-agnostic role token the projection mapped (or failed
    /// to map) from the source record. Validated against
    /// [`EpisodeRole`]; anything else is a gap.
    pub role: &'a str,
    /// The episode-local position: contiguous, ascending from zero
    /// across the occurrence set, within the schema's `u63` domain.
    pub ordinal: u64,
    /// The optional source-stable UTC event time, verbatim. Validated
    /// against the shared `rfc3339-utc-timestamp` shape and calendar;
    /// anything else is a gap.
    pub source_time: Option<&'a str>,
    /// Backward-only references to earlier records this one answers or
    /// continues. Must be unique, at most [`MAX_PARENT_ORDINALS`] long,
    /// and every value strictly below `ordinal`.
    pub parent_ordinals: &'a [u64],
    /// The record's textual content: the text or structured projection
    /// the detectors run over. Binary sources never reach this module —
    /// the projection's own unsupported state expresses them before here.
    pub content: &'a str,
}

/// Why a validated occurrence produced no redacted occurrence: the closed
/// v1 gap set. Every variant is content-free — it names the fault class,
/// never the offending input — so a gap can never become a channel for
/// the very material the pipeline exists to redact. A gap carries no
/// episode payload: the caller emits a bounded coverage-gap result and
/// nothing else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactionGap {
    /// The record is outside the pipeline's supported shape: a role
    /// token outside the closed four-role set. The projection could not
    /// vouch for the record, so the pipeline refuses it.
    Unsupported,
    /// The record is well-formed enough to read but semantically broken:
    /// a `source_time` off the shared UTC shape or calendar, a parent
    /// ordinal that points forward or is duplicated.
    Malformed,
    /// A bound is exceeded: content over [`MAX_CONTENT_BYTES`], more
    /// than [`MAX_PARENT_ORDINALS`] parents, or an ordinal outside the
    /// schema's `u63` domain.
    Oversized,
    /// The record is crafted to exhaust the pipeline's budgets — more
    /// replacements than [`MAX_REPLACEMENTS`] or more entropy probes
    /// than [`MAX_ENTROPY_PROBES`]. Fail closed, never slow down.
    ResourceExhausted,
    /// A pinned detector's internal invariant broke (an unknown registry
    /// slug, an unrepresentable value). Structurally unreachable while
    /// the pinned corpus stands; the variant exists so the failure mode
    /// is a gap, never a partial episode.
    DetectorFailed,
}

impl RedactionGap {
    /// The wire token a coverage-gap record carries for this fault
    /// class.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Malformed => "malformed",
            Self::Oversized => "oversized",
            Self::ResourceExhausted => "resource_exhausted",
            Self::DetectorFailed => "detector_failed",
        }
    }
}

impl std::fmt::Display for RedactionGap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Unsupported => "unsupported occurrence",
            Self::Malformed => "malformed occurrence",
            Self::Oversized => "oversized occurrence",
            Self::ResourceExhausted => "resource-exhausting occurrence",
            Self::DetectorFailed => "detector failure",
        };
        f.write_str(name)
    }
}

impl std::error::Error for RedactionGap {}

/// The transformation's output for one validated, supported occurrence:
/// exactly the allowlisted structured fields plus the redacted content
/// rendering and the two censuses the episode's `marker_counts` and
/// `pseudonym_counts` members are summed from. Build one with
/// [`redact_occurrence`]; identical inputs and renderer build identical
/// values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedOccurrence {
    role: EpisodeRole,
    ordinal: i64,
    source_time: Option<Timestamp>,
    parent_ordinals: Vec<i64>,
    content: String,
    marker_counts: [u64; MarkerClass::ALL.len()],
    pseudonym_counts: [u64; PseudonymClass::ALL.len()],
}

impl RedactedOccurrence {
    /// The validated role.
    #[must_use]
    pub fn role(&self) -> EpisodeRole {
        self.role
    }

    /// The episode-local ordinal, within the schema's `u63` domain.
    #[must_use]
    pub fn ordinal(&self) -> i64 {
        self.ordinal
    }

    /// The validated source-stable event time, when the source carried
    /// one.
    #[must_use]
    pub fn source_time(&self) -> Option<&Timestamp> {
        self.source_time.as_ref()
    }

    /// The validated backward-only parent ordinals (empty when the
    /// record answers nothing).
    #[must_use]
    pub fn parent_ordinals(&self) -> &[i64] {
        &self.parent_ordinals
    }

    /// The redacted content rendering: source text after the pinned
    /// registry replaced matches with markers and renderer pseudonyms.
    /// Removed bytes are not recoverable from it and no mapping to them
    /// exists.
    #[must_use]
    pub fn content(&self) -> &str {
        &self.content
    }

    /// How many times the marker detector of `class` fired.
    #[must_use]
    pub fn marker_count(&self, class: MarkerClass) -> u64 {
        self.marker_counts[marker_index(class)]
    }

    /// How many times the pseudonym detector of `class` fired (each fire
    /// is one renderer call).
    #[must_use]
    pub fn pseudonym_count(&self, class: PseudonymClass) -> u64 {
        self.pseudonym_counts[pseudonym_index(class)]
    }

    /// The marker census contribution over all classes — explicit zeros
    /// included, so a clean scan is distinguishable from a detector that
    /// silently failed to run.
    #[must_use]
    pub fn marker_counts(&self) -> [u64; MarkerClass::ALL.len()] {
        self.marker_counts
    }

    /// The pseudonym census contribution over all classes.
    #[must_use]
    pub fn pseudonym_counts(&self) -> [u64; PseudonymClass::ALL.len()] {
        self.pseudonym_counts
    }

    /// The episode schema's `episode-record` object for this occurrence:
    /// exactly the allowlisted members (`content`, `ordinal`, `role`,
    /// plus `source_time` and `parent_ordinals` when present), ready for
    /// the composition stage to order and digest. This is the whole
    /// allowlist projection — nothing else of the source record survives
    /// anywhere in this value.
    #[must_use]
    pub fn record_value(&self) -> Value {
        let mut record = Object::new();
        record.set("content", Value::Text(self.content.clone()));
        record.set("ordinal", Value::Int(self.ordinal));
        record.set("role", Value::Text(self.role.token().to_owned()));
        if let Some(time) = &self.source_time {
            record.set("source_time", Value::Text(time.as_str().to_owned()));
        }
        if !self.parent_ordinals.is_empty() {
            record.set(
                "parent_ordinals",
                Value::Array(
                    self.parent_ordinals
                        .iter()
                        .map(|ordinal| Value::Int(*ordinal))
                        .collect(),
                ),
            );
        }
        Value::Object(record)
    }
}

/// Exhaustive class → census-slot mapping; the compiler enforces that a
/// new class cannot silently miss its slot.
fn marker_index(class: MarkerClass) -> usize {
    match class {
        MarkerClass::PinnedCredential => 0,
        MarkerClass::AuthorizationHeader => 1,
        MarkerClass::PrivateKeyBlock => 2,
        MarkerClass::EnvironmentSecret => 3,
        MarkerClass::HighEntropyToken => 4,
    }
}

/// Exhaustive class → census-slot mapping, as above.
fn pseudonym_index(class: PseudonymClass) -> usize {
    match class {
        PseudonymClass::AbsolutePath => 0,
        PseudonymClass::Hostname => 1,
        PseudonymClass::Username => 2,
        PseudonymClass::EmailAddress => 3,
        PseudonymClass::IpAddress => 4,
    }
}

/// Redact one validated, supported raw occurrence through the pinned
/// allowlist and ordered detector registry.
///
/// `pseudonym` renders one pseudonym-class match: it receives the class
/// and the original matched bytes and returns the replacement text (the
/// composition stage supplies the tenant-HMAC renderer; the pipeline
/// never builds a mapping of removed to replacement text, so repeats of
/// one secret each re-run the renderer). The renderer must be total and
/// deterministic — identical arguments must return identical text — and
/// it must not return the matched bytes themselves; the pipeline cannot
/// enforce that, which is exactly why the renderer is the composition
/// stage's trusted component rather than this module's.
///
/// # Errors
/// A [`RedactionGap`] when the record is unsupported, malformed,
/// oversized, or exhausts the pipeline's budgets (or a detector
/// invariant breaks). The error is content-free and carries no episode
/// material.
pub fn redact_occurrence(
    record: &SourceRecord<'_>,
    pseudonym: impl FnMut(PseudonymClass, &str) -> String,
) -> Result<RedactedOccurrence, RedactionGap> {
    // Fixed first-fault order: domain bounds, then semantic shape, so a
    // record with several faults always reports the same first one.
    let role = EpisodeRole::parse(record.role).ok_or(RedactionGap::Unsupported)?;
    if record.content.len() > MAX_CONTENT_BYTES {
        return Err(RedactionGap::Oversized);
    }
    if record.parent_ordinals.len() > MAX_PARENT_ORDINALS {
        return Err(RedactionGap::Oversized);
    }
    let ordinal = i64::try_from(record.ordinal).map_err(|_| RedactionGap::Oversized)?;
    let mut parents = Vec::with_capacity(record.parent_ordinals.len());
    for parent in record.parent_ordinals {
        let parent = i64::try_from(*parent).map_err(|_| RedactionGap::Oversized)?;
        if parent >= ordinal {
            // Backward-only: a forward or self reference is not a
            // relationship the episode schema can carry. (This also
            // bounds every parent inside the u63 domain, because the
            // ordinal already is.)
            return Err(RedactionGap::Malformed);
        }
        if parents.contains(&parent) {
            return Err(RedactionGap::Malformed);
        }
        parents.push(parent);
    }
    let source_time = match record.source_time {
        Some(text) => {
            let time = Timestamp::parse(text).map_err(|_| RedactionGap::Malformed)?;
            if !time.calendar_valid() {
                return Err(RedactionGap::Malformed);
            }
            Some(time)
        }
        None => None,
    };

    // Apply the registry, ascending order, over claimed-region-opaque
    // segments.
    let mut engine = Engine::new(record.content);
    let mut render = pseudonym;
    for entry in RedactionCorpus::pinned().detectors() {
        engine.apply(entry, &mut render)?;
    }

    let marker_counts = engine.markers;
    let pseudonym_counts = engine.pseudonyms;
    Ok(RedactedOccurrence {
        role,
        ordinal,
        source_time,
        parent_ordinals: parents,
        content: engine.finish(),
        marker_counts,
        pseudonym_counts,
    })
}

/// The evolving redaction state: residual text segments and already-
/// emitted replacements, plus the budgets and both censuses. Replaced
/// regions are [`Piece::Removed`] and are never scanned again — the
/// structural form of detector precedence (first claim wins) and of
/// replacement opacity (markers and pseudonyms cannot be re-detected).
struct Engine {
    pieces: Vec<Piece>,
    markers: [u64; MarkerClass::ALL.len()],
    pseudonyms: [u64; PseudonymClass::ALL.len()],
    replacements: usize,
    entropy_probes: usize,
}

enum Piece {
    /// Residual source text, still scannable.
    Text(String),
    /// An emitted replacement: opaque to every later detector.
    Removed(String),
}

impl Engine {
    fn new(content: &str) -> Self {
        Self {
            pieces: vec![Piece::Text(content.to_owned())],
            markers: [0; MarkerClass::ALL.len()],
            pseudonyms: [0; PseudonymClass::ALL.len()],
            replacements: 0,
            entropy_probes: 0,
        }
    }

    /// The redacted content: reassemble the text segments; the removed
    /// segments are already their own replacements.
    fn finish(self) -> String {
        let mut out = String::with_capacity(64);
        for piece in self.pieces {
            match piece {
                Piece::Text(text) | Piece::Removed(text) => out.push_str(&text),
            }
        }
        out
    }

    /// Run one registry row over every residual text segment, in
    /// left-to-right order, claiming each match region.
    fn apply(
        &mut self,
        entry: &DetectorEntry,
        pseudonym: &mut impl FnMut(PseudonymClass, &str) -> String,
    ) -> Result<(), RedactionGap> {
        let mut next: Vec<Piece> = Vec::with_capacity(self.pieces.len());
        for piece in std::mem::take(&mut self.pieces) {
            match piece {
                Piece::Removed(text) => next.push(Piece::Removed(text)),
                Piece::Text(text) => {
                    let matches = scan_piece(entry, &text, self)?;
                    if matches.is_empty() {
                        next.push(Piece::Text(text));
                        continue;
                    }
                    let mut rest = 0;
                    for (start, end) in matches {
                        if rest < start {
                            next.push(Piece::Text(text[rest..start].to_owned()));
                        }
                        if self.replacements >= MAX_REPLACEMENTS {
                            return Err(RedactionGap::ResourceExhausted);
                        }
                        self.replacements += 1;
                        let replacement = match entry.emits() {
                            DetectorEmit::Marker(class) => {
                                self.markers[marker_index(class)] += 1;
                                class.marker_text().to_owned()
                            }
                            DetectorEmit::Pseudonym(class) => {
                                self.pseudonyms[pseudonym_index(class)] += 1;
                                pseudonym(class, &text[start..end])
                            }
                        };
                        next.push(Piece::Removed(replacement));
                        rest = end;
                    }
                    if rest < text.len() {
                        next.push(Piece::Text(text[rest..].to_owned()));
                    }
                }
            }
        }
        self.pieces = next;
        Ok(())
    }
}

/// Dispatch one registry row's scan. The slug is pinned by the corpus,
/// so the catch-all is structurally unreachable — and it is a typed gap,
/// not a panic.
fn scan_piece(
    entry: &DetectorEntry,
    text: &str,
    engine: &mut Engine,
) -> Result<Vec<(usize, usize)>, RedactionGap> {
    match entry.slug() {
        "pinned-credential-formats" => Ok(scan_pinned_credentials(text)),
        "authorization-headers" => Ok(scan_authorization_headers(text)),
        "private-key-blocks" => Ok(scan_private_key_blocks(text)),
        "environment-secret-assignments" => Ok(scan_environment_secrets(text)),
        "high-entropy-token-candidates" => scan_high_entropy_tokens(text, engine),
        "absolute-path-pseudonyms" => Ok(scan_absolute_paths(text)),
        "hostname-pseudonyms" => Ok(scan_hostnames(text)),
        "username-pseudonyms" => Ok(scan_usernames(text)),
        "email-address-pseudonyms" => Ok(scan_email_addresses(text)),
        "ip-address-pseudonyms" => Ok(scan_ip_addresses(text)),
        _ => Err(RedactionGap::DetectorFailed),
    }
}

/// ASCII byte classes shared by the scanners. Every detector works on
/// bytes, and every match extent starts and ends on an ASCII boundary,
/// so multi-byte UTF-8 sequences are natural boundaries and slicing is
/// always char-safe.
mod classes {
    /// `[A-Za-z0-9]`
    pub fn alnum(b: u8) -> bool {
        b.is_ascii_alphanumeric()
    }

    /// `[A-Za-z0-9_]` — the identifier continuation class.
    pub fn word(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_'
    }

    /// `[A-Za-z]`
    pub fn alpha(b: u8) -> bool {
        b.is_ascii_alphabetic()
    }

    /// `[0-9]`
    pub fn digit(b: u8) -> bool {
        b.is_ascii_digit()
    }

    /// `[0-9a-fA-F]`
    pub fn hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }

    /// `[A-Z0-9]` — AWS key-id bodies.
    pub fn alnum_upper(b: u8) -> bool {
        b.is_ascii_uppercase() || b.is_ascii_digit()
    }

    /// `[A-Za-z0-9-]` — Slack token bodies.
    pub fn token_dash(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'-'
    }

    /// `[A-Za-z0-9_-]` — Google key bodies.
    pub fn token_underscore(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
    }
}

/// One pinned credential shape: a literal prefix, the character class of
/// the secret body, and the accepted body-length range. A match is
/// prefix + body, claimed whole.
struct PinnedCredential {
    prefix: &'static [u8],
    body: fn(u8) -> bool,
    min_body: usize,
    max_body: usize,
}

const fn credential(
    prefix: &'static [u8],
    body: fn(u8) -> bool,
    min_body: usize,
    max_body: usize,
) -> PinnedCredential {
    PinnedCredential {
        prefix,
        body,
        min_body,
        max_body,
    }
}

/// The pinned v1 credential table. Formats are added here only with a
/// new pipeline version; the shapes are the detector's whole behavior.
const PINNED_CREDENTIALS: &[PinnedCredential] = &[
    credential(b"AKIA", classes::alnum_upper, 16, 16), // AWS access key id
    credential(b"ASIA", classes::alnum_upper, 16, 16), // AWS temporary key id
    credential(b"ghp_", classes::alnum, 36, 36),       // GitHub classic token
    credential(b"gho_", classes::alnum, 36, 36),       // GitHub OAuth token
    credential(b"ghu_", classes::alnum, 36, 36),       // GitHub user token
    credential(b"ghs_", classes::alnum, 36, 36),       // GitHub server token
    credential(b"ghr_", classes::alnum, 36, 36),       // GitHub refresh token
    credential(b"github_pat_", classes::word, 22, 22), // GitHub fine-grained
    credential(b"glpat-", classes::word, 20, 20),      // GitLab personal token
    credential(b"sk_live_", classes::alnum, 24, 64),   // Stripe secret key
    credential(b"rk_live_", classes::alnum, 24, 64),   // Stripe restricted key
    credential(b"xoxb-", classes::token_dash, 10, 64), // Slack bot token
    credential(b"xoxp-", classes::token_dash, 10, 64), // Slack user token
    credential(b"xoxa-", classes::token_dash, 10, 64), // Slack app token
    credential(b"xoxr-", classes::token_dash, 10, 64), // Slack refresh token
    credential(b"AIza", classes::token_underscore, 35, 35), // Google API key
    credential(b"shpat_", classes::alnum, 32, 32),     // Shopify access token
    credential(b"npm_", classes::alnum, 36, 36),       // npm granular token
];

/// Detector 1: pinned credential formats. Claim `prefix + body` whole,
/// only at a word boundary, and only when the token ends there — a
/// match glued into a longer alphanumeric run is not claimed (it is
/// either prose or a token the entropy detector has a chance at).
fn scan_pinned_credentials(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    'scan: while i < bytes.len() {
        if i > 0 && classes::word(bytes[i - 1]) {
            i += 1;
            continue;
        }
        let mut best: Option<(usize, &PinnedCredential)> = None;
        for rule in PINNED_CREDENTIALS {
            if bytes[i..].starts_with(rule.prefix) {
                let mut j = i + rule.prefix.len();
                let mut body = 0;
                while j < bytes.len() && body < rule.max_body && (rule.body)(bytes[j]) {
                    j += 1;
                    body += 1;
                }
                if body >= rule.min_body
                    && (j >= bytes.len() || (!(rule.body)(bytes[j]) && !classes::alnum(bytes[j])))
                {
                    let end = i + rule.prefix.len() + body;
                    if best.is_none_or(|(best_end, _)| end > best_end) {
                        best = Some((end, rule));
                    }
                }
            }
        }
        if let Some((end, _)) = best {
            matches.push((i, end));
            i = end;
            continue 'scan;
        }
        i += 1;
    }
    matches
}

/// Split `text` into lines; yields `(start, content_end)` where
/// `content_end` excludes the line terminator (`\n`, with a preceding
/// `\r` stripped). `cursor` resumes after the previous line.
fn next_line(text: &str, cursor: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    if cursor >= bytes.len() {
        return None;
    }
    let start = cursor;
    let rest = &bytes[start..];
    let end = rest
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |rel| start + rel);
    let mut content_end = end;
    if content_end > start && bytes[content_end - 1] == b'\r' {
        content_end -= 1;
    }
    Some((start, content_end))
}

/// Detector 2: authorization headers. Match `Authorization:` or
/// `Proxy-Authorization:` (ASCII case-insensitive) at the start of a
/// line and claim the value — everything after the optional whitespace
/// around the colon to end of line. The header name survives.
fn scan_authorization_headers(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut cursor = 0;
    while let Some((start, content_end)) = next_line(text, cursor) {
        cursor = content_end + 1;
        let line = &bytes[start..content_end];
        let name_len = if starts_with_ignore_case(line, b"proxy-authorization") {
            b"proxy-authorization".len()
        } else if starts_with_ignore_case(line, b"authorization") {
            b"authorization".len()
        } else {
            continue;
        };
        let mut p = start + name_len;
        while p < content_end && (bytes[p] == b' ' || bytes[p] == b'\t') {
            p += 1;
        }
        if p >= content_end || bytes[p] != b':' {
            continue;
        }
        p += 1;
        while p < content_end && (bytes[p] == b' ' || bytes[p] == b'\t') {
            p += 1;
        }
        if p < content_end {
            matches.push((p, content_end));
        }
    }
    matches
}

fn starts_with_ignore_case(line: &[u8], prefix: &[u8]) -> bool {
    line.len() >= prefix.len() && line[..prefix.len()].eq_ignore_ascii_case(prefix)
}

/// Detector 3: private key blocks. A `-----BEGIN <label> PRIVATE
/// KEY-----` delimiter opens a block — at the start of a line, or glued
/// after an assignment such as `SERVICE_KEY=`, which is how exported
/// keys appear in practice — and the matching `-----END <label> PRIVATE
/// KEY-----` line closes it; the whole extent is claimed. A block whose
/// end line never arrives is claimed to the end of the content:
/// unterminated input is destroyed, not leaked.
fn scan_private_key_blocks(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if is_key_block_begin(bytes, i) {
            let mut end = text.len();
            let mut search = i;
            while let Some((line_start, line_end)) = next_line(text, search) {
                search = line_end + 1;
                if is_private_key_delimiter(&bytes[line_start..line_end], b"END") {
                    end = line_end;
                    break;
                }
            }
            matches.push((i, end));
            i = end + 1;
            continue;
        }
        i += 1;
    }
    matches
}

/// True when the bytes from `start` begin a key-block opening
/// delimiter: `-----BEGIN <label> PRIVATE KEY-----` occupying the rest
/// of its line, with an uppercase, digit, or space label (possibly
/// empty).
fn is_key_block_begin(bytes: &[u8], start: usize) -> bool {
    const LEAD: &[u8] = b"-----BEGIN ";
    const TAIL: &[u8] = b"PRIVATE KEY-----";
    if !bytes[start..].starts_with(LEAD) {
        return false;
    }
    let label_start = start + LEAD.len();
    let raw_end = bytes[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(bytes.len(), |rel| start + rel);
    let line_end = if raw_end > start && bytes[raw_end - 1] == b'\r' {
        raw_end - 1
    } else {
        raw_end
    };
    line_end >= label_start + TAIL.len()
        && &bytes[line_end - TAIL.len()..line_end] == TAIL
        && bytes[label_start..line_end - TAIL.len()]
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b' ')
}

fn is_private_key_delimiter(line: &[u8], kind: &[u8]) -> bool {
    const LEAD: &[u8] = b"-----";
    const TAIL: &[u8] = b"PRIVATE KEY-----";
    if line.len() < LEAD.len() + kind.len() + 1 + TAIL.len() {
        return false;
    }
    if !line.starts_with(LEAD) || !line.ends_with(TAIL) {
        return false;
    }
    let middle = &line[LEAD.len()..line.len() - TAIL.len()];
    middle.starts_with(kind)
        && middle[kind.len()..]
            .iter()
            .all(|b| b.is_ascii_uppercase() || *b == b' ' || b.is_ascii_digit())
}

/// The pinned secret-bearing name segments of detector 4. A variable
/// name whose underscore-separated segments include one of these is a
/// secret assignment; everything else of the shell namespace is left
/// alone (`PWD`, `PATH`, `KEYBOARD_LAYOUT` pass).
const ENV_SECRET_SEGMENTS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API",
    "KEY",
    "ACCESS",
    "PRIVATE",
    "CREDENTIAL",
    "CREDENTIALS",
    "AUTH",
    "SESSION",
];

/// Detector 4: environment secret assignments. Match an optional
/// `export `, a name whose segments include a pinned secret-bearing
/// one, `=`, and claim the value to end of line. The name survives.
fn scan_environment_secrets(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut cursor = 0;
    while let Some((start, content_end)) = next_line(text, cursor) {
        cursor = content_end + 1;
        let mut p = start;
        if bytes[p..content_end].starts_with(b"export ") {
            p += b"export ".len();
        }
        let name_start = p;
        match bytes.get(p) {
            Some(&b) if b == b'_' || b.is_ascii_alphabetic() => p += 1,
            _ => continue,
        }
        while p < content_end && classes::word(bytes[p]) {
            p += 1;
        }
        let name = &text[name_start..p];
        if !env_name_is_secret_bearing(name) {
            continue;
        }
        while p < content_end && (bytes[p] == b' ' || bytes[p] == b'\t') {
            p += 1;
        }
        if p >= content_end || bytes[p] != b'=' {
            continue;
        }
        p += 1;
        while p < content_end && (bytes[p] == b' ' || bytes[p] == b'\t') {
            p += 1;
        }
        // A value that is only whitespace is not a secret; anything else
        // to end of line is claimed whole.
        if p < content_end
            && bytes[p..content_end]
                .iter()
                .any(|&b| !b.is_ascii_whitespace())
        {
            matches.push((p, content_end));
        }
    }
    matches
}

fn env_name_is_secret_bearing(name: &str) -> bool {
    name.to_ascii_uppercase()
        .split('_')
        .any(|segment| ENV_SECRET_SEGMENTS.contains(&segment))
}

/// The entropy detector's token character class: `[A-Za-z0-9+/=_]`.
/// Deliberately no `-`: hyphenated prose must not form single runs, and
/// that omission is part of the pinned v1 shape.
fn entropy_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'_'
}

/// Detector 5: high-entropy token candidates. A maximal run of token
/// characters at a run boundary is a candidate; a candidate at least
/// [`ENTROPY_MIN_TOKEN_CHARS`] long with at least one digit, one letter,
/// and an entropy over the pinned window at or above the floor is
/// claimed whole. Probes are budgeted
/// ([`MAX_ENTROPY_PROBES`]) so an input crafted as millions of
/// candidates fails closed instead of scanning slowly.
fn scan_high_entropy_tokens(
    text: &str,
    engine: &mut Engine,
) -> Result<Vec<(usize, usize)>, RedactionGap> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if entropy_token_byte(bytes[i]) && (i == 0 || !entropy_token_byte(bytes[i - 1])) {
            let mut j = i;
            while j < bytes.len() && entropy_token_byte(bytes[j]) {
                j += 1;
            }
            engine.entropy_probes += 1;
            if engine.entropy_probes > MAX_ENTROPY_PROBES {
                return Err(RedactionGap::ResourceExhausted);
            }
            if j - i >= ENTROPY_MIN_TOKEN_CHARS && entropy_fires(&bytes[i..j]) {
                matches.push((i, j));
                i = j;
                continue;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    Ok(matches)
}

/// The pinned v1 entropy verdict: at least one digit, at least one
/// letter, and a fixed-point Shannon entropy of the probe window at or
/// above 3.5 bits per byte. The log₂ terms are integer 1/64-unit
/// approximations (a bit-length plus a 17-entry fractional table), so
/// the verdict is exact, deterministic arithmetic on every platform.
fn entropy_fires(candidate: &[u8]) -> bool {
    let window = &candidate[..candidate.len().min(ENTROPY_PROBE_WINDOW)];
    let mut counts = [0u64; 256];
    let mut has_digit = false;
    let mut has_alpha = false;
    for &b in window {
        counts[b as usize] += 1;
        has_digit |= classes::digit(b);
        has_alpha |= classes::alpha(b);
    }
    if !has_digit || !has_alpha {
        return false;
    }
    let n = window.len() as u64;
    // H = log2(n) - Σ (c_i / n) log2(c_i), all in 1/64-bit units scaled
    // by n: fires when n·H ≥ 3.5·n.
    let scaled = n * log2_scaled(n)
        - counts
            .iter()
            .filter(|count| **count > 0)
            .map(|count| count * log2_scaled(*count))
            .sum::<u64>();
    scaled >= ENTROPY_FLOOR_SCALED * n
}

/// `64 · log2(x)` for integer `x ≥ 1`: bit length plus a fractional
/// table over the leading mantissa bits. Monotone and deterministic;
/// the approximation is part of the pinned pipeline version.
fn log2_scaled(x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }
    let bits = 64 - u64::from(x.leading_zeros()); // x in [2^(bits-1), 2^bits)
    let base = 64 * (bits - 1);
    // Fractional part: mantissa = (x / 2^(bits-1)) - 1, in 1/16ths. The
    // product runs in u128 so the fixed point is well-defined for every
    // u64 input, and the quotient is at most 16.
    let half = 1u64 << (bits - 1);
    let mantissa = u128::from(x - half) * 16 / u128::from(half);
    let index = usize::try_from(mantissa).expect("mantissa is at most 16");
    base + LOG2_FRACTION_64[index]
}

/// `64 · log2(1 + k/16)` for `k` in 0..=16, rounded.
const LOG2_FRACTION_64: [u64; 17] = [
    0, 6, 12, 17, 22, 26, 30, 34, 37, 40, 43, 47, 49, 52, 55, 57, 64,
];

/// The path component class: `[A-Za-z0-9._~+@%-]`.
fn path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'+' | b'@' | b'%' | b'-')
}

/// Detector 6: absolute paths. A `/` at a component boundary (the
/// previous byte outside the component class — which also admits the
/// `//` of a URL scheme) opens a run of `/`-separated components; the
/// whole run is claimed when its first component carries at least one
/// alphanumeric byte (so `/`, `/...`, `/--` are not paths).
fn scan_absolute_paths(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/'
            && (i == 0 || !path_byte(bytes[i - 1]))
            && i + 1 < bytes.len()
            && path_byte(bytes[i + 1])
        {
            let mut j = i + 1;
            loop {
                while j < bytes.len() && path_byte(bytes[j]) {
                    j += 1;
                }
                // The run stopped on a non-component byte; a slash whose
                // next byte is another component continues the path.
                if j + 1 < bytes.len() && bytes[j] == b'/' && path_byte(bytes[j + 1]) {
                    j += 1;
                } else {
                    break;
                }
            }
            // The first component runs from i+1 to the first slash (or
            // the end of the match).
            let first_end = bytes[i + 1..j]
                .iter()
                .position(|&b| b == b'/')
                .map_or(j, |rel| i + 1 + rel);
            if bytes[i + 1..first_end].iter().any(|&b| classes::alnum(b)) {
                matches.push((i, j));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    matches
}

/// Parse dot-separated hostname labels from `from`, returning the end
/// of the last label together with its extent, when at least `min`
/// labels parsed. A label is `[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?`.
fn parse_hostname_labels(
    bytes: &[u8],
    from: usize,
    min_labels: usize,
) -> Option<(usize, usize, usize)> {
    let mut j = from;
    let mut labels = 0;
    let mut last = (from, from);
    loop {
        let label_start = j;
        while j < bytes.len() && (classes::alnum(bytes[j]) || bytes[j] == b'-') {
            j += 1;
        }
        let mut label_end = j;
        while label_end > label_start && bytes[label_end - 1] == b'-' {
            label_end -= 1;
        }
        if label_end == label_start || !bytes[label_start].is_ascii_alphanumeric() {
            break;
        }
        labels += 1;
        last = (label_start, label_end);
        if j < bytes.len()
            && bytes[j] == b'.'
            && j + 1 < bytes.len()
            && classes::alnum(bytes[j + 1])
        {
            j += 1;
        } else {
            break;
        }
    }
    if labels >= min_labels {
        Some((last.0, last.1, labels))
    } else {
        None
    }
}

/// Whether the bytes at `tld_start..tld_end` are the pinned TLD shape:
/// all-alphabetic, 2–24 bytes.
fn is_tld_shape(tld: &[u8]) -> bool {
    tld.iter().all(|&b| classes::alpha(b)) && (2..=24).contains(&tld.len())
}

/// Detector 7: hostnames. At least two labels whose last is the TLD
/// shape, at a boundary — and never directly after an `@`, which
/// reserves the region for the email detector that runs later in the
/// pinned order.
fn scan_hostnames(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let prev_ok = i == 0 || {
            let prev = bytes[i - 1];
            !(classes::alnum(prev) || prev == b'-' || prev == b'.') && prev != b'@'
        };
        if prev_ok
            && bytes[i] != b'@'
            && classes::alnum(bytes[i])
            && let Some((tld_start, end, _)) = parse_hostname_labels(bytes, i, 2)
            && is_tld_shape(&bytes[tld_start..end])
            && (end >= bytes.len() || !(classes::alnum(bytes[end]) || bytes[end] == b'-'))
        {
            matches.push((i, end));
            i = end;
            continue;
        }
        i += 1;
    }
    matches
}

/// The handle character class of detector 8: `[A-Za-z0-9_-]`.
fn handle_byte(b: u8) -> bool {
    classes::word(b) || b == b'-'
}

/// Detector 8: usernames. Two shapes: an `@mention` (an `@` plus a
/// handle of 2–32, refused when a `.` follows — that region belongs to
/// an email address) and a `~home` (a `~` plus a handle of 2–32).
fn scan_usernames(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if (bytes[i] == b'@' || bytes[i] == b'~')
            && (i == 0 || !handle_byte(bytes[i - 1]))
            && i + 1 < bytes.len()
            && handle_byte(bytes[i + 1])
        {
            let mut j = i + 1;
            while j < bytes.len() && handle_byte(bytes[j]) {
                j += 1;
            }
            let handle_len = j - i - 1;
            let dot_after = j < bytes.len() && bytes[j] == b'.';
            if (2..=32).contains(&handle_len) && !(bytes[i] == b'@' && dot_after) {
                matches.push((i, j));
                i = j;
                continue;
            }
        }
        i += 1;
    }
    matches
}

/// The email local-part class: `[A-Za-z0-9._%+-]`.
fn email_local_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-')
}

/// Detector 9: email addresses. A non-empty local part, an `@`, and a
/// hostname-shaped domain with the TLD shape, claimed as one extent.
fn scan_email_addresses(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'@'
            && i > 0
            && email_local_byte(bytes[i - 1])
            && i + 1 < bytes.len()
            && classes::alnum(bytes[i + 1])
        {
            let mut local_start = i - 1;
            while local_start > 0 && email_local_byte(bytes[local_start - 1]) {
                local_start -= 1;
            }
            if let Some((tld_start, end, _)) = parse_hostname_labels(bytes, i + 1, 2)
                && is_tld_shape(&bytes[tld_start..end])
                && (end >= bytes.len() || !(classes::alnum(bytes[end]) || bytes[end] == b'-'))
            {
                matches.push((local_start, end));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    matches
}

/// Detector 10: IP addresses. IPv4 dotted-quad (no leading zeros,
/// octets ≤ 255, claimed even when a sentence period follows) and IPv6
/// hex groups (an uncompressed form of at least four groups, or a
/// `::`-compressed form with at least one group, at hex/colon
/// boundaries). Hex-only prose times like `16:44:05` stay below the
/// uncompressed floor and survive.
fn scan_ip_addresses(text: &str) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut matches = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if classes::digit(bytes[i])
            && (i == 0 || (bytes[i - 1] != b'.' && !classes::digit(bytes[i - 1])))
            && let Some(end) = parse_ipv4(bytes, i)
        {
            matches.push((i, end));
            i = end;
            continue;
        }
        let colon_ok = bytes[i] == b':'
            && bytes.get(i + 1) == Some(&b':')
            && (i == 0 || (bytes[i - 1] != b':' && !classes::hex(bytes[i - 1])));
        let hex_ok = classes::hex(bytes[i])
            && (i == 0 || (bytes[i - 1] != b':' && !classes::hex(bytes[i - 1])));
        if (colon_ok || hex_ok)
            && let Some(end) = parse_ipv6(bytes, i)
        {
            matches.push((i, end));
            i = end;
            continue;
        }
        i += 1;
    }
    matches
}

/// Parse an IPv4 dotted quad starting at `i` (which is a digit at a
/// non-digit, non-dot boundary); return the end of the fourth octet. A
/// following digit is refused (it would be a fifth octet's beginning);
/// a following `.` is allowed — sentence punctuation after an address
/// must not defeat the claim.
fn parse_ipv4(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    for octet in 0..4 {
        let start = j;
        let mut value = 0u32;
        while j < bytes.len() && classes::digit(bytes[j]) && j - start < 3 {
            value = value * 10 + u32::from(bytes[j] - b'0');
            j += 1;
        }
        let width = j - start;
        if width == 0 || value > 255 || (width > 1 && bytes[start] == b'0') {
            return None;
        }
        if octet < 3 {
            if j < bytes.len() && bytes[j] == b'.' {
                j += 1;
            } else {
                return None;
            }
        }
    }
    if j < bytes.len() && classes::digit(bytes[j]) {
        return None;
    }
    Some(j)
}

/// Parse an IPv6 literal starting at `i` (a hex byte, or the first of a
/// `::` pair, at a non-hex non-colon boundary). Returns the end when
/// the shape is an uncompressed form of ≥ 4 groups or a `::`-compressed
/// form with ≥ 1 group and exactly one compression.
fn parse_ipv6(bytes: &[u8], i: usize) -> Option<usize> {
    let mut j = i;
    let mut groups = 0usize;
    let mut compressions = 0usize;
    if bytes[j] == b':' {
        // Leading compression: "::…" opens the literal.
        compressions += 1;
        j += 2;
    }
    loop {
        let group_start = j;
        while j < bytes.len() && j - group_start < 4 && classes::hex(bytes[j]) {
            j += 1;
        }
        if j > group_start {
            groups += 1;
        }
        if j < bytes.len() && bytes[j] == b':' {
            if bytes.get(j + 1) == Some(&b':') {
                if compressions > 0 {
                    return None;
                }
                compressions += 1;
                j += 2;
                // A compressed tail ("2001:db8::") ends the literal here
                // — unless a third colon makes the shape invalid.
                if j >= bytes.len() || !classes::hex(bytes[j]) {
                    if j < bytes.len() && bytes[j] == b':' {
                        return None;
                    }
                    break;
                }
                continue;
            }
            j += 1;
            if j >= bytes.len() || !classes::hex(bytes[j]) {
                return None;
            }
        } else {
            break;
        }
    }
    let ok = if compressions > 0 {
        groups >= 1 && compressions == 1
    } else {
        groups >= 4
    };
    ok.then_some(j)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic key-block delimiters, assembled from fragments so no
    /// contiguous delimiter exists in this source file (the fast lane
    /// secret-scans the working tree; these are fixtures, not keys).
    const PEM_BEGIN: &str = concat!("-----", "BEGIN ", "RSA ", "PRIVATE ", "KEY-----");
    const PEM_END: &str = concat!("-----", "END ", "RSA ", "PRIVATE ", "KEY-----");
    const PEM_BEGIN_UNLABELED: &str = concat!("-----", "BEGIN ", "PRIVATE ", "KEY-----");
    const PEM_END_UNLABELED: &str = concat!("-----", "END ", "PRIVATE ", "KEY-----");

    /// A synthetic OpenSSH delimiter, assembled the same way.
    fn openssh_delimiter() -> String {
        ["-----", "BEGIN ", "OPENSSH ", "PRIVATE ", "KEY-----"].concat()
    }

    /// The deterministic synthetic renderer every test uses: pinned
    /// format, zero entropy, and a stable function of the matched bytes.
    fn synthetic(class: PseudonymClass, matched: &str) -> String {
        let checksum: u64 = matched.bytes().map(u64::from).sum::<u64>() % 0xffff_ffff_ffff;
        format!("ps_{}_{:012x}", class.token(), checksum)
    }

    fn record(content: &str) -> SourceRecord<'_> {
        SourceRecord {
            role: "user",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content,
        }
    }

    fn redact(content: &str) -> RedactedOccurrence {
        redact_occurrence(&record(content), synthetic).expect("test record redacts")
    }

    fn github_token() -> String {
        format!("ghp_{}", "A1bC2dE3fG4hI5jK6lM7nO8pQ9rS0tU3vW4x")
    }

    #[test]
    fn clean_scan_counts_explicit_zeros() {
        let redacted = redact("nothing here but us processors");
        assert_eq!(redacted.content(), "nothing here but us processors");
        for class in MarkerClass::ALL {
            assert_eq!(redacted.marker_count(class), 0, "{class:?}");
        }
        for class in PseudonymClass::ALL {
            assert_eq!(redacted.pseudonym_count(class), 0, "{class:?}");
        }
        assert_eq!(redacted.role(), EpisodeRole::User);
        assert_eq!(redacted.ordinal(), 0);
        assert_eq!(redacted.source_time(), None);
        assert!(redacted.parent_ordinals().is_empty());
    }

    #[test]
    fn empty_content_is_a_clean_scan() {
        let redacted = redact("");
        assert_eq!(redacted.content(), "");
        assert_eq!(redacted.marker_counts(), [0; 5]);
        assert_eq!(redacted.pseudonym_counts(), [0; 5]);
    }

    #[test]
    fn record_value_carries_exactly_the_allowlist() {
        let source = SourceRecord {
            role: "assistant",
            ordinal: 7,
            source_time: Some("2026-09-11T16:44:05Z"),
            parent_ordinals: &[3, 1],
            content: "clean",
        };
        let redacted = redact_occurrence(&source, synthetic).expect("valid record redacts");
        let Value::Object(record) = redacted.record_value() else {
            panic!("record value is an object");
        };
        let mut members: Vec<_> = record.iter().map(|(name, _)| name).collect();
        members.sort_unstable();
        assert_eq!(
            members,
            [
                "content",
                "ordinal",
                "parent_ordinals",
                "role",
                "source_time"
            ],
            "the allowlist is the whole projection"
        );
        assert_eq!(
            record.get("role"),
            Some(&Value::Text("assistant".to_owned()))
        );
        assert_eq!(record.get("ordinal"), Some(&Value::Int(7)));
        assert_eq!(
            record.get("source_time"),
            Some(&Value::Text("2026-09-11T16:44:05Z".to_owned()))
        );
        assert_eq!(
            record.get("parent_ordinals"),
            Some(&Value::Array(vec![Value::Int(3), Value::Int(1)]))
        );

        // Without the optional fields only the three required members
        // remain.
        let bare = redact("clean");
        let Value::Object(record) = bare.record_value() else {
            panic!("record value is an object");
        };
        let mut members: Vec<_> = record.iter().map(|(name, _)| name).collect();
        members.sort_unstable();
        assert_eq!(members, ["content", "ordinal", "role"]);
    }

    #[test]
    fn marker_detectors_destroy_their_pinned_shapes() {
        let pem = format!("{PEM_BEGIN}\nMIIEpAIBAAKCAQ\n{PEM_END}");
        let slack = format!("xoxb-{}", "123456789012-1234567890123-abc");
        let cases: [(&str, MarkerClass, u64); 6] = [
            (&github_token(), MarkerClass::PinnedCredential, 1),
            (&slack, MarkerClass::PinnedCredential, 1),
            (
                "Authorization: Bearer some-credential-value",
                MarkerClass::AuthorizationHeader,
                1,
            ),
            (&pem, MarkerClass::PrivateKeyBlock, 1),
            (
                "export DEPLOY_API_TOKEN=super-secret-value-123",
                MarkerClass::EnvironmentSecret,
                1,
            ),
            (
                "Ab3xY9pQ2rT7vW4zB6nM8cD0fF1",
                MarkerClass::HighEntropyToken,
                1,
            ),
        ];
        for (content, class, count) in cases {
            let redacted = redact(content);
            assert_eq!(
                redacted.marker_count(class),
                count,
                "{class:?} must fire on the pinned shape"
            );
            assert!(
                redacted.content().contains(class.marker_text()),
                "{class:?} marker text must be the only trace"
            );
            assert!(
                !redacted.content().contains("super-secret-value-123")
                    && !redacted.content().contains("MIIEpAIBAAKCAQ")
                    && !redacted.content().contains("some-credential-value")
                    && !content.is_empty(),
                "no removed value byte may survive anywhere"
            );
        }
    }

    #[test]
    fn every_pinned_credential_format_is_claimed() {
        // AWS example key ids, assembled like the other fixtures so no
        // contiguous access-key pattern exists in this source file.
        let aws_key = |body: &str| format!("AKIA{body}");
        let tokens = [
            aws_key("IOSFODNN7EXAMPLE"),
            format!("ASIA{}", "IOSFODNN7EXAMPL3"),
            github_token(),
            format!("gho_{}", "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp0Oo2"),
            format!("github_pat_{}", "A1b2C3d4E5f6G7h8I9j0K1"),
            format!("glpat-{}", "Ab3dEf7hIj0kLm2nOp3q"),
            format!("sk_live_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"),
            format!("xoxp-{}", "987654321098-zyxwvutsrq-9876"),
            format!("AIza{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"),
            format!("shpat_{}", "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"),
            format!("npm_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"),
        ];
        for token in tokens {
            let redacted = redact(&format!("see {token} in the vault"));
            assert_eq!(
                redacted.marker_count(MarkerClass::PinnedCredential),
                1,
                "each pinned format is claimed whole: {token}"
            );
            assert!(
                !redacted.content().contains(&token),
                "removed credential bytes must not survive"
            );
        }
    }

    #[test]
    fn a_pinned_credential_glued_into_a_longer_word_is_refused() {
        let glued = format!("AKIA{}", "IOSFODNN7EXAMPLES");
        let redacted = redact(&glued);
        assert_eq!(
            redacted.marker_count(MarkerClass::PinnedCredential),
            0,
            "a match inside a longer alphanumeric run is not claimed"
        );
    }

    #[test]
    fn pseudonym_detectors_render_through_the_renderer() {
        let content = "cd /etc/nginx/nginx.conf on host build.example.org, ping @alice, \
                       mail ops@example.org from 10.0.0.7 or ~carol";
        let redacted = redact(content);
        assert_eq!(
            redacted.pseudonym_count(PseudonymClass::AbsolutePath),
            1,
            "the nginx config path is one path"
        );
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Hostname), 1);
        assert_eq!(
            redacted.pseudonym_count(PseudonymClass::Username),
            2,
            "the mention and the tilde home"
        );
        assert_eq!(redacted.pseudonym_count(PseudonymClass::EmailAddress), 1);
        assert_eq!(redacted.pseudonym_count(PseudonymClass::IpAddress), 1);
        assert!(redacted.content().contains("ps_absolute_path_"));
        assert!(redacted.content().contains("ps_hostname_"));
        assert!(redacted.content().contains("ps_username_"));
        assert!(redacted.content().contains("ps_email_address_"));
        assert!(redacted.content().contains("ps_ip_address_"));
    }

    #[test]
    fn overlapping_detector_precedence_is_pinned() {
        // A credential inside an authorization header: the credential
        // detector (order 1) claims the token, the header detector
        // (order 2) claims the residual value text.
        let token = github_token();
        let redacted = redact(&format!("Authorization: Bearer {token}"));
        assert_eq!(redacted.marker_count(MarkerClass::PinnedCredential), 1);
        assert_eq!(redacted.marker_count(MarkerClass::AuthorizationHeader), 1);
        assert!(!redacted.content().contains(&token));

        // A key block inside an environment assignment: the key-block
        // detector (order 3) claims the block, and the assignment
        // detector (order 4) finds no residual value to claim.
        let pem = format!("{PEM_BEGIN_UNLABELED}\nMIIEpAIBAAKCAQ\n{PEM_END_UNLABELED}");
        let redacted = redact(&format!("SERVICE_KEY={pem}"));
        assert_eq!(redacted.marker_count(MarkerClass::PrivateKeyBlock), 1);
        assert_eq!(redacted.marker_count(MarkerClass::EnvironmentSecret), 0);
        assert!(!redacted.content().contains("MIIEpAIBAAKCAQ"));

        // A high-entropy path: the entropy detector (order 5) marks it,
        // the path detector (order 6) never sees it.
        let redacted = redact("/var/tmp/Ab3xY9pQ2rT7vW4zB6nM8cD0fF1");
        assert_eq!(redacted.marker_count(MarkerClass::HighEntropyToken), 1);
        assert_eq!(redacted.pseudonym_count(PseudonymClass::AbsolutePath), 0);

        // An email address: the hostname detector (order 7) refuses the
        // domain after an at-sign, the username detector (order 8)
        // refuses a mention followed by a dot, so the email detector
        // (order 9) claims the whole address.
        let redacted = redact("mail alice@example.com now");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::EmailAddress), 1);
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Hostname), 0);
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Username), 0);

        // A credential inside an environment assignment: order 1 beats
        // order 4, and the assignment detector finds no residual value.
        let token = github_token();
        let redacted = redact(&format!("API_TOKEN={token} extra"));
        assert_eq!(redacted.marker_count(MarkerClass::PinnedCredential), 1);
        assert_eq!(redacted.marker_count(MarkerClass::EnvironmentSecret), 0);
        assert!(redacted.content().contains("extra"));
    }

    #[test]
    fn repeated_secrets_count_individually() {
        let token = github_token();
        let redacted = redact(&format!("{token} then {token} then {token}"));
        assert_eq!(redacted.marker_count(MarkerClass::PinnedCredential), 3);
        assert_eq!(
            redacted
                .content()
                .matches("[redacted:pinned_credential]")
                .count(),
            3,
            "every repeat is destroyed, none skipped as a duplicate"
        );
        assert_eq!(
            redacted.marker_count(MarkerClass::AuthorizationHeader),
            0,
            "no class may borrow another's count"
        );

        // Repeated pseudonym matches each re-run the renderer with the
        // same bytes — the engine keeps no map that could deduplicate
        // (or reverse) them.
        let mut calls: Vec<(PseudonymClass, String, String)> = Vec::new();
        let source = SourceRecord {
            role: "user",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content: "alice@example.com met alice@example.com",
        };
        let redacted = redact_occurrence(&source, |class, matched| {
            let out = synthetic(class, matched);
            calls.push((class, matched.to_owned(), out.clone()));
            out
        })
        .expect("redacts");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::EmailAddress), 2);
        assert_eq!(calls.len(), 2, "one renderer call per match, no map");
        assert_eq!(calls[0], calls[1], "identical matches, identical calls");
        assert_eq!(calls[0].1, "alice@example.com");
        assert!(redacted.content().contains(&calls[0].2));
    }

    #[test]
    fn redaction_is_deterministic_across_runs() {
        let inputs = [
            "plain text with nothing to hide".to_owned(),
            format!(
                "deploy {} to /opt/app on db.internal as @ops from 192.168.0.4",
                github_token()
            ),
            "Authorization: Basic dXNlcjpwYXNzd29yZA==".to_owned(),
            "export SESSION_TOKEN=abc123 and PATH=/usr/bin too".to_owned(),
            "mail bob@example.co.uk about 2001:db8::1".to_owned(),
            "héllo /tmp/ünïcode wörld".to_owned(),
        ];
        for content in inputs {
            let first = redact(&content);
            let second = redact(&content);
            assert_eq!(first, second, "identical inputs must redact identically");
            let one = first.record_value().canonical_bytes();
            let two = second.record_value().canonical_bytes();
            assert_eq!(one, two, "canonical record bytes must reproduce");
        }
    }

    #[test]
    fn resource_limits_fail_closed() {
        // Content over the byte cap.
        let big = "a".repeat(MAX_CONTENT_BYTES + 1);
        assert_eq!(
            redact_occurrence(&record(&big), synthetic),
            Err(RedactionGap::Oversized)
        );
        // Exactly at the cap is accepted.
        let at_cap = "a".repeat(MAX_CONTENT_BYTES);
        let redacted =
            redact_occurrence(&record(&at_cap), synthetic).expect("content at the cap redacts");
        assert_eq!(redacted.marker_counts(), [0; 5]);

        // More entropy candidates than the probe budget: runs of 19
        // token bytes (below the match floor, so each only costs a
        // probe) separated by dots.
        let many = "A1b2c3d4e5f6g7h8i9j.".repeat(MAX_ENTROPY_PROBES + 1);
        assert!(many.len() < MAX_CONTENT_BYTES);
        assert_eq!(
            redact_occurrence(&record(&many), synthetic),
            Err(RedactionGap::ResourceExhausted)
        );

        // More matches than the replacement budget.
        let many_tokens = format!("{} ", github_token()).repeat(MAX_REPLACEMENTS + 1);
        assert!(many_tokens.len() < MAX_CONTENT_BYTES);
        assert_eq!(
            redact_occurrence(&record(&many_tokens), synthetic),
            Err(RedactionGap::ResourceExhausted)
        );
    }

    #[test]
    fn fail_closed_validation_matrix() {
        fn malformed_time(time: &str) -> SourceRecord<'_> {
            SourceRecord {
                role: "user",
                ordinal: 0,
                source_time: Some(time),
                parent_ordinals: &[],
                content: "x",
            }
        }
        fn parent_matrix(ordinal: u64, parents: &[u64]) -> SourceRecord<'_> {
            SourceRecord {
                role: "user",
                ordinal,
                source_time: None,
                parent_ordinals: parents,
                content: "x",
            }
        }

        let unsupported = SourceRecord {
            role: "robot",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content: "x",
        };
        assert_eq!(
            redact_occurrence(&unsupported, synthetic),
            Err(RedactionGap::Unsupported)
        );

        assert_eq!(
            redact_occurrence(&malformed_time("not-a-time"), synthetic),
            Err(RedactionGap::Malformed)
        );
        assert_eq!(
            redact_occurrence(&malformed_time("2026-13-45T99:99:99Z"), synthetic),
            Err(RedactionGap::Malformed),
            "grammar-passing but calendar-impossible times fail closed"
        );
        assert_eq!(
            redact_occurrence(&malformed_time("2026-09-11T16:44:05+02:00"), synthetic),
            Err(RedactionGap::Malformed),
            "the shared shape is UTC only"
        );

        let oversized = SourceRecord {
            role: "user",
            ordinal: u64::MAX,
            source_time: None,
            parent_ordinals: &[],
            content: "x",
        };
        assert_eq!(
            redact_occurrence(&oversized, synthetic),
            Err(RedactionGap::Oversized),
            "an ordinal outside the u63 domain is oversized"
        );

        assert_eq!(
            redact_occurrence(&parent_matrix(2, &[2]), synthetic),
            Err(RedactionGap::Malformed),
            "a self reference is not backward"
        );
        assert_eq!(
            redact_occurrence(&parent_matrix(2, &[3]), synthetic),
            Err(RedactionGap::Malformed),
            "a forward reference is not backward"
        );
        assert_eq!(
            redact_occurrence(&parent_matrix(3, &[0, 0]), synthetic),
            Err(RedactionGap::Malformed),
            "duplicate parents are not a relationship set"
        );
        let too_many = [0u64; MAX_PARENT_ORDINALS + 1];
        assert_eq!(
            redact_occurrence(&parent_matrix(100, &too_many), synthetic),
            Err(RedactionGap::Oversized)
        );
        let at_bound: Vec<u64> = (1..=64).collect();
        assert_eq!(at_bound.len(), MAX_PARENT_ORDINALS);
        let ok = redact_occurrence(&parent_matrix(100, &at_bound), synthetic)
            .expect("parents at the bound are valid");
        assert_eq!(ok.parent_ordinals().len(), MAX_PARENT_ORDINALS);
    }

    #[test]
    fn removed_bytes_never_reach_the_output() {
        let token = github_token();
        let secrets = [
            token.clone(),
            "AKIAIOSFODNN7EXAMPLE".to_owned(),
            "super-secret-value-123".to_owned(),
            "MIIEpAIBAAKCAQ".to_owned(),
            "/etc/nginx/nginx.conf".to_owned(),
            "build.example.org".to_owned(),
            "ops@example.org".to_owned(),
            "10.0.0.7".to_owned(),
            "dXNlcjpwYXNzd29yZA==".to_owned(),
        ];
        let content = format!(
            "Authorization: Basic dXNlcjpwYXNzd29yZA==\n\
             export DEPLOY_API_TOKEN=super-secret-value-123\n\
             block {PEM_BEGIN}\nMIIEpAIBAAKCAQ\n{PEM_END}\n\
             deploy {token} to /etc/nginx/nginx.conf on build.example.org, \
             mail ops@example.org from 10.0.0.7"
        );
        let redacted = redact(&content);
        let rendered = redacted.record_value().canonical_bytes();
        let rendered = std::str::from_utf8(&rendered).expect("canonical bytes are utf-8");
        for secret in secrets {
            assert!(
                !redacted.content().contains(secret.as_str()),
                "removed bytes must not survive in the content"
            );
            assert!(
                !rendered.contains(secret.as_str()),
                "removed bytes must not survive in the record bytes"
            );
        }
        assert!(rendered.contains("[redacted:"));
    }

    #[test]
    fn replacement_output_is_opaque_to_later_detectors() {
        // A hostile renderer emits a token-shaped pseudonym; the pinned
        // credential detector runs later in the same transformation and
        // must not see it — claimed regions are opaque.
        let token_shaped = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        let source = SourceRecord {
            role: "user",
            ordinal: 0,
            source_time: None,
            parent_ordinals: &[],
            content: "log at /var/log/app.log line 12",
        };
        let redacted = redact_occurrence(&source, |class, matched| {
            let _ = (class, matched);
            token_shaped.clone()
        })
        .expect("redacts");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::AbsolutePath), 1);
        assert_eq!(
            redacted.marker_count(MarkerClass::PinnedCredential),
            0,
            "renderer output must never be re-detected"
        );
        assert!(redacted.content().contains(&token_shaped));
    }

    #[test]
    fn detector_shapes_survive_edges() {
        // An unterminated key block is destroyed to the end.
        let open_block = openssh_delimiter();
        let redacted = redact(&format!("preamble\n{open_block}\nb3BlbnNzaA"));
        assert_eq!(redacted.marker_count(MarkerClass::PrivateKeyBlock), 1);
        assert!(!redacted.content().contains("b3BlbnNzaA"));

        // Multi-byte UTF-8 is a natural boundary, never sliced
        // mid-character.
        let redacted = redact("héllo /tmp/ünïcode wörld ✓");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::AbsolutePath), 1);
        assert!(redacted.content().contains("ünïcode"));

        // Header matching is case-insensitive and keeps the name.
        let redacted = redact("proxy-authorization: Basic dXNlcjpwYXNzd29yZA==");
        assert_eq!(redacted.marker_count(MarkerClass::AuthorizationHeader), 1);
        assert!(redacted.content().starts_with("proxy-authorization:"));

        // Entropy guards: hyphenated prose, all-letter, and all-digit
        // runs are not tokens.
        for prose in [
            "well-known-compound-words-entirely",
            "alllowercasewithnodigitsatall",
            "123456789012345678901234567890",
        ] {
            let redacted = redact(prose);
            assert_eq!(
                redacted.marker_count(MarkerClass::HighEntropyToken),
                0,
                "prose runs are not token candidates"
            );
        }

        // IP shapes: a dotted quad survives a sentence period; IPv6
        // needs its compression or four groups; prose times stay put.
        let redacted = redact("server 10.0.0.1 up");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::IpAddress), 1);
        let redacted = redact("reach 192.168.1.1.");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::IpAddress), 1);
        let redacted = redact("gateway fe80::1 and 2001:db8::1 ready");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::IpAddress), 2);
        let redacted = redact("at 16:44:05 utc");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::IpAddress), 0);

        // Hostname guards: versions are not hosts.
        let redacted = redact("release v1.2.3 today");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Hostname), 0);
        let redacted = redact("on host build.example.com now");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Hostname), 1);

        // A mention keeps its at-sign; a tilde home keeps its tilde.
        let redacted = redact("ping @alice and ~bob/src");
        assert_eq!(redacted.pseudonym_count(PseudonymClass::Username), 2);
        assert!(redacted.content().contains("ps_username_"));
    }

    #[test]
    fn structured_fields_survive_validation_verbatim() {
        // 2028 is a leap year, so this day exists.
        let source = SourceRecord {
            role: "tool",
            ordinal: 9,
            source_time: Some("2028-02-29T00:00:00Z"),
            parent_ordinals: &[4, 8],
            content: &github_token(),
        };
        let redacted = redact_occurrence(&source, synthetic).expect("redacts");
        assert_eq!(redacted.role(), EpisodeRole::Tool);
        assert_eq!(redacted.ordinal(), 9);
        assert_eq!(
            redacted.source_time().map(Timestamp::as_str),
            Some("2028-02-29T00:00:00Z")
        );
        assert_eq!(redacted.parent_ordinals(), &[4, 8]);

        // The leap-day check is semantic, not just grammar: 2026 is not
        // a leap year.
        let impossible = SourceRecord {
            source_time: Some("2026-02-29T00:00:00Z"),
            ..source
        };
        assert_eq!(
            redact_occurrence(&impossible, synthetic),
            Err(RedactionGap::Malformed)
        );
    }

    #[test]
    fn every_episode_role_parses_and_refuses_outside_the_closed_set() {
        assert_eq!(
            EpisodeRole::parse("assistant"),
            Some(EpisodeRole::Assistant)
        );
        assert_eq!(EpisodeRole::parse("system"), Some(EpisodeRole::System));
        assert_eq!(EpisodeRole::parse("tool"), Some(EpisodeRole::Tool));
        assert_eq!(EpisodeRole::parse("user"), Some(EpisodeRole::User));
        for unknown in ["", "Assistant", "human", "robot", "assistant "] {
            assert_eq!(EpisodeRole::parse(unknown), None);
        }
        for role in EpisodeRole::ALL {
            assert_eq!(EpisodeRole::parse(role.token()), Some(role));
        }
    }

    #[test]
    fn gap_tokens_are_content_free_and_bounded() {
        let tokens = [
            (RedactionGap::Unsupported, "unsupported"),
            (RedactionGap::Malformed, "malformed"),
            (RedactionGap::Oversized, "oversized"),
            (RedactionGap::ResourceExhausted, "resource_exhausted"),
            (RedactionGap::DetectorFailed, "detector_failed"),
        ];
        for (gap, token) in tokens {
            assert_eq!(gap.token(), token);
            assert!(!gap.to_string().is_empty());
        }
    }
}
