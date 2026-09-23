// SPDX-License-Identifier: Apache-2.0

//! The immutable upload retry state (plan Sections 7.4, 7.8, and 7.9).
//!
//! One spool entry is one upload promise: the occurrence it carries is
//! identified once, at spool creation, and every later attempt re-sends
//! that same promise until a receipt proves it durable. Three things are
//! frozen in that moment and never change for the entry's life:
//!
//! - the **request ID** — a `UUIDv7` minted exactly once when the entry
//!   is frozen (plan Section 7.4);
//! - the **occurrence ID** — the content-derived identity the capture
//!   path computed (plan Section 7.4; `occurrence-v1`);
//! - the **upload-attestation ID** — derived from the occurrence, the
//!   uploader, and the frozen request (`attestation-v1`), so every
//!   attempt of this entry is auditable as one attestation.
//!
//! Everything that must vary per attempt stays outside the frozen rows:
//! the uploader key ID, the authorization epoch, and the authorization
//! timestamp are minted fresh for every attempt ([`AttemptAuthorization`]),
//! which is what lets a retry outside the five-minute authorization
//! window — or after a key rotation — re-authorize without changing
//! occurrence or attestation identity (plan Section 7.2). The frozen
//! envelope facts deliberately have no column that could hold a
//! per-attempt value; the protocol's envelope grammar rejects those
//! member names outright.
//!
//! # The retry schedule
//!
//! Retryable failures use full jitter starting at one second, doubling
//! to a 15-minute cap, and continue while the spool entry is retained;
//! there is no arbitrary attempt limit (plan Section 7.8). The schedule
//! is written *before* the attempt it schedules: [`claim_due_upload`]
//! atomically increments `attempt_count` and sets `next_attempt_at` to
//! the full-jitter delay that applies if this attempt's outcome is never
//! recorded — so a process death mid-attempt cannot tight-loop, and a
//! retryable failure needs no second write. A success ends the entry's
//! life at the acknowledgement transaction, and the next entry starts
//! from the one-second base again: success resets the backoff.
//!
//! The delay is one uniform draw over `[0, 2^failures × base)` capped at
//! the 15-minute ceiling (AWS-style *full jitter*). Randomness comes
//! from the operating system through [`Jitter`] and is injectable so the
//! schedule is deterministic under test. The persisted `next_attempt_at`
//! is RFC 3339 UTC at millisecond precision; it is written and compared
//! as text, so due-ness comparisons are well ordered only within that
//! shape — [`state_now`] produces it.
//!
//! # The locked error matrix
//!
//! Every error body carries a stable code and a `retryable` boolean, and
//! the registry's class table (`tools/error-codes.toml`, frozen in
//! registry schema v1) fixes what the client does next. [`decide`] maps
//! one observed [`UploadFailure`] to the one [`RetryDecision`] the
//! matrix allows:
//!
//! - **retry** — lost responses, throttles, transient server failures;
//!   the entry re-enters the claim schedule already laid down at claim
//!   time, with fresh authorization and the identical frozen envelope;
//! - **quarantine the artifact** — poison input; the entry stops being
//!   attempted, other entries continue ([`quarantine_upload`]);
//! - **pause for linking** — unlinked, revoked, or forbidden uploaders;
//!   the engine pauses its lanes until the link or key rotation
//!   completes, then the same frozen identity retries;
//! - **stop the source and page the operator** — integrity conflict;
//! - **rechunk** — a splittable 413, resolved in the capture lane;
//! - **quarantine and report a coverage gap** — an unsplittable record.
//!
//! Quarantine is the one matrix action with durable local state of its
//! own: a quarantined entry is excluded from claiming from then on,
//! across restarts, so poisoned history can never storm the service
//! again. Pauses and source stops scope beyond one entry — they latch in
//! the engine's lanes, not in this module's tables.
//!
//! # Content-free diagnostics
//!
//! [`UploadError`] cannot carry runtime text: its detail is a `&'static
//! str`, and database or operating-system error strings are classified
//! at the boundary, never wrapped. Identity fields live in the state
//! database only; no type in this module renders a path, a digest, or a
//! transcript-derived value.

use std::fmt;
use std::fs::File;
use std::io::Read;

use archivist_protocol::derivation::{attestation_id, ingest_attempt_signing_input};
use archivist_protocol::vocabulary::{
    AttestationId, BlobDigest, ClientId, EnvelopeDigest, ErrorCode, IncomingChecksum, KeyId,
    OccurrenceId, RequestContentDigest, RequestId, StorageProfile, TenantId, Timestamp,
    TransportEncoding, VersionToken,
};
use rusqlite::{Connection, OptionalExtension};

use crate::spool::{self, SpoolErrorKind};
use crate::state::StateStore;

#[cfg(test)]
mod tests;

/// The full-jitter base: the first retry waits one uniform draw over
/// `[0, 1 s)` (plan Section 7.8).
pub const INITIAL_BACKOFF_MS: u64 = 1_000;

/// The full-jitter cap: no retry delay exceeds 15 minutes, however long
/// the outage (plan Section 7.8).
pub const MAX_BACKOFF_MS: u64 = 15 * 60 * 1_000;

/// The closed failure classes of an immutable-upload operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UploadErrorKind {
    /// The state database could not be read or committed.
    Unavailable,
    /// The state database remained locked beyond its busy timeout.
    Busy,
    /// A caller-supplied value is outside its grammar, the spool entry is
    /// not in a state that admits the operation, or the entry does not
    /// exist. A caller bug or a stale handle, never a runtime condition.
    InvalidInput,
    /// The spool entry already carries a frozen identity and the request
    /// being frozen disagrees with it. The committed identity always
    /// wins; this refusal is the immutability guarantee reporting an
    /// attempt to rewrite history.
    IdentityConflict,
    /// The operating-system entropy source could not be read. A retry
    /// delay or an identity drawn from anything weaker could collide
    /// across processes, so the operation refuses rather than guess.
    EntropyUnavailable,
}

impl UploadErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::Unavailable,
            Self::Busy,
            Self::InvalidInput,
            Self::IdentityConflict,
            Self::EntropyUnavailable,
        ]
    }

    /// The content-free default detail shipped with this kind. Pinned
    /// to the protocol's safe-message grammar by a unit test.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::Unavailable => "upload state operation failed",
            Self::Busy => "upload state database is locked by another process",
            Self::InvalidInput => "upload inputs or spool state are invalid",
            Self::IdentityConflict => "the spool entry already carries a different frozen identity",
            Self::EntropyUnavailable => "host randomness could not be read",
        }
    }
}

impl fmt::Display for UploadErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::InvalidInput => "invalid-input",
            Self::IdentityConflict => "identity-conflict",
            Self::EntropyUnavailable => "entropy-unavailable",
        };
        formatter.write_str(token)
    }
}

/// Why an immutable-upload operation failed: a closed class plus
/// content-free context.
///
/// The type is incapable of carrying path, identity, SQL, or
/// operating-system error text by construction — the only string field
/// is a static literal, and driver errors are classified, never wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UploadError {
    kind: UploadErrorKind,
    detail: &'static str,
}

impl UploadError {
    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: UploadErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// Build an error with a static, content-free detail other than the
    /// kind's default.
    #[must_use]
    pub const fn with_detail(kind: UploadErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> UploadErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for UploadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "upload {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for UploadError {}

/// The identity frozen at spool creation and re-sent unchanged by every
/// attempt (plan Sections 7.4 and 7.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenUpload {
    request: RequestId,
    occurrence: OccurrenceId,
    attestation: AttestationId,
}

impl FrozenUpload {
    /// The frozen request identity: minted once, retried unchanged.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request
    }

    /// The frozen occurrence identity: derived from content, so retries
    /// and replicas converge on one archive object.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence
    }

    /// The frozen upload-attestation identity: derived from the
    /// occurrence, the uploader, and the request.
    #[must_use]
    pub const fn attestation_id(&self) -> &AttestationId {
        &self.attestation
    }
}

/// The delegation relation the attestation records (`upload_attestations.
/// relation`): a direct upload or a relayed one. Both stay separately
/// auditable per uploader and request (STO-013).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UploadRelation {
    /// The linked uploader holds the payload itself.
    Direct,
    /// The uploader relays another client's upload.
    Relay,
}

impl UploadRelation {
    /// The schema token recorded in `upload_attestations.relation`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Relay => "relay",
        }
    }
}

/// The immutable envelope facts frozen with the request at spool
/// creation (plan Section 7.3): the identity inputs the server re-derives,
/// the digest/size pair that names the payload, and the capture
/// timestamps. Per-attempt authorization facts are deliberately absent —
/// they are never frozen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreezeUpload<'a> {
    /// The spool entry this upload promise belongs to.
    pub spool_entry_id: &'a RequestId,
    /// The issuer-created tenant (plan Section 7.4).
    pub tenant_id: &'a TenantId,
    /// The client that captured the source.
    pub origin_client_id: &'a ClientId,
    /// The client whose uploader identity signs each attempt.
    pub uploader_client_id: &'a ClientId,
    /// The content-derived occurrence identity.
    pub occurrence_id: &'a OccurrenceId,
    /// The envelope schema version token (for example `envelope-v1`).
    pub envelope_version: &'a VersionToken,
    /// The named canonical storage profile.
    pub storage_profile: StorageProfile,
    /// The declared transport encoding of the payload part.
    pub transport_encoding: Option<TransportEncoding>,
    /// Canonical uncompressed SHA-256 — the blob identity (STO-001).
    pub canonical_digest: &'a BlobDigest,
    /// Checksum of the payload as transported (PI-02).
    pub incoming_checksum: &'a IncomingChecksum,
    /// Canonical uncompressed size, in bytes.
    pub canonical_size: u64,
    /// Transported size, in bytes.
    pub transport_size: u64,
    /// The source-side instant the range ends at, when the source
    /// exposes one.
    pub source_at: Option<&'a Timestamp>,
    /// The capture instant.
    pub captured_at: &'a Timestamp,
    /// The instant the envelope was created.
    pub envelope_created_at: &'a Timestamp,
    /// The delegation relation the attestation records.
    pub relation: UploadRelation,
}

/// Freeze one upload: mint the request ID, derive the attestation ID,
/// and commit the `frozen_requests` and `upload_attestations` rows in
/// one transaction (plan Sections 7.4 and 7.9).
///
/// Freezing happens once, in the capture flow that materialized the
/// bundle and before the entry becomes claimable — [`claim_due_upload`]
/// only selects frozen entries, so a crash between the two steps leaves
/// the entry quietly un-claimable until the capture flow re-freezes it.
///
/// Re-freezing a spool entry converges: when the entry already carries a
/// frozen identity, that identity is returned unchanged and every frozen
/// field is checked against the committed rows — any disagreement is the
/// [`UploadErrorKind::IdentityConflict`] refusal, never a silent
/// rewrite. The committed identity always wins, because attempts may
/// already have been made under it. The entry itself must exist and be
/// `materialized`; anything else is refused.
///
/// # Errors
///
/// [`UploadErrorKind::InvalidInput`] when the spool entry is missing or
/// not `materialized`, or a size cannot be recorded in the state
/// schema; [`UploadErrorKind::IdentityConflict`] when the entry already
/// carries a different frozen identity; [`UploadErrorKind::Unavailable`]
/// or [`UploadErrorKind::Busy`] when the state database fails.
pub fn freeze_upload(
    store: &mut StateStore,
    fields: &FreezeUpload<'_>,
) -> Result<FrozenUpload, UploadError> {
    let canonical_size = recorded_size(fields.canonical_size, "canonical")?;
    let transport_size = recorded_size(fields.transport_size, "transport")?;
    validate_freeze_timestamps(fields)?;

    let transaction = store
        .connection_mut()
        .transaction()
        .map_err(|ref err| classify_sql(err))?;
    let state: Option<String> = transaction
        .query_row(
            "SELECT state FROM spool_entries WHERE spool_entry_id = ?1",
            rusqlite::params![fields.spool_entry_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|ref err| classify_sql(err))?;
    let Some(state) = state else {
        return Err(absent_spool_entry());
    };
    if state != "materialized" {
        return Err(UploadError::with_detail(
            UploadErrorKind::InvalidInput,
            "only a materialized spool entry can be frozen",
        ));
    }

    let existing = CommittedFreeze::load(&transaction, fields.spool_entry_id)?;
    let frozen = if let Some(committed) = existing {
        committed.assert_matches(fields, canonical_size, transport_size)?;
        committed.frozen
    } else {
        let request_id = spool::mint_uuid_v7().map_err(map_mint_error)?;
        let attestation =
            attestation_id(fields.occurrence_id, fields.uploader_client_id, &request_id);
        let now = state_now_conn(&transaction).ok_or_else(|| {
            UploadError::with_detail(
                UploadErrorKind::Unavailable,
                "the state database clock is unreadable",
            )
        })?;
        transaction
            .execute(
                "INSERT INTO frozen_requests (
                         request_id, spool_entry_id, tenant_id, origin_client_id,
                         uploader_client_id, occurrence_id, envelope_version,
                         storage_profile, transport_encoding, canonical_digest,
                         incoming_checksum, canonical_size, transport_size,
                         source_at, captured_at, envelope_created_at, frozen_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                             ?13, ?14, ?15, ?16, ?17)",
                rusqlite::params![
                    request_id.as_str(),
                    fields.spool_entry_id.as_str(),
                    fields.tenant_id.as_str(),
                    fields.origin_client_id.as_str(),
                    fields.uploader_client_id.as_str(),
                    fields.occurrence_id.to_hex(),
                    fields.envelope_version.as_str(),
                    fields.storage_profile.token(),
                    fields.transport_encoding.map(|encoding| encoding.token()),
                    fields.canonical_digest.to_hex(),
                    fields.incoming_checksum.to_hex(),
                    canonical_size,
                    transport_size,
                    fields.source_at.map(Timestamp::as_str),
                    fields.captured_at.as_str(),
                    fields.envelope_created_at.as_str(),
                    now.as_str(),
                ],
            )
            .map_err(|ref err| classify_sql(err))?;
        transaction
            .execute(
                "INSERT INTO upload_attestations (
                         attestation_id, tenant_id, occurrence_id, origin_client_id,
                         uploader_client_id, request_id, relation, recorded_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    attestation.to_hex(),
                    fields.tenant_id.as_str(),
                    fields.occurrence_id.to_hex(),
                    fields.origin_client_id.as_str(),
                    fields.uploader_client_id.as_str(),
                    request_id.as_str(),
                    fields.relation.token(),
                    now.as_str(),
                ],
            )
            .map_err(|ref err| classify_sql(err))?;
        FrozenUpload {
            request: request_id,
            occurrence: *fields.occurrence_id,
            attestation,
        }
    };
    transaction.commit().map_err(|ref err| classify_sql(err))?;
    Ok(frozen)
}

/// Load the frozen identity of one spool entry, when it has one: the
/// read half of the freeze contract, for engines and diagnostics.
///
/// # Errors
///
/// [`UploadErrorKind::Unavailable`] or [`UploadErrorKind::Busy`] when
/// the state database fails, [`UploadErrorKind::IdentityConflict`] when
/// a committed row is outside its grammar.
pub fn frozen_upload(
    store: &StateStore,
    spool_entry_id: &RequestId,
) -> Result<Option<FrozenUpload>, UploadError> {
    CommittedFreeze::load(store.connection(), spool_entry_id)
        .map(|committed| committed.map(|row| row.frozen))
}

/// One due upload, claimed atomically with the schedule of the retry
/// that follows if this attempt's outcome is never recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryClaim {
    frozen: FrozenUpload,
    spool_entry_id: RequestId,
    bundle_name: String,
    envelope_digest: String,
    size_bytes: u64,
    attempt_count: u64,
    retry_delay_ms: u64,
}

impl RetryClaim {
    /// The frozen identity this attempt re-sends.
    #[must_use]
    pub const fn frozen(&self) -> &FrozenUpload {
        &self.frozen
    }

    /// The spool entry identity.
    #[must_use]
    pub const fn spool_entry_id(&self) -> &RequestId {
        &self.spool_entry_id
    }

    /// The bundle's file name inside the spool directory.
    #[must_use]
    pub fn bundle_name(&self) -> &str {
        &self.bundle_name
    }

    /// The lowercase-hex SHA-256 of the bundle bytes, as recorded by the
    /// spool row.
    #[must_use]
    pub fn envelope_digest(&self) -> &str {
        &self.envelope_digest
    }

    /// The bundle size in bytes.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// The attempt number this claim represents: 1 for the first attempt
    /// of the entry, and unbounded — no code path refuses an attempt
    /// because of how many came before it.
    #[must_use]
    pub const fn attempt_count(&self) -> u64 {
        self.attempt_count
    }

    /// The full-jitter delay, in milliseconds, already persisted as the
    /// entry's `next_attempt_at`: the wait that applies from *now* if
    /// this attempt's outcome is never recorded, or the wait the engine
    /// observes before re-claiming after a retryable failure.
    #[must_use]
    pub const fn retry_delay_ms(&self) -> u64 {
        self.retry_delay_ms
    }
}

/// Claim one due upload: pick the longest-waiting due frozen entry that
/// is not quarantined, increment its attempt count, and persist its
/// next-attempt schedule, all in one transaction.
///
/// Due means `materialized`, frozen, not quarantined, and never
/// attempted or past its `next_attempt_at`. Candidates are ordered by
/// that schedule (never-attempted entries first), then by spool entry
/// identity, so the choice is stable for one state snapshot and never
/// depends on map iteration. The claim is what makes an attempt
/// crash-safe: the attempt count and the full-jitter retry delay are
/// durable before any network I/O, so a process death mid-attempt
/// degrades into one properly delayed retry instead of a tight loop.
///
/// The delay indexes the failures already recorded: the first attempt
/// schedules a draw over `[0, 1 s)`, the second over `[0, 2 s)`, and so
/// on to the cap ([`RetryPolicy`]). A retryable failure therefore needs
/// no further write; a success ends the entry at the acknowledgement
/// transaction; the matrix's non-retry actions ([`decide`]) act on the
/// claim's outcome.
///
/// `now` fixes the due boundary and the row's `updated_at` stamp; read
/// it once per scheduling cycle with [`state_now`].
///
/// # Errors
///
/// [`UploadErrorKind::EntropyUnavailable`] when the jitter source
/// cannot deliver randomness; [`UploadErrorKind::Unavailable`] or
/// [`UploadErrorKind::Busy`] when the state database fails. A failed
/// claim changes nothing.
pub fn claim_due_upload(
    store: &mut StateStore,
    now: &Timestamp,
    policy: &RetryPolicy,
    jitter: &mut impl Jitter,
) -> Result<Option<RetryClaim>, UploadError> {
    let transaction = store
        .connection_mut()
        .transaction()
        .map_err(|ref err| classify_sql(err))?;
    let candidate: Option<(String, i64)> = transaction
        .query_row(
            "SELECT se.spool_entry_id, se.attempt_count
             FROM spool_entries se
             JOIN frozen_requests fr ON fr.spool_entry_id = se.spool_entry_id
             WHERE se.state = 'materialized'
               AND (se.next_attempt_at IS NULL OR se.next_attempt_at <= ?1)
               AND NOT EXISTS (
                   SELECT 1 FROM quarantined_uploads q
                   WHERE q.spool_entry_id = se.spool_entry_id)
             ORDER BY se.next_attempt_at, se.spool_entry_id
             LIMIT 1",
            rusqlite::params![now.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|ref err| classify_sql(err))?;
    let Some((spool_entry_id, attempt_count)) = candidate else {
        return Ok(None);
    };
    let attempt_count = u64::try_from(attempt_count).map_err(|_| {
        UploadError::with_detail(UploadErrorKind::Unavailable, "attempt count is negative")
    })?;
    let entry_id = RequestId::parse(&spool_entry_id).map_err(|_| {
        UploadError::with_detail(
            UploadErrorKind::Unavailable,
            "spool identity is outside its grammar",
        )
    })?;

    let retry_delay_ms = policy.full_jitter_ms(attempt_count, jitter)?;
    // SQLite's time modifiers have no millisecond unit — an `ms`
    // directive would make `strftime` return null and silently drop
    // the entry back into the due set — so the delay is a fractional
    // seconds directive, applied at the same millisecond precision the
    // schedule stores.
    let delay_directive = format!(
        "+{}.{:03} seconds",
        retry_delay_ms / 1_000,
        retry_delay_ms % 1_000
    );
    let changed = transaction
        .execute(
            "UPDATE spool_entries
             SET attempt_count = attempt_count + 1,
                 next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', ?2, ?3),
                 updated_at = ?2
             WHERE spool_entry_id = ?1 AND state = 'materialized'",
            rusqlite::params![entry_id.as_str(), now.as_str(), delay_directive,],
        )
        .map_err(|ref err| classify_sql(err))?;
    if changed != 1 {
        return Err(UploadError::with_detail(
            UploadErrorKind::Unavailable,
            "the claimed entry changed state during the claim",
        ));
    }

    let claimed = load_claim(&transaction, &entry_id, retry_delay_ms)?;
    transaction.commit().map_err(|ref err| classify_sql(err))?;
    Ok(Some(claimed))
}

/// Load one claimed entry's full row after the schedule update.
fn load_claim(
    conn: &Connection,
    spool_entry_id: &RequestId,
    retry_delay_ms: u64,
) -> Result<RetryClaim, UploadError> {
    let row = conn
        .query_row(
            "SELECT se.bundle_name, se.envelope_digest, se.size_bytes, se.attempt_count,
                    fr.request_id, fr.occurrence_id, ua.attestation_id
             FROM spool_entries se
             JOIN frozen_requests fr ON fr.spool_entry_id = se.spool_entry_id
             JOIN upload_attestations ua ON ua.request_id = fr.request_id
             WHERE se.spool_entry_id = ?1",
            rusqlite::params![spool_entry_id.as_str()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .map_err(|ref err| classify_sql(err))?;
    let (bundle_name, envelope_digest, size_bytes, attempt_count, request, occurrence, attestation) =
        row;
    let size_bytes = u64::try_from(size_bytes).map_err(|_| {
        UploadError::with_detail(UploadErrorKind::Unavailable, "bundle size is negative")
    })?;
    let attempt_count = u64::try_from(attempt_count).map_err(|_| {
        UploadError::with_detail(UploadErrorKind::Unavailable, "attempt count is negative")
    })?;
    let request_id =
        RequestId::parse(&request).map_err(|_| ungrammatical_committed("request identity"))?;
    let occurrence_id = OccurrenceId::parse(&occurrence)
        .map_err(|_| ungrammatical_committed("occurrence identity"))?;
    let attestation_id = AttestationId::parse(&attestation)
        .map_err(|_| ungrammatical_committed("attestation identity"))?;
    Ok(RetryClaim {
        frozen: FrozenUpload {
            request: request_id,
            occurrence: occurrence_id,
            attestation: attestation_id,
        },
        spool_entry_id: spool_entry_id.clone(),
        bundle_name,
        envelope_digest,
        size_bytes,
        attempt_count,
        retry_delay_ms,
    })
}

/// One attempt's fresh authorization: the uploader key, the
/// authorization epoch, and the authorization timestamp (plan
/// Section 7.2).
///
/// A new value is minted for every attempt and never stored in the
/// frozen upload rows. After a key rotation the same frozen upload is
/// re-authorized under the rotated key and the current epoch — the
/// occurrence and attestation identities do not move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptAuthorization {
    uploader_key_id: KeyId,
    authorization_epoch: u64,
    authorization_timestamp: Timestamp,
}

impl AttemptAuthorization {
    /// Mint the authorization for one attempt. Refuses epoch zero — the
    /// epoch counts rotations from one — and a timestamp outside the
    /// calendar.
    ///
    /// # Errors
    ///
    /// [`UploadErrorKind::InvalidInput`] when the epoch is zero or the
    /// timestamp is not a real calendar instant.
    pub fn mint(
        uploader_key_id: KeyId,
        authorization_epoch: u64,
        authorization_timestamp: Timestamp,
    ) -> Result<Self, UploadError> {
        if authorization_epoch == 0 {
            return Err(UploadError::with_detail(
                UploadErrorKind::InvalidInput,
                "the authorization epoch is never zero",
            ));
        }
        if !authorization_timestamp.calendar_valid() {
            return Err(UploadError::with_detail(
                UploadErrorKind::InvalidInput,
                "the authorization timestamp is not a real calendar instant",
            ));
        }
        Ok(Self {
            uploader_key_id,
            authorization_epoch,
            authorization_timestamp,
        })
    }

    /// The uploader key ID this attempt presents.
    #[must_use]
    pub const fn uploader_key_id(&self) -> &KeyId {
        &self.uploader_key_id
    }

    /// The authorization epoch this attempt presents.
    #[must_use]
    pub const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }

    /// The fresh authorization timestamp of this one attempt.
    #[must_use]
    pub const fn authorization_timestamp(&self) -> &Timestamp {
        &self.authorization_timestamp
    }

    /// The exact bytes this attempt's Ed25519 signature covers
    /// (`ingest-attempt-v1`, plan Section 7.2): the route facts and
    /// digests of the immutable request plus this attempt's fresh
    /// authorization. The signing itself belongs to the transport seam
    /// holding the uploader's private key; nothing here sees it.
    // The registry pins the covered fields, so the arity is the contract.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn signing_input(
        &self,
        http_method: &str,
        route: &str,
        content_type: &str,
        request_content_digest: &RequestContentDigest,
        envelope_digest: &EnvelopeDigest,
        payload_canonical_digest: &BlobDigest,
        payload_transport_digest: &IncomingChecksum,
    ) -> Vec<u8> {
        ingest_attempt_signing_input(
            http_method,
            route,
            content_type,
            request_content_digest,
            envelope_digest,
            payload_canonical_digest,
            payload_transport_digest,
            &self.uploader_key_id,
            self.authorization_epoch,
            &self.authorization_timestamp,
        )
    }
}

/// The full-jitter retry schedule of the locked matrix (plan
/// Section 7.8): bounded exponential growth from one second to a
/// 15-minute cap, one uniform draw inside the bound, and no attempt
/// limit anywhere in the arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    base_ms: u64,
    cap_ms: u64,
}

impl RetryPolicy {
    /// The policy from explicit bounds — synthetic schedules and tests.
    /// The base is floored at one millisecond so the doubling is always
    /// defined; a cap below the base simply becomes the delay.
    #[must_use]
    pub const fn new(base_ms: u64, cap_ms: u64) -> Self {
        Self {
            base_ms: if base_ms == 0 { 1 } else { base_ms },
            cap_ms,
        }
    }

    /// The plan's policy: one-second base, 15-minute cap.
    #[must_use]
    pub const fn plan() -> Self {
        Self::new(INITIAL_BACKOFF_MS, MAX_BACKOFF_MS)
    }

    /// The schedule base, in milliseconds.
    #[must_use]
    pub const fn base_ms(&self) -> u64 {
        self.base_ms
    }

    /// The schedule cap, in milliseconds.
    #[must_use]
    pub const fn cap_ms(&self) -> u64 {
        self.cap_ms
    }

    /// The un-jittered bound after `failures_so_far` recorded failures:
    /// the base doubling, saturated at the cap. The doubling is a
    /// checked multiply — a shift only bounds its own amount, so an
    /// unchecked `<<` would wrap to a near-zero bound in the fifties
    /// and tight-loop those attempts — and once it overflows, or the
    /// failures count leaves the shift's range entirely, the bound is
    /// the cap. The schedule never refuses an attempt for having tried
    /// before.
    #[must_use]
    pub fn upper_bound_ms(&self, failures_so_far: u64) -> u64 {
        let doubled = match u32::try_from(failures_so_far) {
            Ok(shift) if shift < 64 => self.base_ms.checked_mul(1u64 << shift),
            _ => None,
        }
        .unwrap_or(self.cap_ms);
        doubled.min(self.cap_ms)
    }

    /// One full-jitter delay: a uniform draw over
    /// `[0, upper_bound_ms(failures_so_far))`.
    ///
    /// # Errors
    ///
    /// [`UploadErrorKind::EntropyUnavailable`] when the jitter source
    /// cannot deliver randomness.
    pub fn full_jitter_ms(
        &self,
        failures_so_far: u64,
        jitter: &mut impl Jitter,
    ) -> Result<u64, UploadError> {
        let bound = self.upper_bound_ms(failures_so_far);
        let bits = jitter.random_bits()?;
        Ok(uniform_below(bits, bound))
    }
}

/// The randomness the full-jitter draw consumes. Production uses
/// [`OsJitter`]; tests pin the draw.
pub trait Jitter {
    /// Draw 64 uniform bits for one delay computation.
    ///
    /// # Errors
    ///
    /// [`UploadErrorKind::EntropyUnavailable`] when the source cannot
    /// deliver randomness; the caller must treat the operation as
    /// failed, not as "some bits were drawn".
    fn random_bits(&mut self) -> Result<u64, UploadError>;
}

/// The operating-system entropy source, held open for the schedule's
/// life. There is deliberately no userland fallback: a schedule drawn
/// from time or process state could synchronize across processes and
/// stampede the server the outage just released.
pub struct OsJitter {
    device: File,
}

impl OsJitter {
    /// Open the entropy source.
    ///
    /// # Errors
    ///
    /// [`UploadErrorKind::EntropyUnavailable`] when the device cannot be
    /// opened. The error never names the device path.
    pub fn open() -> Result<Self, UploadError> {
        let device = File::open("/dev/urandom")
            .map_err(|_| UploadError::of_kind(UploadErrorKind::EntropyUnavailable))?;
        Ok(Self { device })
    }
}

impl Jitter for OsJitter {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        let mut bytes = [0u8; 8];
        self.device
            .read_exact(&mut bytes)
            .map_err(|_| UploadError::of_kind(UploadErrorKind::EntropyUnavailable))?;
        Ok(u64::from_be_bytes(bytes))
    }
}

/// One uniform draw over `[0, upper)` from 64 random bits: the
/// 128-bit product's high half. The result is strictly below `upper`
/// and unbiased enough for a delay.
#[must_use]
pub fn uniform_below(bits: u64, upper: u64) -> u64 {
    // The product's high 64 bits are strictly less than `upper` (which
    // fits u64), so the narrowing cast cannot truncate.
    #[allow(clippy::cast_possible_truncation)]
    let high = (u128::from(bits) * u128::from(upper)) >> 64;
    high as u64
}

/// One upload failure, as the attempt surface observed it: either no
/// response existed at all, or the response's status, or the stable
/// error body the protocol guarantees (plan Section 7.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UploadFailure {
    /// The request never produced a response — connection failure,
    /// timeout, or a lost response. The registry's `network` class.
    ResponseLost,
    /// A response arrived but carried no parseable archivist error
    /// body; only its HTTP status is known.
    Status(u16),
    /// The response carried the stable error body: its registry code
    /// and `retryable` boolean.
    Registry {
        /// The stable wire code (`domain.condition`).
        code: ErrorCode,
        /// The body's `retryable` boolean.
        retryable: bool,
    },
}

/// What the locked matrix directs the engine to do after one failure
/// (plan Section 7.8; the registry's frozen `client_action` column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetryDecision {
    /// Retry the identical envelope with fresh authorization. The wait
    /// is the schedule already persisted at claim time; nothing is
    /// quarantined and nothing pauses. The registry renders this one
    /// decision with two class tokens — `backoff_and_retry` for the
    /// throttle and server-failure classes, `retry_identical_envelope`
    /// for the network class — but the client action is the same:
    /// re-send the frozen envelope, never a re-derived one.
    Retry,
    /// A splittable 413: resolve in the capture lane by rechunking at a
    /// record boundary. The entry keeps retrying until the replacement
    /// range supersedes it.
    Rechunk,
    /// Poison input: quarantine the artifact and continue other sources.
    QuarantineArtifact,
    /// An unsplittable record: quarantine the artifact and report the
    /// coverage gap.
    QuarantineAndReportGap,
    /// Authorization refused: pause uploads until the link or key
    /// rotation completes, then retry the same frozen identity.
    PauseForLinking,
    /// Integrity conflict: stop the affected tenant source and page the
    /// operator. Never retried into an overwrite loop.
    StopSourceAndPage,
}

impl RetryDecision {
    /// The registry's frozen `client_action` token for this decision —
    /// the closed rendering diagnostics and status output use. The one
    /// ambiguity is retry, where the registry names the network class's
    /// identical action with its own token (see [`RetryDecision::Retry`]);
    /// this renders the throttle/server-failure token, and a surface
    /// that knows the failure class can prefer it.
    #[must_use]
    pub const fn action_token(self) -> &'static str {
        match self {
            Self::Retry => "backoff_and_retry",
            Self::Rechunk => "rechunk_and_resubmit",
            Self::QuarantineArtifact => "quarantine_artifact",
            Self::QuarantineAndReportGap => "quarantine_and_report_gap",
            Self::PauseForLinking => "pause_for_linking",
            Self::StopSourceAndPage => "stop_and_page_operator",
        }
    }
}

/// Apply the locked matrix to one observed failure (plan Section 7.8).
///
/// The mapping is total and pure: every registered upload-path code
/// resolves through its frozen class, an HTTP status resolves through
/// the class table's status rows, and anything unclassifiable falls
/// back on the body's `retryable` boolean when there is one, and on
/// quarantine when there is not — an unknown condition is never a
/// license to storm the service.
#[must_use]
pub fn decide(failure: &UploadFailure) -> RetryDecision {
    match failure {
        UploadFailure::ResponseLost => RetryDecision::Retry,
        UploadFailure::Status(status) => decide_status(*status),
        UploadFailure::Registry { code, retryable } => classify_registry_code(code.as_str())
            .unwrap_or({
                // An unregistered but well-formed code: the body's own
                // `retryable` boolean is the cross-version contract.
                // Without a body classification there is none, so the
                // fail-closed reading wins.
                if *retryable {
                    RetryDecision::Retry
                } else {
                    RetryDecision::QuarantineArtifact
                }
            }),
    }
}

/// The matrix rows that key on the HTTP status alone: the class table's
/// status columns. A status-only 413 reads as the splittable class —
/// the recoverable one; the body's code is what distinguishes the
/// unsplittable record. An unknown status fails closed (retry only the
/// server-failure range, quarantine everything else).
fn decide_status(status: u16) -> RetryDecision {
    match status {
        401 | 403 => RetryDecision::PauseForLinking,
        409 => RetryDecision::StopSourceAndPage,
        413 => RetryDecision::Rechunk,
        408 | 425 | 429 | 500 | 502 | 503 | 504 => RetryDecision::Retry,
        // 400, 415, and every status the matrix does not name fail
        // closed: quarantine, never a retry.
        _ => RetryDecision::QuarantineArtifact,
    }
}

/// The registry codes the upload path can observe, mapped through their
/// frozen classes. `None` — a code outside this closed mapping — sends
/// the caller to the `retryable` fallback. The client-local classes
/// (`cli.*`, `client.*`) never arrive as server responses and are
/// deliberately absent.
fn classify_registry_code(code: &str) -> Option<RetryDecision> {
    let decision = match code {
        // request_invalid: poison input.
        "envelope.malformed"
        | "envelope.version_unsupported"
        | "envelope.media_type_unsupported"
        | "envelope.schema_invalid"
        | "envelope.size_exceeded"
        | "auth.epoch_unreached"
        | "auth.key_id_mismatch"
        | "request.framing_invalid" => RetryDecision::QuarantineArtifact,
        // authorization: pause for linking or rotation.
        "auth.unlinked" | "auth.revoked" | "auth.authorization_rejected" | "auth.forbidden" => {
            RetryDecision::PauseForLinking
        }
        // integrity_conflict: stop and page.
        "storage.integrity_conflict" => RetryDecision::StopSourceAndPage,
        // payload_limit_splittable: rechunk at a record boundary.
        "request.payload_too_large" | "request.expansion_ratio_exceeded" => RetryDecision::Rechunk,
        // payload_limit_unsplittable: quarantine and report the gap.
        "request.record_too_large" => RetryDecision::QuarantineAndReportGap,
        // throttle, server_failure, network: retry.
        "request.deadline_exceeded"
        | "request.rate_limited"
        | "request.too_early"
        | "server.internal"
        | "server.storage_failure"
        | "server.unavailable"
        | "server.partial_commit"
        | "server.upstream_timeout"
        | "transport.connection_failed"
        | "transport.response_lost" => RetryDecision::Retry,
        _ => return None,
    };
    Some(decision)
}

/// Why an entry is removed from the retry set: the two quarantine
/// classes of the locked matrix, recorded as their registry class
/// tokens.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QuarantineReason {
    /// The server refused the envelope or its media (`request_invalid`).
    PoisonInput,
    /// One record alone exceeds an unsplittable limit
    /// (`payload_limit_unsplittable`).
    UnsplittableRecord,
}

impl QuarantineReason {
    /// The registry class token recorded in `quarantined_uploads.reason`.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::PoisonInput => "request_invalid",
            Self::UnsplittableRecord => "payload_limit_unsplittable",
        }
    }
}

/// Quarantine one spool entry: remove it from the retry set durably, so
/// poisoned history can neither storm the service again nor block the
/// entries behind it (plan Section 7.8: "quarantine artifact; continue
/// other sources").
///
/// The bundle is retained — its bytes keep occupying the spool and keep
/// counting against the pressure cap — so an operator can inspect the
/// artifact and report the coverage gap; removal is an operator action,
/// never a retry-path side effect. Quarantining an already-quarantined
/// entry is a no-op that reports `false`: the first reason wins, and a
/// quarantine decision is never rewritten.
///
/// Returns whether this call quarantined the entry.
///
/// # Errors
///
/// [`UploadErrorKind::InvalidInput`] when the spool entry does not
/// exist; [`UploadErrorKind::Unavailable`] or [`UploadErrorKind::Busy`]
/// when the state database fails.
pub fn quarantine_upload(
    store: &mut StateStore,
    spool_entry_id: &RequestId,
    reason: QuarantineReason,
    now: &Timestamp,
) -> Result<bool, UploadError> {
    let changed = store
        .connection_mut()
        .execute(
            "INSERT OR IGNORE INTO quarantined_uploads (
                 spool_entry_id, reason, quarantined_at)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![spool_entry_id.as_str(), reason.token(), now.as_str(),],
        )
        .map_err(|ref err| classify_constraint(err))?;
    Ok(changed == 1)
}

/// Whether one spool entry is quarantined.
///
/// # Errors
///
/// [`UploadErrorKind::Unavailable`] or [`UploadErrorKind::Busy`] when
/// the state database fails.
pub fn is_quarantined(store: &StateStore, spool_entry_id: &RequestId) -> Result<bool, UploadError> {
    let found: Option<i64> = store
        .connection()
        .query_row(
            "SELECT 1 FROM quarantined_uploads WHERE spool_entry_id = ?1",
            rusqlite::params![spool_entry_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(|ref err| classify_sql(err))?;
    Ok(found.is_some())
}

/// The state database's clock as an RFC 3339 UTC timestamp at
/// millisecond precision — the shape `next_attempt_at` is written in
/// and the value to hand [`claim_due_upload`], [`quarantine_upload`],
/// and every other call that needs "now" from this module.
///
/// The state database's clock is the one clock the client's durable
/// state already agrees on (the migration history uses the same
/// source); the engine's in-process waits run on the monotonic clock
/// and read this once per scheduling cycle.
///
/// # Errors
///
/// [`UploadErrorKind::Unavailable`] when the clock cannot be read or
/// produces a value outside the protocol's timestamp grammar.
pub fn state_now(store: &StateStore) -> Result<Timestamp, UploadError> {
    state_now_conn(store.connection()).ok_or_else(|| {
        UploadError::with_detail(
            UploadErrorKind::Unavailable,
            "the state database clock is unreadable",
        )
    })
}

/// The millisecond-precision database clock over any connection.
fn state_now_conn(conn: &Connection) -> Option<Timestamp> {
    let text: String = conn
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .ok()?;
    let parsed = Timestamp::parse(&text).ok()?;
    parsed.calendar_valid().then_some(parsed)
}

/// A size the state schema can record (`i64`, non-negative): the two
/// envelope size columns.
fn recorded_size(size: u64, which: &'static str) -> Result<i64, UploadError> {
    i64::try_from(size).map_err(|_| {
        UploadError::with_detail(
            UploadErrorKind::InvalidInput,
            match which {
                "canonical" => "canonical size exceeds the size the state schema can record",
                _ => "transport size exceeds the size the state schema can record",
            },
        )
    })
}

/// Reject grammar-valid timestamps that are not real calendar instants before
/// they can become part of an immutable envelope. The vocabulary deliberately
/// keeps grammar and calendar checks separate, so the state boundary must do
/// both checks explicitly.
fn validate_freeze_timestamps(fields: &FreezeUpload<'_>) -> Result<(), UploadError> {
    let valid = fields.captured_at.calendar_valid()
        && fields.envelope_created_at.calendar_valid()
        && fields.source_at.is_none_or(Timestamp::calendar_valid);
    if valid {
        Ok(())
    } else {
        Err(UploadError::with_detail(
            UploadErrorKind::InvalidInput,
            "a frozen envelope timestamp is not a real calendar instant",
        ))
    }
}

/// The error for a spool row the freeze found missing.
fn absent_spool_entry() -> UploadError {
    UploadError::with_detail(
        UploadErrorKind::InvalidInput,
        "the spool entry does not exist",
    )
}

/// The error for a committed identity row that is outside its grammar.
fn ungrammatical_committed(which: &'static str) -> UploadError {
    UploadError::with_detail(
        UploadErrorKind::IdentityConflict,
        match which {
            "request identity" => "the committed request identity is outside its grammar",
            "occurrence identity" => "the committed occurrence identity is outside its grammar",
            "attestation identity" => "the committed attestation identity is outside its grammar",
            _ => "a committed identity field is outside its grammar",
        },
    )
}

/// Map the shared identity mint's failure: its only failure mode is the
/// unreadable entropy source, and this module names that directly.
fn map_mint_error(error: spool::SpoolError) -> UploadError {
    if matches!(error.kind(), SpoolErrorKind::Unavailable) {
        UploadError::of_kind(UploadErrorKind::EntropyUnavailable)
    } else {
        UploadError::of_kind(UploadErrorKind::Unavailable)
    }
}

/// Classify a foreign-key refusal: quarantining an absent entry is a
/// caller bug, not a database failure.
fn classify_constraint(error: &rusqlite::Error) -> UploadError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(ffi, _)
            if ffi.code == rusqlite::ErrorCode::ConstraintViolation
    ) {
        absent_spool_entry()
    } else {
        classify_sql(error)
    }
}

/// Classify a driver error without keeping any of its text: the busy
/// distinction is the one worth keeping; everything else is the
/// unavailable class. Mirrors the spool and acknowledgement
/// classifiers so all surfaces report the same contention signal.
fn classify_sql(error: &rusqlite::Error) -> UploadError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(ffi, _)
            if matches!(
                ffi.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    ) {
        UploadError::of_kind(UploadErrorKind::Busy)
    } else {
        UploadError::of_kind(UploadErrorKind::Unavailable)
    }
}

/// The committed freeze of one spool entry, as its rows hold it.
struct CommittedFreeze {
    frozen: FrozenUpload,
    tenant_id: String,
    origin_client_id: String,
    uploader_client_id: String,
    envelope_version: String,
    storage_profile: String,
    transport_encoding: Option<String>,
    canonical_digest: String,
    incoming_checksum: String,
    canonical_size: i64,
    transport_size: i64,
    source_at: Option<String>,
    captured_at: String,
    envelope_created_at: String,
    relation: String,
}

impl CommittedFreeze {
    /// Load the committed freeze of one spool entry, when it has one.
    /// The identity fields are parsed through their vocabularies so a
    /// corrupt row is refused rather than echoed.
    fn load(conn: &Connection, spool_entry_id: &RequestId) -> Result<Option<Self>, UploadError> {
        let row = conn
            .query_row(
                "SELECT fr.request_id, fr.tenant_id, fr.origin_client_id,
                        fr.uploader_client_id, fr.occurrence_id, fr.envelope_version,
                        fr.storage_profile, fr.transport_encoding, fr.canonical_digest,
                        fr.incoming_checksum, fr.canonical_size, fr.transport_size,
                        fr.source_at, fr.captured_at, fr.envelope_created_at,
                        ua.attestation_id, ua.relation
                 FROM frozen_requests fr
                 LEFT JOIN upload_attestations ua ON ua.request_id = fr.request_id
                 WHERE fr.spool_entry_id = ?1",
                rusqlite::params![spool_entry_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, String>(8)?,
                        row.get::<_, String>(9)?,
                        row.get::<_, i64>(10)?,
                        row.get::<_, i64>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, String>(13)?,
                        row.get::<_, String>(14)?,
                        row.get::<_, Option<String>>(15)?,
                        row.get::<_, Option<String>>(16)?,
                    ))
                },
            )
            .optional()
            .map_err(|ref err| classify_sql(err))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let (
            request,
            tenant_id,
            origin_client_id,
            uploader_client_id,
            occurrence,
            envelope_version,
            storage_profile,
            transport_encoding,
            canonical_digest,
            incoming_checksum,
            canonical_size,
            transport_size,
            source_at,
            captured_at,
            envelope_created_at,
            attestation,
            relation,
        ) = row;
        let (Some(attestation), Some(relation)) = (attestation, relation) else {
            // A frozen request without its attestation is a broken
            // durable invariant — treat it as a conflicting committed
            // state, never as something to re-freeze over.
            return Err(UploadError::with_detail(
                UploadErrorKind::IdentityConflict,
                "the committed frozen request carries no upload attestation",
            ));
        };
        let request_id =
            RequestId::parse(&request).map_err(|_| ungrammatical_committed("request identity"))?;
        let occurrence_id = OccurrenceId::parse(&occurrence)
            .map_err(|_| ungrammatical_committed("occurrence identity"))?;
        let attestation_id = AttestationId::parse(&attestation)
            .map_err(|_| ungrammatical_committed("attestation identity"))?;
        Ok(Some(Self {
            frozen: FrozenUpload {
                request: request_id,
                occurrence: occurrence_id,
                attestation: attestation_id,
            },
            tenant_id,
            origin_client_id,
            uploader_client_id,
            envelope_version,
            storage_profile,
            transport_encoding,
            canonical_digest,
            incoming_checksum,
            canonical_size,
            transport_size,
            source_at,
            captured_at,
            envelope_created_at,
            relation,
        }))
    }

    /// Refuse unless the freeze being attempted restates exactly this
    /// committed identity.
    fn assert_matches(
        &self,
        fields: &FreezeUpload<'_>,
        canonical_size: i64,
        transport_size: i64,
    ) -> Result<(), UploadError> {
        let matches = self.frozen.occurrence == *fields.occurrence_id
            && self.tenant_id == fields.tenant_id.as_str()
            && self.origin_client_id == fields.origin_client_id.as_str()
            && self.uploader_client_id == fields.uploader_client_id.as_str()
            && self.envelope_version == fields.envelope_version.as_str()
            && self.storage_profile == fields.storage_profile.token()
            && self.transport_encoding.as_deref()
                == fields
                    .transport_encoding
                    .as_ref()
                    .map(TransportEncoding::token)
            && self.canonical_digest == fields.canonical_digest.to_hex()
            && self.incoming_checksum == fields.incoming_checksum.to_hex()
            && self.canonical_size == canonical_size
            && self.transport_size == transport_size
            && self.source_at.as_deref() == fields.source_at.map(Timestamp::as_str)
            && self.captured_at == fields.captured_at.as_str()
            && self.envelope_created_at == fields.envelope_created_at.as_str()
            && self.relation == fields.relation.token();
        if matches {
            // The derived attestation must also re-derive: it is a pure
            // function of the checked fields above and the request ID.
            let derived = attestation_id(
                &self.frozen.occurrence,
                fields.uploader_client_id,
                &self.frozen.request,
            );
            if derived == self.frozen.attestation {
                return Ok(());
            }
        }
        Err(UploadError::of_kind(UploadErrorKind::IdentityConflict))
    }
}
