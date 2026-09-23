// SPDX-License-Identifier: Apache-2.0

//! Durable receipt acknowledgement (plan Sections 5.2, 5.4, and 7.9).
//!
//! A receipt is not evidence merely because it parses or because its
//! signature verifies.  This module binds the authenticated receipt back to
//! the frozen request, its captured range, and the source that produced that
//! range.  Only after all of those checks pass does one SQLite transaction
//! retain the canonical receipt, advance the source watermark, and mark the
//! spool entry acknowledged.  The bundle file is removed only after that
//! transaction commits.

use std::fmt;

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::receipt::Receipt;
use archivist_protocol::derivation::attestation_id;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::sha256::{digest, encode_hex};
use archivist_protocol::vocabulary::{
    AttestationId, BlobDigest, ClientId, Ed25519Signature, HarnessId, KeyId, OccurrenceId,
    RequestId, SessionHash, SignatureAlgorithm, StorageOutcome, StorageProfile, TenantId,
    Timestamp,
};
use rusqlite::{Connection, OptionalExtension, Row};

use crate::spool::{Spool, SpoolErrorKind};
use crate::state::StateStore;

const STATE_ACKNOWLEDGED: &str = "acknowledged";

/// The closed failure classes of a durable acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AcknowledgementErrorKind {
    /// The receipt is not a valid v1 receipt shape.
    MalformedReceipt,
    /// The receipt's certificate chain or receipt signature is not trusted.
    UntrustedReceipt,
    /// A receipt identity, object key, range, or source binding disagrees.
    IdentityMismatch,
    /// The state database could not be read or committed.
    Unavailable,
    /// The state database remained locked beyond its busy timeout.
    Busy,
    /// The receipt was committed, but post-commit payload cleanup needs a
    /// later reconciliation pass.
    CleanupPending,
}

impl AcknowledgementErrorKind {
    /// Every acknowledgement failure class, in declaration order.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::MalformedReceipt,
            Self::UntrustedReceipt,
            Self::IdentityMismatch,
            Self::Unavailable,
            Self::Busy,
            Self::CleanupPending,
        ]
    }

    /// The content-free detail for this class.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::MalformedReceipt => "receipt does not match the v1 acknowledgement shape",
            Self::UntrustedReceipt => "receipt authority chain or signature failed verification",
            Self::IdentityMismatch => "receipt identity does not match the frozen upload",
            Self::Unavailable => "acknowledgement state operation failed",
            Self::Busy => "acknowledgement state database is locked",
            Self::CleanupPending => "acknowledgement committed and payload cleanup is pending",
        }
    }
}

impl fmt::Display for AcknowledgementErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let token = match self {
            Self::MalformedReceipt => "malformed-receipt",
            Self::UntrustedReceipt => "untrusted-receipt",
            Self::IdentityMismatch => "identity-mismatch",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::CleanupPending => "cleanup-pending",
        };
        formatter.write_str(token)
    }
}

/// Why an acknowledgement failed.  It deliberately cannot carry receipt,
/// identity, path, SQL, or operating-system error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AcknowledgementError {
    kind: AcknowledgementErrorKind,
    detail: &'static str,
}

impl AcknowledgementError {
    /// Construct the standard detail for `kind`.
    #[must_use]
    pub const fn of_kind(kind: AcknowledgementErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// Construct a content-free error with a more precise static detail.
    #[must_use]
    pub const fn with_detail(kind: AcknowledgementErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> AcknowledgementErrorKind {
        self.kind
    }

    /// The content-free detail.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for AcknowledgementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "acknowledgement {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for AcknowledgementError {}

/// The receipt bytes and the next opaque adapter cursor to commit together.
///
/// The cursor is intentionally supplied by the capture engine rather than
/// guessed from a range coordinate.  The transaction binds it to the range
/// reached by the verified receipt and keeps a separate numeric watermark so
/// out-of-order acknowledgements cannot move it backwards.
pub struct AcknowledgementRequest<'a> {
    receipt_bytes: &'a [u8],
    cursor: &'a str,
}

impl<'a> AcknowledgementRequest<'a> {
    /// Build an acknowledgement request for one frozen upload.
    #[must_use]
    pub const fn new(receipt_bytes: &'a [u8], cursor: &'a str) -> Self {
        Self {
            receipt_bytes,
            cursor,
        }
    }

    /// The signed receipt bytes.
    #[must_use]
    pub const fn receipt_bytes(&self) -> &'a [u8] {
        self.receipt_bytes
    }

    /// The adapter cursor reached by the captured range.
    #[must_use]
    pub const fn cursor(&self) -> &'a str {
        self.cursor
    }
}

/// The durable result of an acknowledgement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcknowledgedReceipt {
    request_id: RequestId,
    receipt_digest: String,
    cursor_advanced: bool,
}

impl AcknowledgedReceipt {
    /// The frozen request accepted by the receipt.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// SHA-256 of the retained canonical receipt bytes.
    #[must_use]
    pub fn receipt_digest(&self) -> &str {
        &self.receipt_digest
    }

    /// Whether this call moved the source cursor forward.  A lower range can
    /// still be acknowledged after a higher one without regressing the cursor.
    #[must_use]
    pub const fn cursor_advanced(&self) -> bool {
        self.cursor_advanced
    }
}

/// Verify and durably acknowledge one receipt.
///
/// Verification happens before any state mutation.  The transaction then
/// re-reads the complete frozen-upload chain and performs all identity checks
/// against that snapshot before inserting the verified receipt, advancing the
/// source cursor watermark, and changing the spool row to `acknowledged`.
/// `spool.remove` is called only after commit; if it fails, the committed row
/// is left for startup reconciliation and this function returns
/// [`AcknowledgementErrorKind::CleanupPending`].
pub fn acknowledge_receipt(
    spool: &Spool,
    store: &mut StateStore,
    request: AcknowledgementRequest<'_>,
    root: &PinnedAuthorityRoot,
    authority_records: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<AcknowledgedReceipt, AcknowledgementError> {
    if request.cursor().chars().count() > 1024 {
        return Err(AcknowledgementError::of_kind(
            AcknowledgementErrorKind::IdentityMismatch,
        ));
    }

    let receipt = Receipt::parse(request.receipt_bytes())
        .map_err(|_| AcknowledgementError::of_kind(AcknowledgementErrorKind::MalformedReceipt))?;
    let verified = receipt
        .verify(root, authority_records)
        .map_err(|_| AcknowledgementError::of_kind(AcknowledgementErrorKind::UntrustedReceipt))?;
    let canonical_bytes = receipt.canonical_bytes();
    let fields = ReceiptFields::parse(&canonical_bytes)?;
    if fields.tenant_id != *verified.tenant_id()
        || fields.receipt_key_id != *verified.receipt_key_id()
        || fields.commit_time != *verified.commit_time()
    {
        return Err(AcknowledgementError::of_kind(
            AcknowledgementErrorKind::IdentityMismatch,
        ));
    }

    let receipt_digest = encode_hex(&digest(&canonical_bytes));
    let (bundle_name, cursor_advanced) = {
        let transaction = store.connection_mut().transaction().map_err(classify_sql)?;
        let pending = load_pending(&transaction, &fields.request_id)?;
        validate_binding(&pending, &fields)?;

        let existing = transaction
            .query_row(
                "SELECT receipt_digest, signature_verified
                 FROM receipts WHERE request_id = ?1",
                rusqlite::params![fields.request_id.as_str()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(classify_sql)?;

        match existing {
            Some((digest, verified)) if digest == receipt_digest && verified == 1 => {
                // A prior state repair may have retained only the receipt
                // metadata.  Fill the evidence column in the same transaction
                // without creating a second receipt row.
                transaction
                    .execute(
                        "UPDATE receipts SET receipt_bytes = ?1
                         WHERE request_id = ?2 AND receipt_bytes IS NULL",
                        rusqlite::params![&canonical_bytes, fields.request_id.as_str()],
                    )
                    .map_err(classify_sql)?;
            }
            Some(_) => {
                return Err(AcknowledgementError::of_kind(
                    AcknowledgementErrorKind::IdentityMismatch,
                ));
            }
            None if pending.state == STATE_ACKNOWLEDGED => {
                // An acknowledged spool row without its receipt is a
                // broken durable invariant.  Do not repair it by inventing
                // evidence after the fact; leave it for reconciliation.
                return Err(AcknowledgementError::of_kind(
                    AcknowledgementErrorKind::IdentityMismatch,
                ));
            }
            None => {
                let commit_ordinal: i64 = transaction
                    .query_row(
                        "SELECT COALESCE(MAX(commit_ordinal), -1) + 1 FROM receipts",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(classify_sql)?;
                let received_at = now_utc(&transaction)?;
                transaction
                    .execute(
                        "INSERT INTO receipts (
                             request_id, receipt_key_id, signature, receipt_digest,
                         commit_ordinal, commit_time, signature_verified,
                         received_at, receipt_bytes)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?8)",
                        rusqlite::params![
                            fields.request_id.as_str(),
                            fields.receipt_key_id.to_hex(),
                            fields.signature.to_hex(),
                            receipt_digest,
                            commit_ordinal,
                            fields.commit_time.as_str(),
                            received_at.as_str(),
                            &canonical_bytes,
                        ],
                    )
                    .map_err(classify_sql)?;
            }
        }

        let cursor_advanced = update_cursor_and_acknowledge(
            &transaction,
            &pending,
            request.cursor(),
            &fields.request_id,
        )?;
        transaction.commit().map_err(classify_sql)?;
        (pending.bundle_name, cursor_advanced)
    };

    spool.remove(&bundle_name).map_err(|error| {
        if matches!(error.kind(), SpoolErrorKind::Busy) {
            AcknowledgementError::of_kind(AcknowledgementErrorKind::Busy)
        } else {
            AcknowledgementError::of_kind(AcknowledgementErrorKind::CleanupPending)
        }
    })?;

    Ok(AcknowledgedReceipt {
        request_id: fields.request_id,
        receipt_digest,
        cursor_advanced,
    })
}

/// The parsed and authenticated receipt fields the state transaction needs.
struct ReceiptFields {
    tenant_id: TenantId,
    request_id: RequestId,
    occurrence_id: OccurrenceId,
    attestation_id: AttestationId,
    blob_digest: BlobDigest,
    blob_object_key: String,
    occurrence_object_key: String,
    attestation_object_key: String,
    commit_time: Timestamp,
    receipt_key_id: KeyId,
    signature: Ed25519Signature,
}

impl ReceiptFields {
    fn parse(bytes: &[u8]) -> Result<Self, AcknowledgementError> {
        let value = json::parse(bytes).map_err(|_| {
            AcknowledgementError::of_kind(AcknowledgementErrorKind::MalformedReceipt)
        })?;
        let Value::Object(object) = value else {
            return Err(AcknowledgementError::of_kind(
                AcknowledgementErrorKind::MalformedReceipt,
            ));
        };

        if int_member(&object, "receipt_version") != Some(1) || object.get("certificate").is_none()
        {
            return Err(AcknowledgementError::of_kind(
                AcknowledgementErrorKind::MalformedReceipt,
            ));
        }
        SignatureAlgorithm::parse(text_member(&object, "signature_algorithm")?)
            .map_err(|_| malformed())?;
        for name in ["blob_outcome", "occurrence_outcome", "attestation_outcome"] {
            StorageOutcome::parse(text_member(&object, name)?).map_err(|_| malformed())?;
        }

        if !matches!(
            required(&object, "authorization_epoch")?,
            Value::Int(value) if *value >= 1
        ) {
            return Err(malformed());
        }
        // These per-attempt authorization facts are retained inside the
        // signed receipt bytes.  The frozen request deliberately does not
        // store them because retries receive fresh authorization; parsing
        // them here still makes an unknown key shape or epoch fail closed.
        parse_key(&object, "authorization_key_id")?;
        Ok(Self {
            tenant_id: parse_tenant(&object, "tenant_id")?,
            request_id: parse_request(&object, "request_id")?,
            occurrence_id: parse_occurrence(&object, "occurrence_id")?,
            attestation_id: parse_attestation(&object, "attestation_id")?,
            blob_digest: parse_blob(&object, "blob_digest")?,
            blob_object_key: text_member(&object, "blob_object_key")?.to_owned(),
            occurrence_object_key: text_member(&object, "occurrence_object_key")?.to_owned(),
            attestation_object_key: text_member(&object, "attestation_object_key")?.to_owned(),
            commit_time: parse_timestamp(&object, "commit_time")?,
            receipt_key_id: parse_key(&object, "receipt_key_id")?,
            signature: parse_signature(&object, "signature")?,
        })
    }
}

/// The state rows that define the frozen request's complete identity chain.
struct PendingUpload {
    bundle_name: String,
    state: String,
    source_id: String,
    tenant_id: TenantId,
    origin_client_id: ClientId,
    uploader_client_id: ClientId,
    occurrence_id: OccurrenceId,
    storage_profile: StorageProfile,
    canonical_digest: BlobDigest,
    range_blob_digest: BlobDigest,
    range_end: i64,
    harness: HarnessId,
    session_hash: SessionHash,
    last_cursor: Option<String>,
    last_acknowledged_range_end: i64,
    attestation_id: AttestationId,
    attestation_tenant_id: TenantId,
    attestation_occurrence_id: OccurrenceId,
    attestation_origin_client_id: ClientId,
    attestation_uploader_client_id: ClientId,
    attestation_request_id: RequestId,
}

fn load_pending(
    conn: &Connection,
    request_id: &RequestId,
) -> Result<PendingUpload, AcknowledgementError> {
    let mut statement = conn
        .prepare(
            "SELECT se.bundle_name, se.state, s.source_id,
                    fr.tenant_id, fr.origin_client_id, fr.uploader_client_id,
                    fr.occurrence_id, fr.storage_profile, fr.canonical_digest,
                    r.blob_digest, r.range_end, s.harness, s.session_hash,
                    s.last_cursor, s.last_acknowledged_range_end,
                    ua.attestation_id, ua.tenant_id, ua.occurrence_id,
                    ua.origin_client_id, ua.uploader_client_id, ua.request_id
             FROM frozen_requests fr
             JOIN spool_entries se ON se.spool_entry_id = fr.spool_entry_id
             JOIN ranges r ON r.spool_entry_id = se.spool_entry_id
                          AND r.occurrence_id = fr.occurrence_id
             JOIN upload_attestations ua ON ua.request_id = fr.request_id
             JOIN generations g ON g.generation_id = r.generation_id
             JOIN sources s ON s.source_id = g.source_id
             WHERE fr.request_id = ?1
             LIMIT 2",
        )
        .map_err(classify_sql)?;
    let mut rows = statement
        .query(rusqlite::params![request_id.as_str()])
        .map_err(classify_sql)?;
    let Some(row) = rows.next().map_err(classify_sql)? else {
        return Err(AcknowledgementError::of_kind(
            AcknowledgementErrorKind::IdentityMismatch,
        ));
    };
    let pending = PendingUpload::from_row(row)?;
    if rows.next().map_err(classify_sql)?.is_some() {
        return Err(AcknowledgementError::of_kind(
            AcknowledgementErrorKind::IdentityMismatch,
        ));
    }
    Ok(pending)
}

impl PendingUpload {
    fn from_row(row: &Row<'_>) -> Result<Self, AcknowledgementError> {
        let bundle_name: String = row.get(0).map_err(|_| unavailable())?;
        let state: String = row.get(1).map_err(|_| unavailable())?;
        let source_id: String = row.get(2).map_err(|_| unavailable())?;
        let tenant_id: String = row.get(3).map_err(|_| unavailable())?;
        let origin_client_id: String = row.get(4).map_err(|_| unavailable())?;
        let uploader_client_id: String = row.get(5).map_err(|_| unavailable())?;
        let occurrence_id: String = row.get(6).map_err(|_| unavailable())?;
        let storage_profile: String = row.get(7).map_err(|_| unavailable())?;
        let canonical_digest: String = row.get(8).map_err(|_| unavailable())?;
        let range_blob_digest: String = row.get(9).map_err(|_| unavailable())?;
        let range_end: i64 = row.get(10).map_err(|_| unavailable())?;
        let harness: String = row.get(11).map_err(|_| unavailable())?;
        let session_hash: String = row.get(12).map_err(|_| unavailable())?;
        let last_cursor: Option<String> = row.get(13).map_err(|_| unavailable())?;
        let last_acknowledged_range_end: i64 = row.get(14).map_err(|_| unavailable())?;
        let attestation_id: String = row.get(15).map_err(|_| unavailable())?;
        let attestation_tenant_id: String = row.get(16).map_err(|_| unavailable())?;
        let attestation_occurrence_id: String = row.get(17).map_err(|_| unavailable())?;
        let attestation_origin_client_id: String = row.get(18).map_err(|_| unavailable())?;
        let attestation_uploader_client_id: String = row.get(19).map_err(|_| unavailable())?;
        let attestation_request_id: String = row.get(20).map_err(|_| unavailable())?;

        if range_end < 0 || last_acknowledged_range_end < -1 {
            return Err(identity_mismatch());
        }
        Ok(Self {
            bundle_name,
            state,
            source_id,
            tenant_id: TenantId::parse(&tenant_id).map_err(|_| identity_mismatch())?,
            origin_client_id: ClientId::parse(&origin_client_id)
                .map_err(|_| identity_mismatch())?,
            uploader_client_id: ClientId::parse(&uploader_client_id)
                .map_err(|_| identity_mismatch())?,
            occurrence_id: OccurrenceId::parse(&occurrence_id).map_err(|_| identity_mismatch())?,
            storage_profile: StorageProfile::parse(&storage_profile)
                .map_err(|_| identity_mismatch())?,
            canonical_digest: BlobDigest::parse(&canonical_digest)
                .map_err(|_| identity_mismatch())?,
            range_blob_digest: BlobDigest::parse(&range_blob_digest)
                .map_err(|_| identity_mismatch())?,
            range_end,
            harness: HarnessId::parse(&harness).map_err(|_| identity_mismatch())?,
            session_hash: SessionHash::parse(&session_hash).map_err(|_| identity_mismatch())?,
            last_cursor,
            last_acknowledged_range_end,
            attestation_id: AttestationId::parse(&attestation_id)
                .map_err(|_| identity_mismatch())?,
            attestation_tenant_id: TenantId::parse(&attestation_tenant_id)
                .map_err(|_| identity_mismatch())?,
            attestation_occurrence_id: OccurrenceId::parse(&attestation_occurrence_id)
                .map_err(|_| identity_mismatch())?,
            attestation_origin_client_id: ClientId::parse(&attestation_origin_client_id)
                .map_err(|_| identity_mismatch())?,
            attestation_uploader_client_id: ClientId::parse(&attestation_uploader_client_id)
                .map_err(|_| identity_mismatch())?,
            attestation_request_id: RequestId::parse(&attestation_request_id)
                .map_err(|_| identity_mismatch())?,
        })
    }
}

fn validate_binding(
    pending: &PendingUpload,
    receipt: &ReceiptFields,
) -> Result<(), AcknowledgementError> {
    if pending.state == STATE_ACKNOWLEDGED {
        // Idempotent acknowledgement is allowed only when the receipt row
        // checked below proves the same receipt was already committed.
    } else if !matches!(
        pending.state.as_str(),
        "materialized" | "uploading" | "uploaded"
    ) {
        return Err(identity_mismatch());
    }
    if pending.tenant_id != receipt.tenant_id
        || pending.occurrence_id != receipt.occurrence_id
        || pending.canonical_digest != receipt.blob_digest
        || pending.range_blob_digest != receipt.blob_digest
        || pending.attestation_tenant_id != pending.tenant_id
        || pending.attestation_occurrence_id != pending.occurrence_id
        || pending.attestation_origin_client_id != pending.origin_client_id
        || pending.attestation_uploader_client_id != pending.uploader_client_id
        || pending.attestation_request_id != receipt.request_id
    {
        return Err(identity_mismatch());
    }
    let expected_attestation = attestation_id(
        &pending.occurrence_id,
        &pending.uploader_client_id,
        &receipt.request_id,
    );
    if expected_attestation != receipt.attestation_id
        || expected_attestation != pending.attestation_id
    {
        return Err(identity_mismatch());
    }

    let blob_key = BlobObjectKey::new(
        &pending.tenant_id,
        pending.storage_profile,
        &receipt.blob_digest,
    );
    let occurrence_key = OccurrenceObjectKey::new(
        &pending.tenant_id,
        &pending.origin_client_id,
        &pending.harness,
        &pending.session_hash,
        &receipt.occurrence_id,
    );
    let attestation_key = AttestationObjectKey::new(
        &pending.tenant_id,
        &receipt.occurrence_id,
        &receipt.attestation_id,
    );
    if receipt.blob_object_key != blob_key.as_str()
        || receipt.occurrence_object_key != occurrence_key.as_str()
        || receipt.attestation_object_key != attestation_key.as_str()
    {
        return Err(identity_mismatch());
    }
    Ok(())
}

fn update_cursor_and_acknowledge(
    conn: &Connection,
    pending: &PendingUpload,
    cursor: &str,
    request_id: &RequestId,
) -> Result<bool, AcknowledgementError> {
    let range_end = pending.range_end;
    let cursor_at_same_boundary = pending.last_acknowledged_range_end == range_end;
    if cursor_at_same_boundary
        && pending
            .last_cursor
            .as_deref()
            .is_some_and(|previous| previous != cursor)
    {
        return Err(identity_mismatch());
    }

    let now = now_utc(conn)?;
    let cursor_advanced = pending.last_acknowledged_range_end < range_end;
    if cursor_advanced {
        let changed = conn
            .execute(
                "UPDATE sources
                 SET last_cursor = ?1, last_acknowledged_range_end = ?2,
                     updated_at = ?3
                 WHERE source_id = ?4 AND last_acknowledged_range_end < ?2",
                rusqlite::params![cursor, range_end, now.as_str(), pending.source_id],
            )
            .map_err(classify_sql)?;
        if changed != 1 {
            return Err(unavailable());
        }
    } else if pending.last_cursor.is_none() && cursor_at_same_boundary {
        let changed = conn
            .execute(
                "UPDATE sources SET last_cursor = ?1, updated_at = ?2
                 WHERE source_id = ?3 AND last_acknowledged_range_end = ?4",
                rusqlite::params![cursor, now.as_str(), pending.source_id, range_end],
            )
            .map_err(classify_sql)?;
        if changed != 1 {
            return Err(unavailable());
        }
    }

    let changed = conn
        .execute(
            "UPDATE spool_entries SET state = 'acknowledged', updated_at = ?1
             WHERE spool_entry_id = (
                 SELECT spool_entry_id FROM frozen_requests WHERE request_id = ?2
             ) AND state != 'acknowledged'",
            rusqlite::params![now.as_str(), request_id.as_str()],
        )
        .map_err(classify_sql)?;
    if pending.state != STATE_ACKNOWLEDGED && changed != 1 {
        return Err(unavailable());
    }
    Ok(cursor_advanced)
}

fn required<'a>(object: &'a Object, name: &'static str) -> Result<&'a Value, AcknowledgementError> {
    object.get(name).ok_or_else(malformed)
}

fn text_member<'a>(
    object: &'a Object,
    name: &'static str,
) -> Result<&'a str, AcknowledgementError> {
    match required(object, name)? {
        Value::Text(value) => Ok(value),
        _ => Err(malformed()),
    }
}

fn int_member(object: &Object, name: &'static str) -> Option<i64> {
    match object.get(name) {
        Some(Value::Int(value)) => Some(*value),
        _ => None,
    }
}

fn parse_tenant(object: &Object, name: &'static str) -> Result<TenantId, AcknowledgementError> {
    TenantId::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_request(object: &Object, name: &'static str) -> Result<RequestId, AcknowledgementError> {
    RequestId::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_occurrence(
    object: &Object,
    name: &'static str,
) -> Result<OccurrenceId, AcknowledgementError> {
    OccurrenceId::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_attestation(
    object: &Object,
    name: &'static str,
) -> Result<AttestationId, AcknowledgementError> {
    AttestationId::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_blob(object: &Object, name: &'static str) -> Result<BlobDigest, AcknowledgementError> {
    BlobDigest::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_key(object: &Object, name: &'static str) -> Result<KeyId, AcknowledgementError> {
    KeyId::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn parse_timestamp(object: &Object, name: &'static str) -> Result<Timestamp, AcknowledgementError> {
    let timestamp = Timestamp::parse(text_member(object, name)?).map_err(|_| malformed())?;
    timestamp
        .calendar_valid()
        .then_some(timestamp)
        .ok_or_else(malformed)
}

fn parse_signature(
    object: &Object,
    name: &'static str,
) -> Result<Ed25519Signature, AcknowledgementError> {
    Ed25519Signature::parse(text_member(object, name)?).map_err(|_| malformed())
}

fn now_utc(conn: &Connection) -> Result<Timestamp, AcknowledgementError> {
    let text: String = conn
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(classify_sql)?;
    let timestamp = Timestamp::parse(&text).map_err(|_| unavailable())?;
    timestamp
        .calendar_valid()
        .then_some(timestamp)
        .ok_or_else(unavailable)
}

fn classify_sql(error: rusqlite::Error) -> AcknowledgementError {
    if matches!(
        error,
        rusqlite::Error::SqliteFailure(ffi, _)
            if matches!(
                ffi.code,
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
            )
    ) {
        AcknowledgementError::of_kind(AcknowledgementErrorKind::Busy)
    } else {
        unavailable()
    }
}

fn malformed() -> AcknowledgementError {
    AcknowledgementError::of_kind(AcknowledgementErrorKind::MalformedReceipt)
}

fn identity_mismatch() -> AcknowledgementError {
    AcknowledgementError::of_kind(AcknowledgementErrorKind::IdentityMismatch)
}

fn unavailable() -> AcknowledgementError {
    AcknowledgementError::of_kind(AcknowledgementErrorKind::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use archivist_auth::authority::PinnedAuthorityRoot;
    use archivist_auth::ed25519;
    use archivist_auth::receipt::{AuthoritySigner, CertifiedReceiptKey, ReceiptSigningKey};
    use archivist_auth::reference::ProtectedReference;
    use archivist_protocol::derivation::attestation_id;
    use archivist_protocol::json::{Object, Value};
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::vocabulary::{
        ClientId, Ed25519PublicKey, HarnessId, RequestId, SessionHash, StorageProfile, TenantId,
        Timestamp,
    };

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    const AUTHORITY_SEED: [u8; 32] = [0x11; 32];
    const RECEIPT_SEED: [u8; 32] = [0x22; 32];
    const TENANT: &str = "33333333-3333-4333-8333-333333333333";
    const ORIGIN: &str = "11111111-1111-4111-8111-111111111111";
    const UPLOADER: &str = "22222222-2222-4222-8222-222222222222";
    const SOURCE: &str = "44444444-4444-4444-8444-444444444444";
    const GENERATION: &str = "55555555-5555-4555-8555-555555555555";
    const SPOOL_ENTRY: &str = "66666666-6666-7666-8666-666666666666";
    const REQUEST: &str = "01999e00-0000-7000-8000-000000000001";
    const SPOOL_ENTRY_TWO: &str = "77777777-7777-7666-8666-777777777777";
    const REQUEST_TWO: &str = "01999e00-0000-7000-8000-000000000002";
    const OCCURRENCE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const BLOB: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    const OCCURRENCE_TWO: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
    const BLOB_TWO: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ARTIFACT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CAPTURED_AT: &str = "2026-09-02T00:00:00Z";
    const COMMIT_TIME: &str = "2026-09-03T00:00:00Z";

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("archivist-ack-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("acknowledgement test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn secret_reference(dir: &Path, name: &str, seed: &[u8; 32]) -> ProtectedReference {
        let path = dir.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .expect("test secret file");
        file.write_all(seed).expect("test secret bytes");
        ProtectedReference::parse(&format!("file:{}", path.display())).expect("secret reference")
    }

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    #[allow(clippy::too_many_arguments)]
    fn signed_receipt(
        signer: &CertifiedReceiptKey,
        tenant: &TenantId,
        request: &RequestId,
        occurrence: &OccurrenceId,
        attestation: &AttestationId,
        blob: &BlobDigest,
        origin: &ClientId,
        harness: &HarnessId,
        session: &SessionHash,
        authorization_key_id: &KeyId,
    ) -> Vec<u8> {
        let mut object = Object::new();
        object.set("tenant_id", text(tenant.as_str()));
        object.set("request_id", text(request.as_str()));
        object.set("occurrence_id", text(&occurrence.to_hex()));
        object.set("attestation_id", text(&attestation.to_hex()));
        object.set("blob_digest", text(&blob.to_hex()));
        object.set(
            "blob_object_key",
            text(BlobObjectKey::new(tenant, StorageProfile::ZstdV1, blob).as_str()),
        );
        object.set(
            "occurrence_object_key",
            text(OccurrenceObjectKey::new(tenant, origin, harness, session, occurrence).as_str()),
        );
        object.set(
            "attestation_object_key",
            text(AttestationObjectKey::new(tenant, occurrence, attestation).as_str()),
        );
        object.set("blob_outcome", text("created"));
        object.set("occurrence_outcome", text("created"));
        object.set("attestation_outcome", text("created"));
        object.set("authorization_key_id", text(&authorization_key_id.to_hex()));
        object.set("authorization_epoch", Value::Int(1));
        object.set("commit_time", text(COMMIT_TIME));
        signer
            .sign_receipt(object)
            .expect("test receipt signs")
            .canonical_bytes()
    }

    #[allow(clippy::too_many_lines)]
    fn fixture() -> (
        TempDir,
        Spool,
        StateStore,
        PinnedAuthorityRoot,
        CertifiedReceiptKey,
        Vec<u8>,
        RequestId,
        String,
    ) {
        let temp = TempDir::new();
        let tenant = TenantId::parse(TENANT).expect("tenant");
        let origin = ClientId::parse(ORIGIN).expect("origin");
        let uploader = ClientId::parse(UPLOADER).expect("uploader");
        let request = RequestId::parse(REQUEST).expect("request");
        let occurrence = OccurrenceId::parse(OCCURRENCE).expect("occurrence");
        let blob = BlobDigest::parse(BLOB).expect("blob");
        let harness = HarnessId::parse("claude-code").expect("harness");
        let session = SessionHash::parse(SESSION).expect("session");
        let attestation = attestation_id(&occurrence, &uploader, &request);
        let authority_reference = secret_reference(temp.path(), "authority", &AUTHORITY_SEED);
        let receipt_reference = secret_reference(temp.path(), "receipt", &RECEIPT_SEED);
        let authority =
            AuthoritySigner::from_secret_reference(tenant.clone(), &authority_reference)
                .expect("authority signer");
        let root = PinnedAuthorityRoot::new(
            tenant.clone(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        );
        let receipt_signing =
            ReceiptSigningKey::from_secret_reference(tenant.clone(), &receipt_reference)
                .expect("receipt signer");
        let signing_time = Timestamp::parse(COMMIT_TIME).expect("signing time");
        let signer = CertifiedReceiptKey::certify(
            receipt_signing,
            &authority,
            signing_time.clone(),
            signing_time,
        )
        .expect("receipt certificate");
        let receipt = signed_receipt(
            &signer,
            &tenant,
            &request,
            &occurrence,
            &attestation,
            &blob,
            &origin,
            &harness,
            &session,
            &authority.key_id(),
        );

        let mut store = StateStore::open_in_memory().expect("state store");
        store.migrate().expect("state migrations");
        let spool = Spool::open(temp.path()).expect("spool");
        let bundle_name = format!("{SPOOL_ENTRY}.bundle");
        std::fs::write(temp.path().join("spool").join(&bundle_name), b"bundle")
            .expect("bundle bytes");
        let conn = store.connection();
        conn.execute(
            "INSERT INTO sources (
                 source_id, harness, upstream_session_id, id_source, session_hash,
                 artifact_kind, adapter_id, adapter_projection_version,
                 adapter_artifact_id, artifact_hash, freshness_lane, created_at, updated_at)
             VALUES (?1, ?2, 'session', 'natural', ?3, 'jsonl', 'claude', 'v1',
                     'artifact', ?4, 'freshness', ?5, ?5)",
            rusqlite::params![SOURCE, harness.as_str(), SESSION, ARTIFACT, CAPTURED_AT],
        )
        .expect("source row");
        conn.execute(
            "INSERT INTO generations (
                 generation_id, source_id, ordinal, state, detected_reason,
                 tail_checksum, detected_at)
             VALUES (?1, ?2, 1, 'open', 'first-observed', ?3, ?4)",
            rusqlite::params![GENERATION, SOURCE, ARTIFACT, CAPTURED_AT],
        )
        .expect("generation row");
        conn.execute(
            "INSERT INTO spool_entries (
                 spool_entry_id, bundle_name, state, envelope_digest, size_bytes,
                 created_at, updated_at)
             VALUES (?1, ?2, 'materialized', ?3, 6, ?4, ?4)",
            rusqlite::params![SPOOL_ENTRY, bundle_name, BLOB, CAPTURED_AT],
        )
        .expect("spool row");
        conn.execute(
            "INSERT INTO frozen_requests (
                 request_id, spool_entry_id, tenant_id, origin_client_id,
                 uploader_client_id, occurrence_id, envelope_version,
                 storage_profile, transport_encoding, canonical_digest,
                 incoming_checksum, canonical_size, transport_size, source_at,
                 captured_at, envelope_created_at, frozen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'envelope-v1', 'zstd-v1', 'identity',
                     ?7, 'sha256-raw', 6, 6, ?8, ?8, ?8, ?8)",
            rusqlite::params![
                REQUEST,
                SPOOL_ENTRY,
                TENANT,
                ORIGIN,
                UPLOADER,
                OCCURRENCE,
                BLOB,
                CAPTURED_AT
            ],
        )
        .expect("frozen request row");
        conn.execute(
            "INSERT INTO ranges (
                 occurrence_id, generation_id, range_kind, range_start, range_end,
                 sequence, blob_digest, spool_entry_id, captured_at)
             VALUES (?1, ?2, 'bytes', 0, 9, 0, ?3, ?4, ?5)",
            rusqlite::params![OCCURRENCE, GENERATION, BLOB, SPOOL_ENTRY, CAPTURED_AT],
        )
        .expect("range row");
        conn.execute(
            "INSERT INTO upload_attestations (
                 attestation_id, tenant_id, occurrence_id, origin_client_id,
                 uploader_client_id, request_id, relation, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'direct', ?7)",
            rusqlite::params![
                attestation.to_hex(),
                TENANT,
                OCCURRENCE,
                ORIGIN,
                UPLOADER,
                REQUEST,
                CAPTURED_AT
            ],
        )
        .expect("attestation row");

        (
            temp,
            spool,
            store,
            root,
            signer,
            receipt,
            request,
            bundle_name,
        )
    }

    #[test]
    fn diagnostics_are_closed_and_content_free() {
        for kind in AcknowledgementErrorKind::all() {
            let error = AcknowledgementError::of_kind(*kind);
            assert_eq!(error.kind(), *kind);
            assert_eq!(error.detail(), kind.default_detail());
            assert!(!error.to_string().contains("/tmp"));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn receipt_acknowledgement_is_atomic_and_cleans_up_after_commit() {
        let (temp, spool, mut store, root, signer, receipt, request_id, bundle_name) = fixture();
        let bad_blob =
            BlobDigest::parse("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                .expect("bad blob");
        let tenant = TenantId::parse(TENANT).expect("tenant");
        let origin = ClientId::parse(ORIGIN).expect("origin");
        let harness = HarnessId::parse("claude-code").expect("harness");
        let session = SessionHash::parse(SESSION).expect("session");
        let occurrence = OccurrenceId::parse(OCCURRENCE).expect("occurrence");
        let uploader = ClientId::parse(UPLOADER).expect("uploader");
        let attestation = attestation_id(&occurrence, &uploader, &request_id);
        let bad_receipt = signed_receipt(
            &signer,
            &tenant,
            &request_id,
            &occurrence,
            &attestation,
            &bad_blob,
            &origin,
            &harness,
            &session,
            &signer.key_id(),
        );
        let error = acknowledge_receipt(
            &spool,
            &mut store,
            AcknowledgementRequest::new(&bad_receipt, "cursor-9"),
            &root,
            |_| None,
        )
        .expect_err("a digest mismatch is not acknowledged");
        assert_eq!(error.kind(), AcknowledgementErrorKind::IdentityMismatch);
        assert!(temp.path().join("spool").join(&bundle_name).exists());
        assert_eq!(
            store
                .connection()
                .query_row("SELECT COUNT(*) FROM receipts", [], |row| row
                    .get::<_, i64>(0))
                .expect("receipt count"),
            0
        );
        let result = acknowledge_receipt(
            &spool,
            &mut store,
            AcknowledgementRequest::new(&receipt, "cursor-9"),
            &root,
            |_| None,
        )
        .expect("verified receipt acknowledgement");
        assert!(result.cursor_advanced());
        assert!(!temp.path().join("spool").join(&bundle_name).exists());
        let durable: (i64, i64, String, Option<Vec<u8>>) = store
            .connection()
            .query_row(
                "SELECT signature_verified, commit_ordinal, commit_time, receipt_bytes
                 FROM receipts WHERE request_id = ?1",
                rusqlite::params![request_id.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .expect("durable receipt");
        assert_eq!(durable.0, 1);
        assert_eq!(durable.1, 0);
        assert_eq!(durable.2, COMMIT_TIME);
        assert_eq!(durable.3.as_deref(), Some(receipt.as_slice()));
        let cursor: (Option<String>, i64, String) = store
            .connection()
            .query_row(
                "SELECT last_cursor, last_acknowledged_range_end, updated_at
                 FROM sources WHERE source_id = ?1",
                rusqlite::params![SOURCE],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("durable cursor");
        assert_eq!(cursor.0.as_deref(), Some("cursor-9"));
        assert_eq!(cursor.1, 9);
        assert_eq!(cursor.2.len(), 20);
        assert_eq!(
            store
                .connection()
                .query_row(
                    "SELECT state FROM spool_entries WHERE spool_entry_id = ?1",
                    rusqlite::params![SPOOL_ENTRY],
                    |row| row.get::<_, String>(0),
                )
                .expect("spool state"),
            STATE_ACKNOWLEDGED
        );

        // A later retry may acknowledge a lower range after the higher
        // receipt is already durable.  It must release its own spool row
        // without regressing the source cursor or numeric watermark.
        let request_two = RequestId::parse(REQUEST_TWO).expect("second request");
        let occurrence_two = OccurrenceId::parse(OCCURRENCE_TWO).expect("second occurrence");
        let blob_two = BlobDigest::parse(BLOB_TWO).expect("second blob");
        let attestation_two = attestation_id(&occurrence_two, &uploader, &request_two);
        let receipt_two = signed_receipt(
            &signer,
            &tenant,
            &request_two,
            &occurrence_two,
            &attestation_two,
            &blob_two,
            &origin,
            &harness,
            &session,
            &signer.key_id(),
        );
        let bundle_name_two = format!("{SPOOL_ENTRY_TWO}.bundle");
        std::fs::write(temp.path().join("spool").join(&bundle_name_two), b"bundle")
            .expect("second bundle bytes");
        let conn = store.connection();
        conn.execute(
            "INSERT INTO spool_entries (
                 spool_entry_id, bundle_name, state, envelope_digest, size_bytes,
                 created_at, updated_at)
             VALUES (?1, ?2, 'materialized', ?3, 6, ?4, ?4)",
            rusqlite::params![SPOOL_ENTRY_TWO, bundle_name_two, BLOB_TWO, CAPTURED_AT],
        )
        .expect("second spool row");
        conn.execute(
            "INSERT INTO frozen_requests (
                 request_id, spool_entry_id, tenant_id, origin_client_id,
                 uploader_client_id, occurrence_id, envelope_version,
                 storage_profile, transport_encoding, canonical_digest,
                 incoming_checksum, canonical_size, transport_size, source_at,
                 captured_at, envelope_created_at, frozen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'envelope-v1', 'zstd-v1', 'identity',
                     ?7, 'sha256-raw', 6, 6, ?8, ?8, ?8, ?8)",
            rusqlite::params![
                REQUEST_TWO,
                SPOOL_ENTRY_TWO,
                TENANT,
                ORIGIN,
                UPLOADER,
                OCCURRENCE_TWO,
                BLOB_TWO,
                CAPTURED_AT,
            ],
        )
        .expect("second frozen request row");
        conn.execute(
            "INSERT INTO ranges (
                 occurrence_id, generation_id, range_kind, range_start, range_end,
                 sequence, blob_digest, spool_entry_id, captured_at)
             VALUES (?1, ?2, 'bytes', 0, 4, 0, ?3, ?4, ?5)",
            rusqlite::params![
                OCCURRENCE_TWO,
                GENERATION,
                BLOB_TWO,
                SPOOL_ENTRY_TWO,
                CAPTURED_AT,
            ],
        )
        .expect("second range row");
        conn.execute(
            "INSERT INTO upload_attestations (
                 attestation_id, tenant_id, occurrence_id, origin_client_id,
                 uploader_client_id, request_id, relation, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'direct', ?7)",
            rusqlite::params![
                attestation_two.to_hex(),
                TENANT,
                OCCURRENCE_TWO,
                ORIGIN,
                UPLOADER,
                REQUEST_TWO,
                CAPTURED_AT,
            ],
        )
        .expect("second attestation row");
        let lower = acknowledge_receipt(
            &spool,
            &mut store,
            AcknowledgementRequest::new(&receipt_two, "cursor-4"),
            &root,
            |_| None,
        )
        .expect("lower receipt acknowledgement");
        assert!(!lower.cursor_advanced());
        assert!(!temp.path().join("spool").join(&bundle_name_two).exists());
        let cursor_after_lower: (Option<String>, i64) = store
            .connection()
            .query_row(
                "SELECT last_cursor, last_acknowledged_range_end
                 FROM sources WHERE source_id = ?1",
                rusqlite::params![SOURCE],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("cursor after lower receipt");
        assert_eq!(cursor_after_lower.0.as_deref(), Some("cursor-9"));
        assert_eq!(cursor_after_lower.1, 9);

        let retry = acknowledge_receipt(
            &spool,
            &mut store,
            AcknowledgementRequest::new(&receipt, "cursor-9"),
            &root,
            |_| None,
        )
        .expect("idempotent acknowledgement retry");
        assert!(!retry.cursor_advanced());
        assert_eq!(
            store
                .connection()
                .query_row("SELECT COUNT(*) FROM receipts", [], |row| row
                    .get::<_, i64>(0))
                .expect("receipt count after retry"),
            2
        );
    }
}
