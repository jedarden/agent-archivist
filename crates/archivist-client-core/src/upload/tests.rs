// SPDX-License-Identifier: Apache-2.0

//! The immutable upload retry state's contract, at both drill points:
//! identity frozen once and converged on re-freeze; authorization fresh
//! per attempt; the full-jitter schedule written before the attempt it
//! covers; and every locked-matrix row, including the durable quarantine
//! that keeps poisoned history from storming the service after a restart.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_protocol::vocabulary::{
    BlobDigest, ClientId, ErrorCode, IncomingChecksum, KeyId, OccurrenceId, RequestId,
    StorageProfile, TenantId, Timestamp, TransportEncoding, VersionToken,
};

use super::{
    AttemptAuthorization, FreezeUpload, FrozenUpload, INITIAL_BACKOFF_MS, Jitter, MAX_BACKOFF_MS,
    OsJitter, QuarantineReason, RetryDecision, RetryPolicy, UploadError, UploadErrorKind,
    UploadFailure, UploadRelation, decide, freeze_upload, frozen_upload, is_quarantined,
    quarantine_upload,
};
use crate::state::StateStore;

const TENANT: &str = "33333333-3333-4333-8333-333333333333";
const ORIGIN: &str = "11111111-1111-4111-8111-111111111111";
const UPLOADER: &str = "22222222-2222-4222-8222-222222222222";
const ENTRY: &str = "66666666-6666-7666-8666-666666666666";
const ENTRY_TWO: &str = "77777777-7777-7666-8666-777777777777";
const OCCURRENCE: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BLOB: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const CHECKSUM: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const CAPTURED_AT: &str = "2026-09-02T00:00:00Z";
const KEY_ONE: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const KEY_TWO: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const NOW: &str = "2026-09-23T04:45:13.000Z";

/// Draw the same 64 bits every time: pins the full-jitter arithmetic.
struct FixedJitter(u64);

impl Jitter for FixedJitter {
    fn random_bits(&mut self) -> Result<u64, UploadError> {
        Ok(self.0)
    }
}

static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "archivist-upload-{name}-{}-{id}",
            std::process::id(),
        ));
        std::fs::create_dir_all(&path).expect("upload test directory");
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

fn store_in_memory() -> StateStore {
    let mut store = StateStore::open_in_memory().expect("state store");
    store.migrate().expect("state migrations");
    store
}

fn timestamp(text: &str) -> Timestamp {
    Timestamp::parse(text).expect("test timestamp")
}

/// The database clock advanced by one directive, parsed back: the same
/// arithmetic the schedule write performs.
fn offset_now(store: &StateStore, base: &Timestamp, directive: &str) -> Timestamp {
    let text: String = store
        .connection()
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, ?2)",
            rusqlite::params![base.as_str(), directive],
            |row| row.get(0),
        )
        .expect("test clock arithmetic");
    timestamp(&text)
}

fn insert_materialized_entry(store: &StateStore, entry: &str, next_attempt_at: Option<&str>) {
    store
        .connection()
        .execute(
            "INSERT INTO spool_entries (
                 spool_entry_id, bundle_name, state, envelope_digest, size_bytes,
                 attempt_count, next_attempt_at, created_at, updated_at)
             VALUES (?1, ?1 || '.bundle', 'materialized', ?2, 6, 0, ?3, ?4, ?4)",
            rusqlite::params![entry, BLOB, next_attempt_at, CAPTURED_AT,],
        )
        .expect("spool row");
}

fn freeze_fields(entry: &str) -> FreezeUpload<'static> {
    FreezeUpload {
        spool_entry_id: Box::leak(RequestId::parse(entry).expect("entry id").into()),
        tenant_id: Box::leak(TenantId::parse(TENANT).expect("tenant").into()),
        origin_client_id: Box::leak(ClientId::parse(ORIGIN).expect("origin").into()),
        uploader_client_id: Box::leak(ClientId::parse(UPLOADER).expect("uploader").into()),
        occurrence_id: Box::leak(OccurrenceId::parse(OCCURRENCE).expect("occurrence").into()),
        envelope_version: Box::leak(
            VersionToken::parse("envelope-v1")
                .expect("envelope version")
                .into(),
        ),
        storage_profile: StorageProfile::ZstdV1,
        transport_encoding: Some(TransportEncoding::Identity),
        canonical_digest: Box::leak(BlobDigest::parse(BLOB).expect("blob").into()),
        incoming_checksum: Box::leak(IncomingChecksum::parse(CHECKSUM).expect("checksum").into()),
        canonical_size: 6,
        transport_size: 6,
        source_at: None,
        captured_at: Box::leak(timestamp(CAPTURED_AT).into()),
        envelope_created_at: Box::leak(timestamp(CAPTURED_AT).into()),
        relation: UploadRelation::Direct,
    }
}

fn frozen(store: &StateStore, entry: &str) -> FrozenUpload {
    frozen_upload(store, &RequestId::parse(entry).expect("entry id"))
        .expect("frozen lookup")
        .expect("entry is frozen")
}

fn parse_timestamps(store: &StateStore, entry: &str) -> (i64, Option<String>) {
    store
        .connection()
        .query_row(
            "SELECT attempt_count, next_attempt_at FROM spool_entries
             WHERE spool_entry_id = ?1",
            rusqlite::params![entry],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("schedule row")
}

// --- Diagnostics ------------------------------------------------------------

#[test]
fn diagnostics_are_closed_and_content_free() {
    for kind in UploadErrorKind::all() {
        let error = UploadError::of_kind(*kind);
        assert_eq!(error.kind(), *kind);
        assert_eq!(error.detail(), kind.default_detail());
        assert!(!error.to_string().contains("/tmp"));
    }
}

#[test]
fn decisions_render_the_registry_action_tokens() {
    let tokens = [
        (RetryDecision::Retry, "backoff_and_retry"),
        (RetryDecision::Rechunk, "rechunk_and_resubmit"),
        (RetryDecision::QuarantineArtifact, "quarantine_artifact"),
        (
            RetryDecision::QuarantineAndReportGap,
            "quarantine_and_report_gap",
        ),
        (RetryDecision::PauseForLinking, "pause_for_linking"),
        (RetryDecision::StopSourceAndPage, "stop_and_page_operator"),
    ];
    for (decision, token) in tokens {
        assert_eq!(decision.action_token(), token);
    }
}

// --- Freezing ---------------------------------------------------------------

#[test]
fn freeze_commits_identity_once_and_reruns_converge() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let fields = freeze_fields(ENTRY);

    let first = freeze_upload(&mut store, &fields).expect("first freeze");
    let second = freeze_upload(&mut store, &fields).expect("re-freeze converges");
    assert_eq!(first, second);

    // One frozen request and one attestation, no duplicates.
    let counts: (i64, i64) = store
        .connection()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM frozen_requests),
                    (SELECT COUNT(*) FROM upload_attestations)",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("frozen row counts");
    assert_eq!(counts, (1, 1));

    // The attestation identity is the derivation the server re-checks.
    let derived = archivist_protocol::derivation::attestation_id(
        first.occurrence_id(),
        fields.uploader_client_id,
        first.request_id(),
    );
    assert_eq!(first.attestation_id(), &derived);
    assert_eq!(frozen(&store, ENTRY), first);
    assert_eq!(
        frozen_upload(&store, &RequestId::parse(ENTRY_TWO).expect("id")).expect("lookup"),
        None
    );
}

#[test]
fn refreeze_after_any_drift_is_refused() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let committed = freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze");

    // Every mutation of a frozen field is the same refusal: the
    // committed identity always wins.
    let mut drifted = freeze_fields(ENTRY);
    drifted.canonical_digest =
        Box::leak(BlobDigest::parse(OCCURRENCE).expect("other digest").into());
    let error = freeze_upload(&mut store, &drifted).expect_err("digest drift");
    assert_eq!(error.kind(), UploadErrorKind::IdentityConflict);

    let mut drifted = freeze_fields(ENTRY);
    drifted.occurrence_id = Box::leak(OccurrenceId::parse(BLOB).expect("other occurrence").into());
    let error = freeze_upload(&mut store, &drifted).expect_err("occurrence drift");
    assert_eq!(error.kind(), UploadErrorKind::IdentityConflict);

    let mut drifted = freeze_fields(ENTRY);
    drifted.relation = UploadRelation::Relay;
    let error = freeze_upload(&mut store, &drifted).expect_err("relation drift");
    assert_eq!(error.kind(), UploadErrorKind::IdentityConflict);

    let mut drifted = freeze_fields(ENTRY);
    drifted.transport_size = 7;
    let error = freeze_upload(&mut store, &drifted).expect_err("size drift");
    assert_eq!(error.kind(), UploadErrorKind::IdentityConflict);

    assert_eq!(frozen(&store, ENTRY), committed);
}

#[test]
fn freeze_refuses_grammar_valid_but_impossible_capture_times() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let mut fields = freeze_fields(ENTRY);
    fields.captured_at = Box::leak(timestamp("2026-02-30T00:00:00Z").into());
    let error = freeze_upload(&mut store, &fields).expect_err("impossible capture time");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);
    let count: i64 = store
        .connection()
        .query_row(
            "SELECT COUNT(*) FROM frozen_requests WHERE spool_entry_id = ?1",
            rusqlite::params![ENTRY],
            |row| row.get(0),
        )
        .expect("frozen row count");
    assert_eq!(count, 0, "invalid immutable input must not create state");
}

#[test]
fn freeze_refuses_missing_or_already_completed_entries() {
    let mut store = store_in_memory();
    let error = freeze_upload(&mut store, &freeze_fields(ENTRY)).expect_err("no such spool entry");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);

    insert_materialized_entry(&store, ENTRY, None);
    store
        .connection()
        .execute(
            "UPDATE spool_entries SET state = 'acknowledged' WHERE spool_entry_id = ?1",
            rusqlite::params![ENTRY],
        )
        .expect("acknowledged state");
    let error = freeze_upload(&mut store, &freeze_fields(ENTRY)).expect_err("acknowledged entry");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);
}

#[test]
fn an_unfrozen_entry_is_simply_never_claimable() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let claimed = super::claim_due_upload(
        &mut store,
        &timestamp(NOW),
        &RetryPolicy::plan(),
        &mut FixedJitter(0),
    )
    .expect("claim over an unfrozen entry");
    assert_eq!(claimed, None, "no frozen identity, no attempt");
}

// --- Attempt authorization --------------------------------------------------

#[test]
fn authorization_varies_per_attempt_while_identity_stays_frozen() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let committed = freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze");

    let key_one = KeyId::parse(KEY_ONE).expect("key one");
    let key_two = KeyId::parse(KEY_TWO).expect("key two");
    let first = AttemptAuthorization::mint(key_one, 1, timestamp(CAPTURED_AT))
        .expect("first authorization");
    let rotated = AttemptAuthorization::mint(key_two, 2, timestamp("2026-09-24T00:00:00Z"))
        .expect("rotated authorization");

    // Rotation moved the key, the epoch, and the timestamp.
    assert_eq!(first.uploader_key_id(), &key_one);
    assert_eq!(rotated.uploader_key_id().to_hex(), KEY_TWO);
    assert_eq!(first.authorization_epoch(), 1);
    assert_eq!(rotated.authorization_epoch(), 2);
    assert_ne!(
        first.authorization_timestamp(),
        rotated.authorization_timestamp()
    );

    // The signing preimage moves with the authorization...
    let request_digest =
        archivist_protocol::vocabulary::RequestContentDigest::parse(BLOB).expect("request digest");
    let envelope_digest =
        archivist_protocol::vocabulary::EnvelopeDigest::parse(CHECKSUM).expect("envelope digest");
    let payload = BlobDigest::parse(BLOB).expect("payload digest");
    let checksum = IncomingChecksum::parse(CHECKSUM).expect("transport digest");
    let first_input = first.signing_input(
        "POST",
        "/v1/ingest",
        "multipart/related; boundary=archivist",
        &request_digest,
        &envelope_digest,
        &payload,
        &checksum,
    );
    let rotated_input = rotated.signing_input(
        "POST",
        "/v1/ingest",
        "multipart/related; boundary=archivist",
        &request_digest,
        &envelope_digest,
        &payload,
        &checksum,
    );
    assert_ne!(first_input, rotated_input);

    // ...while the frozen identity the preimage's envelope facts name
    // never moved.
    assert_eq!(frozen(&store, ENTRY), committed);
}

#[test]
fn authorization_mint_refuses_epoch_zero_and_fake_timestamps() {
    let key = KeyId::parse(KEY_ONE).expect("key");
    let error = AttemptAuthorization::mint(key, 0, timestamp(CAPTURED_AT)).expect_err("epoch zero");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);
    let error = AttemptAuthorization::mint(key, 1, timestamp("2026-13-45T99:99:99Z"))
        .expect_err("impossible calendar instant");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);
}

// --- The schedule ------------------------------------------------------------

#[test]
fn bounds_double_to_the_cap_and_never_give_up() {
    let policy = RetryPolicy::plan();
    assert_eq!(policy.base_ms(), INITIAL_BACKOFF_MS);
    assert_eq!(policy.cap_ms(), MAX_BACKOFF_MS);
    assert_eq!(policy.upper_bound_ms(0), 1_000);
    assert_eq!(policy.upper_bound_ms(1), 2_000);
    assert_eq!(policy.upper_bound_ms(2), 4_000);
    assert_eq!(policy.upper_bound_ms(9), 512_000);
    assert_eq!(
        policy.upper_bound_ms(10),
        MAX_BACKOFF_MS,
        "the tenth doubling crosses the 15-minute cap"
    );
    for failures in [11, 12, 55, 63, 64, 1_000, u64::MAX] {
        assert_eq!(
            policy.upper_bound_ms(failures),
            MAX_BACKOFF_MS,
            "the bound saturates at the cap, never refuses"
        );
    }
    // A synthetic policy stays defined for degenerate inputs.
    let floored = RetryPolicy::new(0, 500);
    assert_eq!(floored.upper_bound_ms(0), 1);
    assert_eq!(floored.upper_bound_ms(4), 16);
}

#[test]
fn full_jitter_draws_uniformly_below_the_bound() {
    let policy = RetryPolicy::plan();
    let mut pinned = FixedJitter(0);
    assert_eq!(
        policy.full_jitter_ms(0, &mut pinned).expect("draw"),
        0,
        "all-zero bits draw the zero delay"
    );
    let mut maximal = FixedJitter(u64::MAX);
    assert_eq!(
        policy.full_jitter_ms(0, &mut maximal).expect("draw"),
        INITIAL_BACKOFF_MS - 1,
        "all-one bits draw just under the bound"
    );
    assert_eq!(
        policy.full_jitter_ms(63, &mut maximal).expect("draw"),
        MAX_BACKOFF_MS - 1,
        "the cap leaves one millisecond of jitter above zero"
    );
    // The production source delivers two distinct draws.
    let mut os = OsJitter::open().expect("entropy source");
    let first = os.random_bits().expect("draw");
    let second = os.random_bits().expect("draw");
    assert_ne!(first, second, "two 64-byte-aligned draws never repeat");
}

#[test]
fn claim_writes_the_schedule_before_the_attempt_it_covers() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    // A claim hands out a frozen identity, so only a frozen entry is
    // claimable: the schedule covers the attempt on that identity.
    freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze");
    let now = timestamp(NOW);

    // bits=u64::MAX under the first bound draws base - 1 milliseconds.
    let claimed = super::claim_due_upload(
        &mut store,
        &now,
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim")
    .expect("a due entry");
    assert_eq!(claimed.attempt_count(), 1);
    assert_eq!(claimed.retry_delay_ms(), INITIAL_BACKOFF_MS - 1);
    assert_eq!(claimed.spool_entry_id().as_str(), ENTRY);
    assert_eq!(claimed.bundle_name(), format!("{ENTRY}.bundle"));
    assert_eq!(claimed.envelope_digest(), BLOB);

    let (attempt_count, next_attempt_at) = parse_timestamps(&store, ENTRY);
    assert_eq!(attempt_count, 1);
    let expected = offset_now(&store, &now, "+0.999 seconds");
    assert_eq!(next_attempt_at.as_deref(), Some(expected.as_str()));

    // An attempt whose outcome is never recorded (a crash) still gets
    // exactly one properly delayed retry, not a tight loop.
    let immediate = super::claim_due_upload(
        &mut store,
        &now,
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim before the schedule elapses");
    assert_eq!(immediate, None);

    let later = offset_now(&store, &now, "+0.999 seconds");
    let retried = super::claim_due_upload(
        &mut store,
        &later,
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim after the schedule elapses")
    .expect("the delayed retry");
    assert_eq!(retried.attempt_count(), 2);
    // The second failure index doubles the bound; the maximal draw lands
    // one millisecond under it again.
    assert_eq!(retried.retry_delay_ms(), 2 * INITIAL_BACKOFF_MS - 1);
}

#[test]
fn claims_order_never_attempted_first_then_by_due_time() {
    let mut store = store_in_memory();
    // Never attempted, waiting on an elapsed schedule, and not yet due.
    insert_materialized_entry(&store, ENTRY_TWO, Some("2026-09-23T04:45:12.000Z"));
    insert_materialized_entry(&store, ENTRY, None);
    freeze_upload(&mut store, &freeze_fields(ENTRY_TWO)).expect("freeze two");
    freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze one");

    // ENTRY is never attempted, so it wins over the elapsed ENTRY_TWO
    // even though ENTRY_TWO froze first; the maximal draw schedules its
    // retry a full 999 ms out.
    let first = super::claim_due_upload(
        &mut store,
        &timestamp(NOW),
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim")
    .expect("the never-attempted entry");
    assert_eq!(first.spool_entry_id().as_str(), ENTRY);

    // With ENTRY scheduled into the future, the elapsed ENTRY_TWO is due.
    let second = super::claim_due_upload(
        &mut store,
        &timestamp(NOW),
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim")
    .expect("the elapsed entry");
    assert_eq!(second.spool_entry_id().as_str(), ENTRY_TWO);

    // Both now wait until the same future instant: nothing is due.
    let third = super::claim_due_upload(
        &mut store,
        &timestamp(NOW),
        &RetryPolicy::plan(),
        &mut FixedJitter(u64::MAX),
    )
    .expect("claim");
    assert_eq!(third, None, "both entries are scheduled ahead of now");
}

// --- The locked matrix --------------------------------------------------------

#[test]
fn every_registered_upload_code_resolves_through_its_class() {
    let cases: &[(&str, RetryDecision)] = &[
        ("envelope.malformed", RetryDecision::QuarantineArtifact),
        (
            "envelope.version_unsupported",
            RetryDecision::QuarantineArtifact,
        ),
        (
            "envelope.media_type_unsupported",
            RetryDecision::QuarantineArtifact,
        ),
        ("envelope.schema_invalid", RetryDecision::QuarantineArtifact),
        ("envelope.size_exceeded", RetryDecision::QuarantineArtifact),
        ("auth.epoch_unreached", RetryDecision::QuarantineArtifact),
        ("auth.key_id_mismatch", RetryDecision::QuarantineArtifact),
        ("request.framing_invalid", RetryDecision::QuarantineArtifact),
        ("auth.unlinked", RetryDecision::PauseForLinking),
        ("auth.revoked", RetryDecision::PauseForLinking),
        (
            "auth.authorization_rejected",
            RetryDecision::PauseForLinking,
        ),
        ("auth.forbidden", RetryDecision::PauseForLinking),
        (
            "storage.integrity_conflict",
            RetryDecision::StopSourceAndPage,
        ),
        ("request.payload_too_large", RetryDecision::Rechunk),
        ("request.expansion_ratio_exceeded", RetryDecision::Rechunk),
        (
            "request.record_too_large",
            RetryDecision::QuarantineAndReportGap,
        ),
        ("request.deadline_exceeded", RetryDecision::Retry),
        ("request.rate_limited", RetryDecision::Retry),
        ("request.too_early", RetryDecision::Retry),
        ("server.internal", RetryDecision::Retry),
        ("server.storage_failure", RetryDecision::Retry),
        ("server.unavailable", RetryDecision::Retry),
        ("server.partial_commit", RetryDecision::Retry),
        ("server.upstream_timeout", RetryDecision::Retry),
        ("transport.connection_failed", RetryDecision::Retry),
        ("transport.response_lost", RetryDecision::Retry),
    ];
    for (code, expected) in cases {
        let failure = UploadFailure::Registry {
            code: ErrorCode::parse(code).expect("registered code"),
            retryable: false,
        };
        assert_eq!(decide(&failure), *expected, "matrix row for {code}");
    }
}

#[test]
fn statuses_and_fallbacks_follow_the_matrix() {
    let cases: &[(u16, RetryDecision)] = &[
        (400, RetryDecision::QuarantineArtifact),
        (415, RetryDecision::QuarantineArtifact),
        (401, RetryDecision::PauseForLinking),
        (403, RetryDecision::PauseForLinking),
        (409, RetryDecision::StopSourceAndPage),
        (413, RetryDecision::Rechunk),
        (408, RetryDecision::Retry),
        (425, RetryDecision::Retry),
        (429, RetryDecision::Retry),
        (500, RetryDecision::Retry),
        (502, RetryDecision::Retry),
        (503, RetryDecision::Retry),
        (504, RetryDecision::Retry),
    ];
    for (status, expected) in cases {
        assert_eq!(decide(&UploadFailure::Status(*status)), *expected);
    }
    // An unknown status fails closed: only the server-failure range is
    // a license to retry.
    assert_eq!(
        decide(&UploadFailure::Status(418)),
        RetryDecision::QuarantineArtifact
    );
    assert_eq!(
        decide(&UploadFailure::Status(600)),
        RetryDecision::QuarantineArtifact
    );
    assert_eq!(
        decide(&UploadFailure::Status(501)),
        RetryDecision::QuarantineArtifact,
        "an unregistered 5xx must not bypass the frozen registry matrix"
    );
    assert_eq!(
        decide(&UploadFailure::Status(505)),
        RetryDecision::QuarantineArtifact,
        "an unregistered 5xx must fail closed"
    );

    // Lost responses always retry.
    assert_eq!(decide(&UploadFailure::ResponseLost), RetryDecision::Retry);

    // An unregistered code falls back on the body's retryable boolean:
    // true retries, false quarantines — never a storm.
    for (code, retryable, expected) in [
        ("future.retryable_code", true, RetryDecision::Retry),
        (
            "future.final_code",
            false,
            RetryDecision::QuarantineArtifact,
        ),
    ] {
        assert_eq!(
            decide(&UploadFailure::Registry {
                code: ErrorCode::parse(code).expect("well-formed code"),
                retryable,
            }),
            expected
        );
    }
}

// --- Quarantine ---------------------------------------------------------------

#[test]
fn quarantine_is_durable_idempotent_and_claim_excluding() {
    let dir = TempDir::new("quarantine");
    let db = dir.path().join("state.sqlite3");
    let mut store = StateStore::open(&db).expect("file-backed state store");
    store.migrate().expect("migrations");
    insert_materialized_entry(&store, ENTRY, None);
    freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze");

    let quarantined = quarantine_upload(
        &mut store,
        &RequestId::parse(ENTRY).expect("entry id"),
        QuarantineReason::PoisonInput,
        &timestamp(NOW),
    )
    .expect("quarantine");
    assert!(quarantined, "the first call quarantines");

    // The reason is recorded as its registry class token.
    let reason: String = store
        .connection()
        .query_row(
            "SELECT reason FROM quarantined_uploads WHERE spool_entry_id = ?1",
            rusqlite::params![ENTRY],
            |row| row.get(0),
        )
        .expect("quarantine row");
    assert_eq!(reason, "request_invalid");
    assert!(
        is_quarantined(&store, &RequestId::parse(ENTRY).expect("entry id")).expect("check"),
        "the entry is quarantined"
    );

    // A second quarantine changes nothing: the first decision wins.
    let again = quarantine_upload(
        &mut store,
        &RequestId::parse(ENTRY).expect("entry id"),
        QuarantineReason::UnsplittableRecord,
        &timestamp(NOW),
    )
    .expect("re-quarantine");
    assert!(!again, "the first reason wins");
    let reason: String = store
        .connection()
        .query_row(
            "SELECT reason FROM quarantined_uploads WHERE spool_entry_id = ?1",
            rusqlite::params![ENTRY],
            |row| row.get(0),
        )
        .expect("quarantine row");
    assert_eq!(reason, "request_invalid");

    // And the entry never re-enters the claim set.
    let claimed = super::claim_due_upload(
        &mut store,
        &timestamp(NOW),
        &RetryPolicy::plan(),
        &mut FixedJitter(0),
    )
    .expect("claim over the quarantined entry");
    assert_eq!(claimed, None);

    // Quarantine survives a restart: it is the durable half of "poison
    // input must not storm the service".
    drop(store);
    let mut reopened = StateStore::open(&db).expect("reopened state store");
    reopened
        .migrate()
        .expect("migrations on the migrated store");
    assert!(
        is_quarantined(&reopened, &RequestId::parse(ENTRY).expect("entry id"))
            .expect("check after restart"),
        "quarantine is durable across restarts"
    );
}

#[test]
fn quarantine_refuses_absent_entries() {
    let mut store = store_in_memory();
    let error = quarantine_upload(
        &mut store,
        &RequestId::parse(ENTRY).expect("entry id"),
        QuarantineReason::PoisonInput,
        &timestamp(NOW),
    )
    .expect_err("no such entry");
    assert_eq!(error.kind(), UploadErrorKind::InvalidInput);
}

// --- The whole loop -------------------------------------------------------------

#[test]
fn one_entry_retries_the_matrix_without_limit_and_never_moves_identity() {
    let mut store = store_in_memory();
    insert_materialized_entry(&store, ENTRY, None);
    let committed = freeze_upload(&mut store, &freeze_fields(ENTRY)).expect("freeze");
    let policy = RetryPolicy::plan();
    let mut now = timestamp(NOW);

    // Lost response, transient server failure, throttle: all retry, and
    // each re-claim re-sends the identical frozen identity.
    for outcome in [
        UploadFailure::ResponseLost,
        UploadFailure::Status(503),
        UploadFailure::Registry {
            code: ErrorCode::parse("request.rate_limited").expect("code"),
            retryable: true,
        },
    ] {
        assert_eq!(decide(&outcome), RetryDecision::Retry);
        let claim = super::claim_due_upload(&mut store, &now, &policy, &mut FixedJitter(u64::MAX))
            .expect("claim")
            .expect("the entry keeps retrying");
        assert_eq!(claim.frozen(), &committed);
        let (count, _) = parse_timestamps(&store, ENTRY);
        assert_eq!(
            u64::try_from(count).expect("attempt count"),
            claim.attempt_count()
        );
        // Step past the persisted schedule for the next round.
        now = offset_now(&store, &now, "+900 seconds");
    }

    // Poison input quarantines the artifact instead of retrying.
    assert_eq!(
        decide(&UploadFailure::Registry {
            code: ErrorCode::parse("envelope.schema_invalid").expect("code"),
            retryable: false,
        }),
        RetryDecision::QuarantineArtifact
    );

    // An authorization refusal pauses, and a rotation resumes the same
    // frozen identity under fresh authorization — attempt counts keep
    // growing with no limit in sight.
    let pause = decide(&UploadFailure::Status(401));
    assert_eq!(pause, RetryDecision::PauseForLinking);
    let claim = super::claim_due_upload(&mut store, &now, &policy, &mut FixedJitter(u64::MAX))
        .expect("claim after the pause lifts")
        .expect("the entry resumes");
    assert_eq!(claim.frozen(), &committed);
    let authorization =
        AttemptAuthorization::mint(KeyId::parse(KEY_TWO).expect("rotated key"), 2, now)
            .expect("rotated authorization");
    assert_eq!(claim.frozen().request_id(), committed.request_id());
    assert_eq!(authorization.authorization_epoch(), 2);
    let (_, scheduled) = parse_timestamps(&store, ENTRY);
    assert!(scheduled.is_some(), "the resumed attempt is re-scheduled");
}

// --- The state clock -------------------------------------------------------------

#[test]
fn state_now_is_millisecond_precise_rfc3339() {
    let store = store_in_memory();
    let now = super::state_now(&store).expect("state clock");
    assert!(now.as_str().len() == 24, "{}", now.as_str());
    assert!(now.as_str().ends_with('Z'));
    assert!(now.as_str().contains('.'));
    assert!(now.calendar_valid());
}
