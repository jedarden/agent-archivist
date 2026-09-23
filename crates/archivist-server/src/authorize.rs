// SPDX-License-Identifier: Apache-2.0

//! The uploader authorization middleware: the decision layer that sits
//! between the bounded parse and the storage commit, and without whose
//! verdict nothing is ever written (plan Section 7.2, server data flow
//! steps 2–3).
//!
//! # Position
//!
//! The pipeline reaches this middleware twice. Before the body is read,
//! [`attempt_record_from_header`] and [`pre_authorize`] fail fast on a
//! request whose signature-parameter record is absent, malformed, does
//! not describe the presented request (the covered content type), or is
//! already outside the freshness window — no body byte, no control
//! read, no allocation is spent on an attempt that cannot stand. After
//! the parse names the envelope's identities, [`load_uploader_evidence`]
//! fetches and verifies the linked-client evidence under the declared
//! tenant's pinned authority. The complete decision,
//! [`authorize_attempt`], is the only producer of an
//! [`AuthorizedAttempt`], and the commit path consumes nothing else:
//! tenant authorization precedes object-key construction structurally,
//! because the object keys are built from the authorized identities and
//! never from the raw envelope. The route calls
//! [`crate::guard::AdmissionGate::admit_client`] for the identified
//! uploader between the two halves — the guard contract's "between its
//! steps and the pipeline's first payload-scale allocation".
//!
//! # The zero-write property
//!
//! Every rejection this module renders — malformed or stale proof,
//! altered bytes, unlinked uploader, cross-tenant declaration, revoked
//! key, refused scope, missing or refused delegation, unavailable
//! registry — is returned before the route holds anything a commit
//! could use. The acceptance reads: all negative auth cases perform
//! zero raw writes, and the route's tests hold a counting raw store to
//! exactly that.
//!
//! # Wire transport of the signature-parameter record
//!
//! The record travels in the pinned `x-archivist-attempt` request
//! header as the record's JSON object (`schemas/v1/
//! ingest-request.json`). It cannot travel in the body: the whole-body
//! digest it covers is computed over body bytes, and the plan's
//! pre-authorization clause ("the server MAY pre-authorize
//! `uploader_key_id` before the body arrives") requires the record to
//! arrive ahead of them; headers were rejected for *envelope*
//! metadata, whose size varies, while this record is a closed
//! twelve-member shape of bounded members. Any member failure is the
//! same content-free class — the record never echoes what arrived
//! (CFG-027).
//!
//! # The payload digests
//!
//! [`authorize_attempt`] takes the presented digests from its caller.
//! The whole-request digest is computed in the route's body bridge (it
//! is a covered member of the record, and the altered-body verdict is
//! this middleware's); the envelope digest follows from the parsed
//! envelope; the two payload digests are the canonical streaming
//! pipeline's outputs — computed over the payload bytes the request
//! actually carried, never the envelope's declared values, which would
//! turn the digest agreement into declared-vs-declared and check
//! nothing. Until the streaming slice produces them, the route renders
//! the stable retryable refusal behind full verification, exactly as
//! honest as today and now behind the evidence gate.

use std::time::{SystemTime, UNIX_EPOCH};

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::delegation::{DelegationRecord, LinkedClientScopes};
use archivist_auth::link::ScopeOperation;
use archivist_auth::request_verification::{
    self, AttemptAuthorization, AuthorizedAttempt, LinkedUploader, PresentedRequest,
    RequestRejection, verify_request,
};
use archivist_auth::revocation::{
    AttemptRejection, ClientTrustView, LinkedClientPointer, RevocationRecord, RotationRecord,
};
use archivist_protocol::envelope::Envelope;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, EnvelopeDigest, HarnessId, KeyId, PayloadCanonicalDigest,
    PayloadTransportDigest, RequestContentDigest, TenantId, Timestamp,
};
use archivist_storage::control::{AuthorizationEpoch, ControlReadStore};
use axum::http::HeaderMap;

use crate::error::AuthRejection;
use crate::trust::{TenantTrustRoot, TrustConfig};

/// The pinned request header carrying the per-attempt signature
/// parameters (see the module docs for why the record cannot travel in
/// the body).
pub const ATTEMPT_HEADER: &str = "x-archivist-attempt";

/// Why evidence for one uploader could not be established: the closed
/// set the route renders, in decision order. `Unlinked` and `Forbidden`
/// are the uploader's refusals (`auth.unlinked`, `auth.forbidden`);
/// [`EvidenceRejection::RegistryUnavailable`] is the replica's own
/// fail-closed condition — the control plane could not be read, or what
/// it served did not verify, and no attempt is authorized on evidence
/// the replica could not establish (plan EC-09: retryable, no writes).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceRejection {
    /// No configured tenant holds a verified link for the presenting
    /// client.
    Unlinked,
    /// The client is linked — somewhere other than the tenant the
    /// request declares, or the relay grant for its declared pair is
    /// absent.
    Forbidden,
    /// The control read failed, or the record it served did not verify
    /// under the pinned authority it was read from.
    RegistryUnavailable,
}

/// The verified control evidence one attempt's uploader stands on: the
/// folded linked-client evidence for the declared tenant and, for a
/// relay attempt, the verified delegation grant for its pair.
#[derive(Clone, Debug)]
pub struct UploaderEvidence {
    /// The uploader's own evidence: tenant, trust view, public half,
    /// scope.
    pub uploader: LinkedUploader,
    /// The verified relay grant when the attempt names a distinct
    /// origin; `None` for a direct attempt.
    pub delegation: Option<DelegationRecord>,
}

/// The digests the pipeline computed over the bytes the request
/// actually carried. The envelope member is derived from the received
/// part one; the payload members are the streaming pipeline's outputs
/// over the received part two — never the envelope's declared values
/// (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedDigests {
    /// SHA-256 over the whole received request body.
    pub request_content: RequestContentDigest,
    /// SHA-256 over the canonical form of the received part one.
    pub envelope: EnvelopeDigest,
    /// SHA-256 over the canonical payload bytes the request carried.
    pub payload_canonical: PayloadCanonicalDigest,
    /// SHA-256 over the payload bytes as transported.
    pub payload_transport: PayloadTransportDigest,
}

/// Extract and parse the per-attempt signature-parameter record from
/// the request headers.
///
/// A missing or unparseable header is the same refusal as a malformed
/// record — [`AuthRejection::ProofRejected`] — because both mean the
/// attempt presented no v1 proof. The header value is never echoed.
///
/// # Errors
/// [`AuthRejection::ProofRejected`] when the header is absent, is not
/// valid JSON, is not an object, or fails
/// [`AttemptAuthorization::parse`]'s closed-record validation.
pub fn attempt_record_from_header(
    headers: &HeaderMap,
) -> Result<AttemptAuthorization, AuthRejection> {
    let value = headers
        .get(ATTEMPT_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthRejection::ProofRejected)?;
    let parsed = json::parse(value.as_bytes()).map_err(|_| AuthRejection::ProofRejected)?;
    AttemptAuthorization::parse(&parsed).map_err(|_| AuthRejection::ProofRejected)
}

/// Pre-authorize the presented record as far as it can be judged before
/// the body arrives, against the request facts the headers alone carry.
/// The record already parsed, so two claims are checkable: that the
/// signed material describes *this* request — the covered content type
/// is part of the signature's preimage, so a request transmitted under
/// another boundary is not the request the record describes (IA-02; the
/// corpus's `invalid-altered-framing-boundary` class) — and that its
/// authorization is still fresh against the replica's clock. Stale,
/// future-dated, and misdescribing proofs are refused before any body
/// byte is read, any control read is issued, or any payload-scale
/// resource exists — the plan's "MAY pre-authorize before receiving the
/// body", taken where it is safe because the check consults nothing but
/// the record, the presented header, and the clock.
///
/// The full decision repeats both checks in its pinned order — the
/// content type inside the signature preimage, freshness as its second
/// step; this is the early half of the same rules, not second rules.
/// The freshness arithmetic floors to whole seconds and can refuse an
/// attempt whose true age sits inside the window by less than a second
/// — it errs toward refusal, never acceptance.
///
/// # Errors
/// [`AuthRejection::ProofRejected`] when the covered content type does
/// not equal the presented header value, or the record's authorization
/// timestamp is outside the window plus skew on either side.
pub fn pre_authorize(
    record: &AttemptAuthorization,
    presented_content_type: &str,
    now: &Timestamp,
) -> Result<(), AuthRejection> {
    if record.content_type().as_str() != presented_content_type {
        return Err(AuthRejection::ProofRejected);
    }
    freshness(record, now).map_err(classify)
}

/// The freshness half of the verifier's decision, evaluated alone: the
/// record's timestamp must sit no more than the authorization window
/// plus the skew allowance in the verifier's past, and no more than the
/// skew allowance in its future. The named constants are the verifier's
/// own, read as [`request_verification::AUTHORIZATION_WINDOW_SECONDS`]
/// and [`request_verification::CLOCK_SKEW_ALLOWANCE_SECONDS`], so the
/// early gate refuses exactly the proofs the full decision's freshness
/// step refuses — never a superset, never a subset beyond flooring.
fn freshness(record: &AttemptAuthorization, now: &Timestamp) -> Result<(), RequestRejection> {
    const WINDOW: i64 = request_verification::AUTHORIZATION_WINDOW_SECONDS;
    const SKEW: i64 = request_verification::CLOCK_SKEW_ALLOWANCE_SECONDS;
    let age = whole_seconds(now) - whole_seconds(record.authorization_timestamp());
    if age > WINDOW + SKEW {
        Err(RequestRejection::ExpiredAuthorization)
    } else if age < -SKEW {
        Err(RequestRejection::PrematureAuthorization)
    } else {
        Ok(())
    }
}

/// The whole seconds of a calendar timestamp, floored — the same
/// derivation both sides of the age comparison apply. Fractional
/// seconds are truncated: `…:57.9Z` is `…:57`.
fn whole_seconds(timestamp: &Timestamp) -> i64 {
    let bytes = timestamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, byte| acc * 10 + i64::from(*byte - b'0'))
    };
    let year = number(&bytes[..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
}

/// Days from the civil epoch to `year-month-day` (proleptic Gregorian),
/// the calendar half of the age arithmetic.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_offset = if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * (month + month_offset) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The civil date `days` after the Unix epoch (proleptic Gregorian),
/// the inverse of [`days_from_civil`].
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (year + i64::from(month <= 2), month, day)
}

/// Render one Unix-seconds instant as a calendar timestamp. `None` for
/// a clock before the epoch — a broken clock fails toward refusing
/// stale proofs, never toward accepting them.
fn render_timestamp(unix_seconds: u64) -> Option<Timestamp> {
    let days = i64::try_from(unix_seconds / 86_400).ok()?;
    let rest = unix_seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let render = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        (rest % 3_600) / 60,
        rest % 60
    );
    Timestamp::parse(&render).ok()
}

/// The replica's current instant as a calendar timestamp: the one place
/// the authorization path reads the wall clock.
///
/// # Panics
/// Only if a clock before the Unix epoch *and* the epoch instant both
/// fail to render, which the calendar arithmetic cannot produce.
#[must_use]
pub fn now_timestamp() -> Timestamp {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs());
    render_timestamp(seconds)
        .unwrap_or_else(|| render_timestamp(0).expect("the epoch renders as a calendar timestamp"))
}

/// Map the verifier's closed rejection classes onto the registry's
/// authorization refusals. The mapping is the route's whole freedom:
/// every verifier class lands in exactly one registered refusal, and
/// no class carries identifiers to echo.
///
/// Revoked is the one trust-family class with its own registered code;
/// the rest of the family is a proof that does not hold. Cross-tenant,
/// scope, and delegation refusals are the forbidden class — the
/// uploader stands, but not for what the request declares.
#[must_use]
pub fn classify(rejection: RequestRejection) -> AuthRejection {
    match rejection {
        RequestRejection::UnlinkedUploader => AuthRejection::Unlinked,
        // The revoked arm must precede the trust catch-all: the rest of
        // the trust family is a proof that does not hold.
        RequestRejection::Trust(AttemptRejection::Revoked) => AuthRejection::Revoked,
        RequestRejection::MalformedAuthorization
        | RequestRejection::AlteredRequest
        | RequestRejection::ExpiredAuthorization
        | RequestRejection::PrematureAuthorization
        | RequestRejection::InvalidSignature
        | RequestRejection::Trust(_) => AuthRejection::ProofRejected,
        RequestRejection::CrossTenant
        | RequestRejection::ScopeNotGranted
        | RequestRejection::DelegationMissing
        | RequestRejection::DelegationRefused(_) => AuthRejection::Forbidden,
    }
}

/// Build the presented-request evidence the verifier decides against:
/// the identities the parsed envelope declares and the digests computed
/// over the received bytes. The envelope's *declared* payload digests
/// are deliberately unread — the decision's digest members come from
/// [`VerifiedDigests`] alone.
#[must_use]
pub fn presented_request(envelope: &Envelope, digests: &VerifiedDigests) -> PresentedRequest {
    PresentedRequest {
        tenant_id: envelope.tenant_id.clone(),
        uploader_client_id: envelope.uploader_client_id.clone(),
        origin_client_id: envelope.origin_client_id.clone(),
        harness: envelope.harness.clone(),
        request_content_digest: digests.request_content,
        envelope_digest: digests.envelope,
        payload_canonical_digest: digests.payload_canonical,
        payload_transport_digest: digests.payload_transport,
    }
}

/// The complete signed-request decision: render the verifier's verdict
/// against loaded evidence and the replica's clock. This is the gate
/// the commit path sits behind — nothing reaches storage without an
/// [`AuthorizedAttempt`] from here.
///
/// # Errors
/// The mapped [`AuthRejection`] for the verifier's first rejection in
/// its pinned decision order (digests, freshness, linkage, signature,
/// scope, delegation).
pub fn authorize_attempt(
    record: &AttemptAuthorization,
    presented: &PresentedRequest,
    evidence: &UploaderEvidence,
    now: &Timestamp,
) -> Result<AuthorizedAttempt, AuthRejection> {
    verify_request(
        record,
        presented,
        Some(&evidence.uploader),
        evidence.delegation.as_ref(),
        now,
    )
    .map_err(classify)
}

/// Load and verify the control evidence one attempt's uploader stands
/// on: the linked-client record of the presenting client under the
/// tenant the request declares — folded with the client's revocation
/// history, and the pointer-epoch rotation when the attempt presents
/// the previous key inside the overlap window — plus, for a relay
/// attempt, the delegation grant for its pair.
///
/// The linkage probe is deliberately tenant-exact: a client linked
/// under a *different* configured tenant is [`EvidenceRejection::
/// Forbidden`] (the uploader stands, but not for the declared tenant —
/// the corpus's cross-tenant class), while a client linked nowhere is
/// [`EvidenceRejection::Unlinked`]. Telling the two apart is what makes
/// the forbidden code honest, and the probe is bounded by the
/// replica's configured tenant set.
///
/// The revocation fold is bounded by the verified pointer's own epoch —
/// an attacker-chosen epoch cannot extend the walk past the control
/// plane's history, because the walk reaches only epochs the verified
/// pointer has actually issued.
///
/// `fetch_authority_rotation` resolves authority-rotation link bytes by
/// key ID during record verification, exactly as
/// [`crate::state::ServerState::record_verified_control_read`] takes
/// one; a replica whose tenant authority has rotated pre-fetches the
/// links (the reads are the store's) and hands them here.
///
/// # Errors
/// [`EvidenceRejection::RegistryUnavailable`] when a control read
/// fails or a served record fails verification under the pinned
/// authority it was read from; [`EvidenceRejection::Unlinked`] and
/// [`EvidenceRejection::Forbidden`] as above.
pub async fn load_uploader_evidence<C, F>(
    control: &C,
    trust: &TrustConfig,
    record: &AttemptAuthorization,
    declared_tenant: &TenantId,
    uploader: &ClientId,
    origin: &ClientId,
    fetch_authority_rotation: F,
) -> Result<UploaderEvidence, EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    let fetch = |key: &KeyId| fetch_authority_rotation(key);
    let Some(root) = trust.root_for(declared_tenant) else {
        // The declared tenant is not one this replica serves: there is
        // no anchor to verify anything under, so the uploader cannot
        // stand for it.
        return Err(EvidenceRejection::Forbidden);
    };
    let Some(uploader) = client_evidence(control, root, record, uploader, fetch).await? else {
        // Not linked where the request declares: probe the other
        // configured tenants to tell "unlinked" from "linked
        // elsewhere". The probe reads the pointer only — the history
        // fold is not needed to answer where the client stands.
        for other in trust.roots() {
            if other.tenant() == declared_tenant {
                continue;
            }
            if probe_pointer(control, other, uploader, fetch).await? {
                return Err(EvidenceRejection::Forbidden);
            }
        }
        return Err(EvidenceRejection::Unlinked);
    };
    let delegation = relay_grant(
        control,
        root,
        origin,
        uploader.view().pointer().client_id(),
        fetch,
    )
    .await?;
    Ok(UploaderEvidence {
        uploader,
        delegation,
    })
}

/// Read and verify one client's linked-client evidence under `root`,
/// returning `Ok(None)` when the store holds no record at the client's
/// address. A record that fails verification is a registry condition,
/// not an absent client.
async fn client_evidence<C, F>(
    control: &C,
    root: &TenantTrustRoot,
    record: &AttemptAuthorization,
    client: &ClientId,
    fetch: F,
) -> Result<Option<LinkedUploader>, EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    let Some(served) = control
        .read_linked_client(root.tenant(), client)
        .await
        .map_err(|_| EvidenceRejection::RegistryUnavailable)?
    else {
        return Ok(None);
    };
    let pinned = pinned_root(root).ok_or(EvidenceRejection::RegistryUnavailable)?;
    let pointer = LinkedClientPointer::verify(&pinned, served.envelope(), |key| fetch(key), client)
        .map_err(|_| EvidenceRejection::RegistryUnavailable)?;
    let mut view = ClientTrustView::new(pointer.clone());
    fold_history(
        control,
        root.tenant(),
        client,
        &pinned,
        &pointer,
        &mut view,
        &fetch,
    )
    .await?;
    if record.uploader_key_id() != pointer.key_id() {
        // The attempt presents the previous key: the rotation record at
        // the pointer's epoch carries the overlap window, and only the
        // full decision decides whether this attempt is inside it.
        fold_rotation(
            control,
            root.tenant(),
            client,
            &pinned,
            &pointer,
            &mut view,
            &fetch,
        )
        .await?;
    }
    // The public half and scope the verified record carries: the
    // pointer's verification held their shapes, and the evidence
    // constructor re-checks the half against the pointer's key ID —
    // a consistency only a defect here could break, but checked rather
    // than assumed.
    let Ok(Value::Object(object)) = json::parse(served.envelope()) else {
        return Err(EvidenceRejection::RegistryUnavailable);
    };
    let public_key = member_public_key(&object)?;
    let scopes = member_scopes(&object)?;
    LinkedUploader::new(&pinned, view, public_key, scopes)
        .map(Some)
        .ok_or(EvidenceRejection::RegistryUnavailable)
}

/// Whether the control plane holds a verified linked-client pointer for
/// one client under `root`'s tenant — the cross-tenant probe, which
/// reads the pointer alone.
async fn probe_pointer<C, F>(
    control: &C,
    root: &TenantTrustRoot,
    client: &ClientId,
    fetch: F,
) -> Result<bool, EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    let Some(served) = control
        .read_linked_client(root.tenant(), client)
        .await
        .map_err(|_| EvidenceRejection::RegistryUnavailable)?
    else {
        return Ok(false);
    };
    let pinned = pinned_root(root).ok_or(EvidenceRejection::RegistryUnavailable)?;
    LinkedClientPointer::verify(&pinned, served.envelope(), |key| fetch(key), client)
        .map(|_| true)
        .map_err(|_| EvidenceRejection::RegistryUnavailable)
}

/// Fold the client's revocation history into the view: every revocation
/// the control plane published at epochs the verified pointer has
/// reached.
async fn fold_history<C, F>(
    control: &C,
    tenant: &TenantId,
    client: &ClientId,
    pinned: &PinnedAuthorityRoot,
    pointer: &LinkedClientPointer,
    view: &mut ClientTrustView,
    fetch: &F,
) -> Result<(), EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    for epoch in 1..=pointer.epoch() {
        let Some(addressed) = AuthorizationEpoch::new(epoch).ok() else {
            continue;
        };
        if let Some(served) = control
            .read_revocation(tenant, client, addressed)
            .await
            .map_err(|_| EvidenceRejection::RegistryUnavailable)?
        {
            let verified = RevocationRecord::verify(
                pinned,
                served.envelope(),
                |key| fetch(key),
                client,
                epoch,
            )
            .map_err(|_| EvidenceRejection::RegistryUnavailable)?;
            view.record_revocation(&verified)
                .map_err(|_| EvidenceRejection::RegistryUnavailable)?;
        }
    }
    Ok(())
}

/// Read the rotation record at the pointer's epoch into the view — the
/// record whose window the overlap half of the trust decision evaluates
/// against.
async fn fold_rotation<C, F>(
    control: &C,
    tenant: &TenantId,
    client: &ClientId,
    pinned: &PinnedAuthorityRoot,
    pointer: &LinkedClientPointer,
    view: &mut ClientTrustView,
    fetch: &F,
) -> Result<(), EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    let Some(addressed) = AuthorizationEpoch::new(pointer.epoch()).ok() else {
        return Ok(());
    };
    let Some(served) = control
        .read_rotation(tenant, client, addressed)
        .await
        .map_err(|_| EvidenceRejection::RegistryUnavailable)?
    else {
        return Ok(());
    };
    let verified = RotationRecord::verify(
        pinned,
        served.envelope(),
        |key| fetch(key),
        client,
        pointer.epoch(),
    )
    .map_err(|_| EvidenceRejection::RegistryUnavailable)?;
    view.record_rotation(&verified)
        .map_err(|_| EvidenceRejection::RegistryUnavailable)
}

/// Read and verify the relay grant for one (relay, origin) pair under
/// the declared tenant. A direct attempt reads nothing; a relay attempt
/// without a grant is the forbidden class — the conjunction has no
/// delegation dimension to stand on (plan Section 5).
async fn relay_grant<C, F>(
    control: &C,
    root: &TenantTrustRoot,
    origin: &ClientId,
    relay: &ClientId,
    fetch: F,
) -> Result<Option<DelegationRecord>, EvidenceRejection>
where
    C: ControlReadStore,
    F: Fn(&KeyId) -> Option<Vec<u8>>,
{
    if origin == relay {
        return Ok(None);
    }
    let Some(served) = control
        .read_delegation(root.tenant(), relay, origin)
        .await
        .map_err(|_| EvidenceRejection::RegistryUnavailable)?
    else {
        return Err(EvidenceRejection::Forbidden);
    };
    let pinned = pinned_root(root).ok_or(EvidenceRejection::RegistryUnavailable)?;
    DelegationRecord::verify(&pinned, served.envelope(), |key| fetch(key), relay, origin)
        .map(Some)
        .map_err(|_| EvidenceRejection::RegistryUnavailable)
}

/// The pinned verification anchor for one configured tenant: the
/// configured authority text parsed into the verifier's root type. A
/// configured anchor that fails its own grammar is a construction
/// defect [`crate::trust`] already rejects; surfacing it here again is
/// the fail-closed rendering.
fn pinned_root(root: &TenantTrustRoot) -> Option<PinnedAuthorityRoot> {
    let public_key = Ed25519PublicKey::parse(root.authority().as_str()).ok()?;
    Some(PinnedAuthorityRoot::new(root.tenant().clone(), public_key))
}

/// The verified linked-client record's public half.
fn member_public_key(object: &Object) -> Result<Ed25519PublicKey, EvidenceRejection> {
    match object.get("public_key") {
        Some(Value::Text(text)) => {
            Ed25519PublicKey::parse(text).map_err(|_| EvidenceRejection::RegistryUnavailable)
        }
        _ => Err(EvidenceRejection::RegistryUnavailable),
    }
}

/// The verified linked-client record's scope: the two allowlists the
/// record schema pins, parsed into the decision's scope type. The
/// pointer verification has already held each member's shape, so a
/// failure here is a registry condition, not a wire condition.
fn member_scopes(object: &Object) -> Result<LinkedClientScopes, EvidenceRejection> {
    let Some(Value::Object(scopes)) = object.get("scopes") else {
        return Err(EvidenceRejection::RegistryUnavailable);
    };
    let harnesses = allowlist(scopes, "harnesses")?;
    let mut harness_ids = Vec::with_capacity(harnesses.len());
    for text in &harnesses {
        let parsed = HarnessId::parse(text).map_err(|_| EvidenceRejection::RegistryUnavailable)?;
        harness_ids.push(parsed);
    }
    let operations = allowlist(scopes, "operations")?;
    let mut operation_ids = Vec::with_capacity(operations.len());
    for text in &operations {
        // The closed v1 operation set — the same mapping the scope
        // record's own parser applies.
        let parsed = match text.as_str() {
            "ingest" => ScopeOperation::Ingest,
            _ => return Err(EvidenceRejection::RegistryUnavailable),
        };
        operation_ids.push(parsed);
    }
    LinkedClientScopes::new(harness_ids, operation_ids)
        .ok_or(EvidenceRejection::RegistryUnavailable)
}

/// The text members of one scope allowlist.
fn allowlist(scopes: &Object, name: &str) -> Result<Vec<String>, EvidenceRejection> {
    match scopes.get(name) {
        Some(Value::Array(entries)) => {
            let mut texts = Vec::with_capacity(entries.len());
            for entry in entries {
                match entry {
                    Value::Text(text) => texts.push(text.clone()),
                    _ => return Err(EvidenceRejection::RegistryUnavailable),
                }
            }
            Ok(texts)
        }
        _ => Err(EvidenceRejection::RegistryUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_RECORD: &str = r#"{
        "authorization_epoch": 1,
        "authorization_timestamp": "2026-09-11T17:59:57Z",
        "content_type": "multipart/related; boundary=archivist-conformance-01",
        "envelope_digest": "3edfc8806d4bfbb8150fe3a47d98706a0255f03c16d0ff107e6141383c751160",
        "http_method": "POST",
        "payload_canonical_digest": "1954362cfdaf85cb2a0dd5825a303964da1fb31cf96d0f9739db3c4882327175",
        "payload_transport_digest": "1954362cfdaf85cb2a0dd5825a303964da1fb31cf96d0f9739db3c4882327175",
        "request_content_digest": "4512b15204495dcf82cc34972d38bb380a8fad3f74b097bc26c35d91bf61d9f4",
        "route": "/v1/ingest",
        "signature": "0ec7de174c1af1e0bd4886c0e02009b59c740439c5b6a002f3aec336f4e9aae736707bd40fd5f669b3aa857a6ca6942852f0160e8aa4be8a15eba7ae4cee2b03",
        "signature_algorithm": "ed25519",
        "uploader_key_id": "dfe2aa808676ed8715694c1e999df98c8c0aea915758fb6c9b056b51b1636702"
    }"#;

    fn fixture_record() -> AttemptAuthorization {
        let value = json::parse(FIXTURE_RECORD.as_bytes()).expect("fixture parses");
        AttemptAuthorization::parse(&value).expect("fixture is a valid record shape")
    }

    fn at(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("test timestamp renders")
    }

    #[test]
    fn calendar_math_matches_known_days() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // The classic reference point of the civil-days algorithms.
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(days_from_civil(2026, 9, 11), 20_707);
        for days in [-1, 0, 1, 719_468, 719_469, 10_000, 30_000] {
            let (year, month, day) = civil_from_days(days);
            assert_eq!(days_from_civil(year, month, day), days, "round trip {days}");
        }
    }

    #[test]
    fn whole_seconds_is_floor_and_fraction_blind() {
        let base = at("2026-09-11T17:59:57Z");
        let fraction = at("2026-09-11T17:59:57.987654321Z");
        assert_eq!(whole_seconds(&base), whole_seconds(&fraction));
        let next_day = at("2026-09-12T17:59:57Z");
        assert_eq!(whole_seconds(&next_day) - whole_seconds(&base), 86_400);
        let expected = 20_707 * 86_400 + 17 * 3_600 + 59 * 60 + 57;
        assert_eq!(whole_seconds(&base), expected);
    }

    #[test]
    fn now_timestamp_tracks_the_wall_clock() {
        let now = now_timestamp();
        let system = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since_epoch| {
                i64::try_from(since_epoch.as_secs()).unwrap_or(0)
            });
        assert!(
            (whole_seconds(&now) - system).abs() <= 5,
            "rendered {now} against system {system}"
        );
    }

    #[test]
    fn pre_authorize_window_edges() {
        let record = fixture_record();
        let covered = record.content_type().as_str();
        let stamp = at("2026-09-11T17:59:57Z");
        let window = request_verification::AUTHORIZATION_WINDOW_SECONDS;
        let skew = request_verification::CLOCK_SKEW_ALLOWANCE_SECONDS;
        let shift = |seconds: i64| {
            let shifted = whole_seconds(&stamp) + seconds;
            let (year, month, day) = civil_from_days(shifted.div_euclid(86_400));
            let rest = shifted.rem_euclid(86_400);
            let text = format!(
                "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
                rest / 3_600,
                (rest % 3_600) / 60,
                rest % 60
            );
            at(&text)
        };
        assert_eq!(pre_authorize(&record, covered, &stamp), Ok(()));
        assert_eq!(
            pre_authorize(&record, covered, &shift(window + skew)),
            Ok(())
        );
        assert_eq!(
            pre_authorize(&record, covered, &shift(window + skew + 1)),
            Err(AuthRejection::ProofRejected)
        );
        assert_eq!(pre_authorize(&record, covered, &shift(-skew)), Ok(()));
        assert_eq!(
            pre_authorize(&record, covered, &shift(-skew - 1)),
            Err(AuthRejection::ProofRejected)
        );
    }

    #[test]
    fn pre_authorize_refuses_a_request_the_record_does_not_describe() {
        let record = fixture_record();
        // The covered content type is part of the signature's preimage:
        // the same record presented under a substituted boundary is the
        // corpus's altered-framing class, refused before the body opens.
        assert_eq!(
            pre_authorize(
                &record,
                "multipart/related; boundary=archivist-altered-9f",
                record.authorization_timestamp(),
            ),
            Err(AuthRejection::ProofRejected)
        );
    }

    #[test]
    fn classify_maps_every_rejection_family() {
        let proof = AuthRejection::ProofRejected;
        assert_eq!(classify(RequestRejection::MalformedAuthorization), proof);
        assert_eq!(classify(RequestRejection::AlteredRequest), proof);
        assert_eq!(classify(RequestRejection::ExpiredAuthorization), proof);
        assert_eq!(classify(RequestRejection::PrematureAuthorization), proof);
        assert_eq!(classify(RequestRejection::InvalidSignature), proof);
        assert_eq!(
            classify(RequestRejection::UnlinkedUploader),
            AuthRejection::Unlinked
        );
        assert_eq!(
            classify(RequestRejection::Trust(AttemptRejection::Revoked)),
            AuthRejection::Revoked
        );
        assert_eq!(
            classify(RequestRejection::Trust(AttemptRejection::StaleEpoch)),
            proof
        );
        assert_eq!(
            classify(RequestRejection::CrossTenant),
            AuthRejection::Forbidden
        );
        assert_eq!(
            classify(RequestRejection::ScopeNotGranted),
            AuthRejection::Forbidden
        );
        assert_eq!(
            classify(RequestRejection::DelegationMissing),
            AuthRejection::Forbidden
        );
        assert_eq!(
            classify(RequestRejection::DelegationRefused(
                archivist_auth::delegation::DelegationRejection::Withdrawn
            )),
            AuthRejection::Forbidden
        );
    }

    #[test]
    fn member_parsing_holds_the_record_scope() {
        let record = json::parse(
            br#"{
                "public_key": "7949b02cdd46fc7e41b18c238916d851c0a8fb7a944dc1b6329f65d1205d4e2d",
                "scopes": {"harnesses": ["claude-code"], "operations": ["ingest"]}
            }"#,
        )
        .expect("test object parses");
        let Value::Object(object) = record else {
            panic!("test object is an object");
        };
        member_public_key(&object).expect("the fixture half parses");
        let scopes = member_scopes(&object).expect("the fixture scope parses");
        assert!(scopes.contains_operation(ScopeOperation::Ingest));

        let bogus_operation = json::parse(
            br#"{
                "public_key": "7949b02cdd46fc7e41b18c238916d851c0a8fb7a944dc1b6329f65d1205d4e2d",
                "scopes": {"harnesses": ["claude-code"], "operations": ["exfiltrate"]}
            }"#,
        )
        .expect("test object parses");
        let Value::Object(object) = bogus_operation else {
            panic!("test object is an object");
        };
        assert_eq!(
            member_scopes(&object),
            Err(EvidenceRejection::RegistryUnavailable)
        );
    }
}
