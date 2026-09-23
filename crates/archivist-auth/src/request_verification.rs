// SPDX-License-Identifier: Apache-2.0

//! Per-attempt verification of the signed ingest request (plan Section
//! 7.2): the decision an ingestion replica renders between admission and
//! any storage write.
//!
//! Every upload attempt arrives as a canonical envelope plus a
//! signature-parameter record — the twelve closed members of
//! `schemas/v1/ingest-request.json` — whose Ed25519 signature
//! (`ingest-attempt-v1`, `schemas/v1/ingest-identifiers.json`) covers the
//! method, route, content type, whole-request digest, envelope digest,
//! both payload digests, the uploader key ID, the authorization epoch,
//! and the fresh authorization timestamp, in the pinned order. This
//! module is the server side of that construction:
//! [`AttemptAuthorization`] parses and frames the record,
//! [`verify_request`] renders the accept-or-reject decision, and
//! [`AuthorizedAttempt`] is the only value a caller may treat as license
//! to write.
//!
//! # The decision, in order
//!
//! Every check is fail-closed and every rejection is a content-free
//! class ([`RequestRejection`], CFG-027). The order is the contract, and
//! the acceptance property — *altered, replay-expired, unlinked,
//! revoked, cross-tenant, and unauthorized requests make no storage
//! writes* — holds because the decision returns before any caller has a
//! success value to act on:
//!
//! 1. **Digest agreement** ([`RequestRejection::AlteredRequest`]). The
//!    four covered digests are compared against digests the caller
//!    computed over the bytes actually received. The presented members
//!    are inside the signature, so a mismatch proves the body, the
//!    envelope part, or either payload representation diverges from the
//!    bytes the uploader authorized (IA-02): the signature is valid but
//!    not over this request.
//! 2. **Freshness** ([`RequestRejection::ExpiredAuthorization`],
//!    [`RequestRejection::PrematureAuthorization`]). The authorization
//!    timestamp must sit within [`AUTHORIZATION_WINDOW_SECONDS`] of the
//!    verifier's clock, extended by [`CLOCK_SKEW_ALLOWANCE_SECONDS`] on
//!    both edges: the window protects the signer's freshness, the skew
//!    allowance the verifier's clock, and the two deliberately equal
//!    five-minute values are never collapsed into one ten-minute window
//!    (control trust note, timing constants). A retry past the window
//!    re-authorizes with fresh state — it is rejected here and nowhere
//!    else (ID-007).
//! 3. **Linkage** ([`RequestRejection::UnlinkedUploader`],
//!    [`RequestRejection::CrossTenant`], [`RequestRejection::Trust`]).
//!    The presenting key must resolve to a linked client of the tenant
//!    the request declares, and the presented epoch and key must stand
//!    in that client's trust view at the authorization instant:
//!    revocation, staleness, and the 24-hour rotation overlap are the
//!    [`ClientTrustView`] decision, consumed here and decided nowhere
//!    else.
//! 4. **Signature** ([`RequestRejection::InvalidSignature`]). The
//!    Ed25519 signature verifies under the admitted half — the
//!    pointer's own half, or, inside its window, the establishing
//!    rotation's previous half — over the exact
//!    [`ingest-attempt-v1`][ingest_attempt_signing_input] preimage.
//! 5. **Scope** ([`RequestRejection::ScopeNotGranted`]). The harness the
//!    attempt carries and the one v1 operation the route names must be
//!    inside the presenter's own linked scope. The route is pinned to
//!    `/v1/ingest` at parse time, so the operation is derived, never
//!    presented.
//! 6. **Origin delegation** ([`RequestRejection::DelegationMissing`],
//!    [`RequestRejection::DelegationRefused`]). A relay attempt — one
//!    presenting an origin other than its own client — must carry a
//!    verified delegation record whose tenant/origin/harness/operation
//!    conjunction admits it; the authorized attempt anchors at the
//!    origin, never the relay (EC-05A). A direct attempt anchors at
//!    itself and consults no delegation.
//!
//! # Purity and composition
//!
//! The module is pure: no I/O, no clock — `now` is a parameter, and the
//! verified control material (the [`LinkedUploader`] evidence and the
//! [`DelegationRecord`]) is whatever a verified control read served for
//! the attempt's tenant, through the store and its cache. Nothing here
//! reads storage, so nothing here can write it: the decision is complete
//! before a caller has an [`AuthorizedAttempt`], which is the shape the
//! no-write acceptance pins.
//!
//! [ingest_attempt_signing_input]:
//!     archivist_protocol::derivation::ingest_attempt_signing_input

use std::fmt;

use archivist_protocol::derivation;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{
    BlobDigest, ClientId, ContentType, Ed25519PublicKey, Ed25519Signature, EnvelopeDigest,
    GrammarError, HarnessId, IncomingChecksum, KeyId, PayloadCanonicalDigest,
    PayloadTransportDigest, RequestContentDigest, SignatureAlgorithm, TenantId, Timestamp,
};

use crate::authority::PinnedAuthorityRoot;
use crate::delegation::{DelegationRecord, DelegationRejection, LinkedClientScopes, RelayAttempt};
use crate::ed25519::{self, Signature};
use crate::link::ScopeOperation;
use crate::revocation::{AttemptRejection, AuthorizationAttempt, ClientTrustView};

/// How long one attempt's authorization stays fresh after its own
/// timestamp (`authorizationWindowSeconds`, plan Section 5: "Request
/// authorization is fresh per upload attempt and valid for five
/// minutes").
pub const AUTHORIZATION_WINDOW_SECONDS: i64 = 300;

/// How far the signer's clock may disagree with the verifier's in either
/// direction (`clockSkewAllowanceSeconds`, plan Section 5: "with at most
/// five minutes of clock skew"). Deliberately equal to the window and
/// deliberately named separately: the two must not merge into one
/// ten-minute rule.
pub const CLOCK_SKEW_ALLOWANCE_SECONDS: i64 = 300;

/// The method every v1 attempt signs (`ingest-request.json` const).
const HTTP_METHOD: &str = "POST";

/// The route every v1 attempt signs — the route that names the one v1
/// operation ([`ScopeOperation::Ingest`]).
const ROUTE: &str = "/v1/ingest";

/// The closed member set of the signature-parameter record
/// (`ingest-request.json`, `additionalProperties: false`): per-attempt
/// state, so there is nothing to carry forward and an open shape would
/// only widen the disclosure surface (ERR-033).
const ATTEMPT_MEMBERS: [&str; 12] = [
    "http_method",
    "route",
    "content_type",
    "request_content_digest",
    "envelope_digest",
    "payload_canonical_digest",
    "payload_transport_digest",
    "uploader_key_id",
    "authorization_epoch",
    "authorization_timestamp",
    "signature_algorithm",
    "signature",
];

/// The parsed signature-parameter record of one ingest attempt: the
/// twelve closed wire members, each validated against its own grammar.
///
/// Everything an Ed25519 HTTP message signature covers except the
/// covered method and route — those are pinned constants every valid v1
/// record carries, so they are checked at parse time and never stored.
/// Parse with [`AttemptAuthorization::parse`] and nothing else; a value
/// of this type has already failed closed on an unknown method, route,
/// or algorithm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptAuthorization {
    content_type: ContentType,
    request_content_digest: RequestContentDigest,
    envelope_digest: EnvelopeDigest,
    payload_canonical_digest: PayloadCanonicalDigest,
    payload_transport_digest: PayloadTransportDigest,
    uploader_key_id: KeyId,
    authorization_epoch: u64,
    authorization_timestamp: Timestamp,
    signature: Ed25519Signature,
}

impl AttemptAuthorization {
    /// Parse one signature-parameter record from its wire JSON.
    ///
    /// The record is a closed shape, so the member set is exact: an
    /// unknown member, a missing one, a method or route or algorithm
    /// outside its pinned v1 value, a digest outside the lowercase-hex
    /// grammar, a zero or negative epoch, or a non-calendar timestamp is
    /// a malformed record — the same failure class for every shape
    /// refusal, because every one of them means "this is not a v1
    /// attempt record" and none may echo what arrived (CFG-027).
    ///
    /// # Errors
    /// [`RequestRejection::MalformedAuthorization`] for every shape,
    /// grammar, or pinned-constant failure.
    pub fn parse(value: &Value) -> Result<Self, RequestRejection> {
        const MALFORMED: RequestRejection = RequestRejection::MalformedAuthorization;
        let Value::Object(object) = value else {
            return Err(MALFORMED);
        };
        if object.len() != ATTEMPT_MEMBERS.len()
            || ATTEMPT_MEMBERS
                .iter()
                .any(|member| object.get(member).is_none())
        {
            return Err(MALFORMED);
        }
        if text_member(object, "http_method") != Some(HTTP_METHOD)
            || text_member(object, "route") != Some(ROUTE)
        {
            return Err(MALFORMED);
        }
        let algorithm = text_member(object, "signature_algorithm")
            .and_then(|token| SignatureAlgorithm::parse(token).ok());
        if algorithm != Some(SignatureAlgorithm::Ed25519) {
            return Err(MALFORMED);
        }
        let content_type =
            ContentType::parse(text_member(object, "content_type").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        let request_content_digest =
            digest_member::<RequestContentDigest>(object, "request_content_digest")?;
        let envelope_digest = digest_member::<EnvelopeDigest>(object, "envelope_digest")?;
        let payload_canonical_digest =
            digest_member::<PayloadCanonicalDigest>(object, "payload_canonical_digest")?;
        let payload_transport_digest =
            digest_member::<PayloadTransportDigest>(object, "payload_transport_digest")?;
        let uploader_key_id =
            KeyId::parse(text_member(object, "uploader_key_id").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        let epoch = int_member(object, "authorization_epoch").ok_or(MALFORMED)?;
        if epoch < 1 {
            // Epochs are one-based: zero was never established, and no
            // attempt may present it.
            return Err(MALFORMED);
        }
        let authorization_timestamp =
            Timestamp::parse(text_member(object, "authorization_timestamp").ok_or(MALFORMED)?)
                .map_err(|_| MALFORMED)?;
        if !authorization_timestamp.calendar_valid() {
            return Err(MALFORMED);
        }
        let signature = Ed25519Signature::parse(text_member(object, "signature").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        Ok(Self {
            content_type,
            request_content_digest,
            envelope_digest,
            payload_canonical_digest,
            payload_transport_digest,
            uploader_key_id,
            authorization_epoch: u64::try_from(epoch).map_err(|_| MALFORMED)?,
            authorization_timestamp,
            signature,
        })
    }

    /// The exact `ingest-attempt-v1` preimage the signature covers: the
    /// domain label, then the ten covered fields in the pinned order,
    /// framed per the construction registry. The framing itself is the
    /// protocol crate's, so signer and verifier share one implementation.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        derivation::ingest_attempt_signing_input(
            HTTP_METHOD,
            ROUTE,
            self.content_type.as_str(),
            &self.request_content_digest,
            &self.envelope_digest,
            &BlobDigest::from_raw(*self.payload_canonical_digest.as_raw()),
            &IncomingChecksum::from_raw(*self.payload_transport_digest.as_raw()),
            &self.uploader_key_id,
            self.authorization_epoch,
            &self.authorization_timestamp,
        )
    }

    /// The covered content type, boundary parameter included.
    #[must_use]
    pub const fn content_type(&self) -> &ContentType {
        &self.content_type
    }

    /// The covered whole-request digest.
    #[must_use]
    pub const fn request_content_digest(&self) -> &RequestContentDigest {
        &self.request_content_digest
    }

    /// The covered canonical envelope digest.
    #[must_use]
    pub const fn envelope_digest(&self) -> &EnvelopeDigest {
        &self.envelope_digest
    }

    /// The covered canonical payload digest.
    #[must_use]
    pub const fn payload_canonical_digest(&self) -> &PayloadCanonicalDigest {
        &self.payload_canonical_digest
    }

    /// The covered as-transported payload digest.
    #[must_use]
    pub const fn payload_transport_digest(&self) -> &PayloadTransportDigest {
        &self.payload_transport_digest
    }

    /// The linked uploader key the attempt authorizes under.
    #[must_use]
    pub const fn uploader_key_id(&self) -> &KeyId {
        &self.uploader_key_id
    }

    /// The authorization epoch the attempt presents.
    #[must_use]
    pub const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }

    /// The fresh authorization timestamp the signature binds.
    #[must_use]
    pub const fn authorization_timestamp(&self) -> &Timestamp {
        &self.authorization_timestamp
    }

    /// The attempt's Ed25519 signature over [`Self::signing_input`].
    #[must_use]
    pub const fn signature(&self) -> &Ed25519Signature {
        &self.signature
    }
}

/// What the pipeline computed from one received request, beyond the
/// attempt record itself: the identities the parsed envelope declares and
/// the digests the received bytes actually hash to.
///
/// The members are already-validated vocabulary values and digests the
/// caller computed over the received bytes — the decision is relative
/// between the record and this evidence, so no constructor invariant
/// exists beyond the types' own grammars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentedRequest {
    /// The tenant the envelope declares — the namespace every write this
    /// attempt could cause would land in.
    pub tenant_id: TenantId,
    /// The linked client presenting the attempt (the uploader).
    pub uploader_client_id: ClientId,
    /// The origin the attempt presents: the uploader itself for a direct
    /// upload, another linked client for a relay attempt.
    pub origin_client_id: ClientId,
    /// The harness whose session the attempt carries.
    pub harness: HarnessId,
    /// SHA-256 over the whole received request body.
    pub request_content_digest: RequestContentDigest,
    /// SHA-256 over the canonical envelope bytes the part re-serializes
    /// to.
    pub envelope_digest: EnvelopeDigest,
    /// SHA-256 over the canonical uncompressed payload bytes.
    pub payload_canonical_digest: PayloadCanonicalDigest,
    /// SHA-256 over the payload bytes as transported.
    pub payload_transport_digest: PayloadTransportDigest,
}

/// The verified control evidence one uploader presents: the client's
/// folded trust view, the public half its pointer's key ID derives from,
/// and the scope its linked-client record carries.
///
/// Assembled from verified control reads and nothing else —
/// [`ClientTrustView`] from the pointer plus the revocations and
/// rotations folded into it, the half from the record the pointer was
/// verified from, the scope from the same record. The constructor
/// refuses a half whose derivation is not the pointer's own key ID: the
/// evidence must be internally consistent before the decision reads it.
#[derive(Clone, Debug)]
pub struct LinkedUploader {
    tenant_id: TenantId,
    view: ClientTrustView,
    public_key: Ed25519PublicKey,
    scopes: LinkedClientScopes,
}

impl LinkedUploader {
    /// Assemble the evidence for one uploader: the view folded from the
    /// client's control history, the record's public half, and the
    /// record's scope. `root` is the tenant authority the record was
    /// verified under — the tenant the evidence belongs to.
    ///
    /// `None` when the half does not derive the pointer's key ID: a
    /// record whose members disagree is not evidence.
    #[must_use]
    pub fn new(
        root: &PinnedAuthorityRoot,
        view: ClientTrustView,
        public_key: Ed25519PublicKey,
        scopes: LinkedClientScopes,
    ) -> Option<Self> {
        if KeyId::from_public_key(&public_key) != *view.pointer().key_id() {
            return None;
        }
        Some(Self {
            tenant_id: root.tenant_id().clone(),
            view,
            public_key,
            scopes,
        })
    }

    /// The tenant whose authority verified the evidence.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The folded trust view the decision evaluates against.
    #[must_use]
    pub const fn view(&self) -> &ClientTrustView {
        &self.view
    }

    /// The record's public half — the pointer's own.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The linked-client record's scope.
    #[must_use]
    pub const fn scopes(&self) -> &LinkedClientScopes {
        &self.scopes
    }
}

/// An attempt the verifier admitted: the identities and authorization a
/// caller may write storage under.
///
/// The occurrence and attestation anchor at [`Self::anchor_client_id`] —
/// the origin a delegation names for a relay attempt, the uploader
/// itself for a direct one (EC-05A) — while the receipt binds the
/// authorization key and epoch that committed it (RCPT-002).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedAttempt {
    uploader_client_id: ClientId,
    anchor_client_id: ClientId,
    key_id: KeyId,
    authorization_epoch: u64,
}

impl AuthorizedAttempt {
    /// The linked client that presented the attempt.
    #[must_use]
    pub const fn uploader_client_id(&self) -> &ClientId {
        &self.uploader_client_id
    }

    /// The client the attempt's occurrence and attestation anchor at.
    #[must_use]
    pub const fn anchor_client_id(&self) -> &ClientId {
        &self.anchor_client_id
    }

    /// The authorization key that signed the attempt — the key a
    /// receipt binds (RCPT-002).
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The authorization epoch the attempt presented.
    #[must_use]
    pub const fn authorization_epoch(&self) -> u64 {
        self.authorization_epoch
    }
}

/// Why an ingest attempt is rejected: the closed decision classes a
/// replica reports, in decision order.
///
/// Every variant is fail-closed — none is retryable against the same
/// evidence — and none carries the offending identifiers (CFG-027). The
/// trust and delegation classes carry the family decisions they wrap, so
/// a caller that needs the finer dimension (which scope refused, whether
/// a grant was withdrawn) reads the wrapped value; [`Self::class_text`]
/// stays coarse for metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RequestRejection {
    /// The signature-parameter record is not a v1 record: wrong member
    /// set, a pinned constant that does not hold, a grammar or calendar
    /// failure.
    MalformedAuthorization,
    /// A covered digest disagrees with the bytes received: the request's
    /// body, envelope part, or payload representation is not what the
    /// uploader signed (IA-02).
    AlteredRequest,
    /// The authorization timestamp is older than the window plus the
    /// skew allowance: the attempt expired and must re-authorize
    /// (ID-007).
    ExpiredAuthorization,
    /// The authorization timestamp is further ahead of the verifier's
    /// clock than the skew allowance: a future-dated proof.
    PrematureAuthorization,
    /// No verified linked-client evidence exists for the presenting
    /// client: the key is unlinked in the tenant the request declares.
    UnlinkedUploader,
    /// The presenting key's evidence belongs to another tenant: the
    /// signature may verify, but the linkage does not cross tenants
    /// (EC-03).
    CrossTenant,
    /// The linked client's own trust decision refused the attempt —
    /// client mismatch, an epoch the pointer has not reached, a stale
    /// epoch, a revoked key, or an epoch/key pairing no record holds.
    Trust(AttemptRejection),
    /// The Ed25519 signature does not verify over the pinned preimage
    /// under the admitted half.
    InvalidSignature,
    /// The attempt's harness or operation is outside the presenter's own
    /// linked scope.
    ScopeNotGranted,
    /// A relay attempt arrived without verified delegation evidence for
    /// its (tenant, relay, origin) pair.
    DelegationMissing,
    /// The delegation evidence refused the attempt — withdrawn, wrong
    /// pair, or a scope dimension the conjunction does not grant.
    DelegationRefused(DelegationRejection),
}

impl RequestRejection {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedAuthorization => "malformed-authorization",
            Self::AlteredRequest => "altered-request",
            Self::ExpiredAuthorization => "expired-authorization",
            Self::PrematureAuthorization => "premature-authorization",
            Self::UnlinkedUploader => "unlinked-uploader",
            Self::CrossTenant => "cross-tenant",
            Self::Trust(_) => "trust-refused",
            Self::InvalidSignature => "invalid-signature",
            Self::ScopeNotGranted => "scope-not-granted",
            Self::DelegationMissing => "delegation-missing",
            Self::DelegationRefused(_) => "delegation-refused",
        }
    }

    /// The trust-family refusal this rejection wrapped, when it did.
    #[must_use]
    pub const fn trust_rejection(self) -> Option<AttemptRejection> {
        match self {
            Self::Trust(rejection) => Some(rejection),
            _ => None,
        }
    }

    /// The delegation refusal this rejection wrapped, when it did.
    #[must_use]
    pub const fn delegation_rejection(self) -> Option<DelegationRejection> {
        match self {
            Self::DelegationRefused(rejection) => Some(rejection),
            _ => None,
        }
    }
}

impl fmt::Display for RequestRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for RequestRejection {}

/// Verify one ingest attempt: render the accept-or-reject decision the
/// plan's server data flow makes after admission and before anything is
/// written (plan Section 7.2).
///
/// `authorization` is the received signature-parameter record;
/// `presented` is what the pipeline computed from the received bytes and
/// parsed envelope; `linked` is the verified uploader evidence for the
/// presenting client, `None` when no verified record served;
/// `delegation` is the verified delegation evidence for the attempt's
/// (tenant, uploader, origin) pair, `None` when none served — which only
/// a relay attempt notices; `now` is the verifier's clock.
///
/// The decision order is the module contract (digests, freshness,
/// linkage, signature, scope, delegation): every rejection is rendered
/// before an [`AuthorizedAttempt`] exists, so the no-write acceptance —
/// altered, replay-expired, unlinked, revoked, cross-tenant, and
/// unauthorized requests make no storage writes — holds structurally,
/// not by caller discipline.
///
/// The freshness rule reads the two named constants separately: a
/// timestamp is acceptable exactly when it sits no more than
/// [`AUTHORIZATION_WINDOW_SECONDS`] plus [`CLOCK_SKEW_ALLOWANCE_SECONDS`]
/// in the verifier's past and no more than [`CLOCK_SKEW_ALLOWANCE_SECONDS`]
/// in the verifier's future. Sub-second timestamp fractions are floored,
/// so an attempt within one second of either bound may land either side
/// of it.
///
/// # Errors
/// The matching [`RequestRejection`] class, in decision order.
pub fn verify_request(
    authorization: &AttemptAuthorization,
    presented: &PresentedRequest,
    linked: Option<&LinkedUploader>,
    delegation: Option<&DelegationRecord>,
    now: &Timestamp,
) -> Result<AuthorizedAttempt, RequestRejection> {
    // 1. Digest agreement: the covered digests must name the bytes the
    // request actually carried. The presented members are signed, so
    // this is where an altered body, envelope, or payload is caught —
    // the signature would verify, over different bytes.
    if authorization.request_content_digest() != &presented.request_content_digest
        || authorization.envelope_digest() != &presented.envelope_digest
        || authorization.payload_canonical_digest() != &presented.payload_canonical_digest
        || authorization.payload_transport_digest() != &presented.payload_transport_digest
    {
        return Err(RequestRejection::AlteredRequest);
    }

    // 2. Freshness: the window protects the signer's declared lifetime,
    // the skew allowance the two clocks. The two five-minute values stay
    // two — one window, two skew edges.
    let age = epoch_seconds(now) - epoch_seconds(authorization.authorization_timestamp());
    if age > AUTHORIZATION_WINDOW_SECONDS + CLOCK_SKEW_ALLOWANCE_SECONDS {
        return Err(RequestRejection::ExpiredAuthorization);
    }
    if age < -CLOCK_SKEW_ALLOWANCE_SECONDS {
        return Err(RequestRejection::PrematureAuthorization);
    }

    // 3. Linkage: the presenting key must be a linked client of the
    // tenant the request declares, and the attempt must stand in that
    // client's history at its own authorization instant — revocation,
    // staleness, and the rotation overlap are the view's decision.
    let linked = linked.ok_or(RequestRejection::UnlinkedUploader)?;
    if linked.tenant_id() != &presented.tenant_id {
        return Err(RequestRejection::CrossTenant);
    }
    let attempt = AuthorizationAttempt::new(
        presented.uploader_client_id.clone(),
        authorization.authorization_epoch(),
        *authorization.uploader_key_id(),
    )
    .ok_or(RequestRejection::MalformedAuthorization)?;
    linked
        .view()
        .evaluate_at(&attempt, authorization.authorization_timestamp())
        .map_err(RequestRejection::Trust)?;

    // 4. Signature: under the half the view admitted — the pointer's
    // own, or, inside its 24-hour window, the establishing rotation's
    // previous half. The view has already admitted the pairing, so one
    // of the two must hold; the fallback is the pairing class.
    let Some(half) = admitted_half(linked, authorization) else {
        return Err(RequestRejection::Trust(AttemptRejection::KeyEpochMismatch));
    };
    let signature = Signature::from_bytes(*authorization.signature().as_raw());
    if !ed25519::verify(half.as_raw(), &authorization.signing_input(), &signature) {
        return Err(RequestRejection::InvalidSignature);
    }

    // 5. Scope: the presenter's own linked scope must grant the harness
    // the attempt carries and the one operation the pinned route names.
    if !linked.scopes().contains_harness(&presented.harness)
        || !linked.scopes().contains_operation(ScopeOperation::Ingest)
    {
        return Err(RequestRejection::ScopeNotGranted);
    }

    // 6. Origin delegation: a relay attempt must carry a grant the
    // conjunction admits; the anchor is then the origin, never the
    // relay. A direct attempt anchors at itself.
    let anchor = if presented.origin_client_id == presented.uploader_client_id {
        presented.uploader_client_id.clone()
    } else {
        let grant = delegation.ok_or(RequestRejection::DelegationMissing)?;
        let relay_attempt = RelayAttempt {
            tenant_id: presented.tenant_id.clone(),
            relay_client_id: presented.uploader_client_id.clone(),
            origin_client_id: presented.origin_client_id.clone(),
            harness: presented.harness.clone(),
            operation: ScopeOperation::Ingest,
        };
        grant
            .authorize(&relay_attempt, linked.scopes())
            .map_err(RequestRejection::DelegationRefused)?
            .clone()
    };
    Ok(AuthorizedAttempt {
        uploader_client_id: presented.uploader_client_id.clone(),
        anchor_client_id: anchor,
        key_id: *authorization.uploader_key_id(),
        authorization_epoch: authorization.authorization_epoch(),
    })
}

/// The public half the view's own decision admitted for this attempt:
/// the evidence's half when the attempt presents the pointer's key, or
/// the establishing rotation's previous half inside its window. The view
/// has admitted the attempt already, so `None` is the pairing class by
/// construction.
fn admitted_half<'a>(
    linked: &'a LinkedUploader,
    authorization: &AttemptAuthorization,
) -> Option<&'a Ed25519PublicKey> {
    let view = linked.view();
    if authorization.uploader_key_id() == view.pointer().key_id() {
        return Some(linked.public_key());
    }
    let (_, rotation) = view.rotations().find(|(epoch, record)| {
        *epoch == view.pointer().epoch()
            && record.window_covers(authorization.authorization_timestamp())
            && record.previous_key_id() == authorization.uploader_key_id()
    })?;
    Some(rotation.previous_public_key())
}

/// Parse a 64-hex digest member into one of the vocabulary digest
/// newtypes.
fn digest_member<T>(object: &Object, name: &str) -> Result<T, RequestRejection>
where
    T: std::str::FromStr<Err = GrammarError>,
{
    T::from_str(text_member(object, name).ok_or(RequestRejection::MalformedAuthorization)?)
        .map_err(|_| RequestRejection::MalformedAuthorization)
}

fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}

fn int_member(object: &Object, name: &str) -> Option<i64> {
    match object.get(name) {
        Some(Value::Int(value)) => Some(*value),
        _ => None,
    }
}

/// The whole seconds of a calendar-valid timestamp, floored: sub-second
/// fractions never move a freshness bound by more than the fraction
/// itself. The leap second `:60` counts as the sixtieth second, keeping
/// the rendering monotone.
fn epoch_seconds(timestamp: &Timestamp) -> i64 {
    let bytes = timestamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, byte| acc * 10 + i64::from(byte - b'0'))
    };
    let year = number(&bytes[..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_offset = if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * (month + month_offset) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{DelegationScopes, DelegationState, publish_delegation};
    use crate::revocation::{
        LinkedClientPointer, RevocationRecord, RotationRecord, publish_revocation, publish_rotation,
    };

    /// The tenant, clients, and harness the fixtures pin — synthetic
    /// identifiers, stable across this module's vectors.
    const TENANT: &str = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30";
    const OTHER_TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const CLIENT: &str = "c7d8e9f0-1a2b-4c3d-9e4f-5a6b7c8d9e0f";
    const ORIGIN: &str = "d1e2f3a4-5b6c-4d7e-8f9a-0b1c2d3e4f5a";
    const HARNESS: &str = "claude-code";
    const OTHER_HARNESS: &str = "other-harness";

    /// The authority's and the client keys' seeds, fixed by test vector
    /// so every record is reproducible.
    const AUTHORITY_SEED: [u8; 32] = [7; 32];
    const KEY1_SEED: [u8; 32] = [11; 32];
    const KEY2_SEED: [u8; 32] = [12; 32];
    const IMPOSTOR_SEED: [u8; 32] = [21; 32];

    /// Fixture instants: the link, the delegation, the rotation, the
    /// attempt's own authorization instant, and the verifier clocks at
    /// each freshness bound. The bounds are exact — window plus skew is
    /// 600 seconds, the forward skew edge 300 — so each test names the
    /// instant one second inside or outside the boundary it pins.
    const LINK_INSTANT: &str = "2026-09-13T00:00:00Z";
    const DELEGATE_INSTANT: &str = "2026-09-13T06:00:00Z";
    const ROTATE_INSTANT: &str = "2026-09-13T08:00:00Z";
    const REVOKE_INSTANT: &str = "2026-09-13T02:00:00Z";
    const AUTH_INSTANT: &str = "2026-09-13T12:00:00Z";
    const NOW_FRESH: &str = "2026-09-13T12:01:00Z";
    const NOW_WINDOW_EDGE: &str = "2026-09-13T12:10:00Z";
    const NOW_PAST_WINDOW: &str = "2026-09-13T12:10:01Z";
    const NOW_SKEW_EDGE: &str = "2026-09-13T11:55:00Z";
    const NOW_PAST_SKEW: &str = "2026-09-13T11:54:59Z";

    /// The four covered digests, one distinct pattern per member so a
    /// swap is visible in the rejection class.
    const REQUEST_DIGEST: [u8; 32] = [0xa1; 32];
    const ENVELOPE_DIGEST: [u8; 32] = [0xb2; 32];
    const CANONICAL_DIGEST: [u8; 32] = [0xc3; 32];
    const TRANSPORT_DIGEST: [u8; 32] = [0xd4; 32];
    const OTHER_DIGEST: [u8; 32] = [0xe5; 32];

    const BOUNDARY_TYPE: &str = "multipart/related; boundary=archivist-conformance-01";

    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("pinned tenant uuid")
    }

    fn client() -> ClientId {
        ClientId::parse(CLIENT).expect("pinned client uuid")
    }

    fn origin_client() -> ClientId {
        ClientId::parse(ORIGIN).expect("pinned origin uuid")
    }

    fn harness() -> HarnessId {
        HarnessId::parse(HARNESS).expect("pinned harness")
    }

    fn instant(at: &str) -> Timestamp {
        Timestamp::parse(at).expect("pinned test instant")
    }

    fn public_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    fn key_id(seed: &[u8; 32]) -> KeyId {
        KeyId::from_public_key(&public_half(seed))
    }

    fn root_for(tenant: TenantId) -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant, public_half(&AUTHORITY_SEED))
    }

    fn scopes() -> LinkedClientScopes {
        LinkedClientScopes::new(vec![harness()], vec![ScopeOperation::Ingest])
            .expect("granted scope")
    }

    /// Sign `members` with `seed` under the control-record-v1
    /// construction: canonical bytes without the signature, then the
    /// signature appended.
    fn signed(seed: &[u8; 32], mut members: Object) -> Vec<u8> {
        let signature = ed25519::sign(seed, &Value::Object(members.clone()).canonical_bytes());
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// The linked-client record linking `who` at `epoch` with the half
    /// `key_seed` derives, signed by the authority.
    fn linked_client_for(
        tenant_text: &str,
        who: &str,
        epoch: u64,
        key_seed: &[u8; 32],
        signed_at: &str,
    ) -> Vec<u8> {
        let half = public_half(key_seed);
        let mut members = Object::new();
        members.set("schema", text("archivist.control/v1"));
        members.set("record_type", text("linked-client"));
        members.set("record_kind", text("current-pointer"));
        members.set("tenant_id", text(tenant_text));
        members.set("client_id", text(who));
        members.set("key_id", text(&KeyId::from_public_key(&half).to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&half.to_hex()));
        let mut scope_members = Object::new();
        scope_members.set("harnesses", Value::Array(vec![text(HARNESS)]));
        scope_members.set("operations", Value::Array(vec![text("ingest")]));
        members.set("scopes", Value::Object(scope_members));
        members.set("authorization_epoch", Value::Int(epoch.cast_signed()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&key_id(&AUTHORITY_SEED).to_hex()));
        signed(&AUTHORITY_SEED, members)
    }

    /// Verify a fixture linked-client record into its pointer.
    fn verified_pointer_for(
        tenant: &TenantId,
        who: &str,
        epoch: u64,
        key_seed: &[u8; 32],
        signed_at: &str,
    ) -> LinkedClientPointer {
        let root = root_for(tenant.clone());
        LinkedClientPointer::verify(
            &root,
            &linked_client_for(tenant.as_str(), who, epoch, key_seed, signed_at),
            |_| None,
            &ClientId::parse(who).expect("fixture client uuid"),
        )
        .expect("the fixture pointer verifies")
    }

    /// The uploader evidence for a fixture pointer at `epoch`.
    fn uploader_for(
        tenant: &TenantId,
        who: &str,
        epoch: u64,
        key_seed: &[u8; 32],
        signed_at: &str,
    ) -> LinkedUploader {
        let pointer = verified_pointer_for(tenant, who, epoch, key_seed, signed_at);
        LinkedUploader::new(
            &root_for(tenant.clone()),
            ClientTrustView::new(pointer),
            public_half(key_seed),
            scopes(),
        )
        .expect("the fixture evidence is consistent")
    }

    /// What the uploader presents for a direct upload: the pinned
    /// tenant, the fixture client as both uploader and origin, and the
    /// four covered digests.
    fn presented() -> PresentedRequest {
        PresentedRequest {
            tenant_id: tenant(),
            uploader_client_id: client(),
            origin_client_id: client(),
            harness: harness(),
            request_content_digest: RequestContentDigest::from_raw(REQUEST_DIGEST),
            envelope_digest: EnvelopeDigest::from_raw(ENVELOPE_DIGEST),
            payload_canonical_digest: PayloadCanonicalDigest::from_raw(CANONICAL_DIGEST),
            payload_transport_digest: PayloadTransportDigest::from_raw(TRANSPORT_DIGEST),
        }
    }

    fn presented_for(origin: ClientId) -> PresentedRequest {
        let mut presented = presented();
        presented.origin_client_id = origin;
        presented
    }

    /// The attempt record's fields before signing — everything the
    /// preimage covers except the signature itself.
    struct AttemptFixture {
        epoch: u64,
        at: &'static str,
        key: KeyId,
        request: [u8; 32],
        envelope: [u8; 32],
        canonical: [u8; 32],
        transport: [u8; 32],
    }

    impl Default for AttemptFixture {
        fn default() -> Self {
            Self {
                epoch: 1,
                at: AUTH_INSTANT,
                key: key_id(&KEY1_SEED),
                request: REQUEST_DIGEST,
                envelope: ENVELOPE_DIGEST,
                canonical: CANONICAL_DIGEST,
                transport: TRANSPORT_DIGEST,
            }
        }
    }

    fn attempt_members(fixture: &AttemptFixture) -> Object {
        let mut members = Object::new();
        members.set("http_method", text(HTTP_METHOD));
        members.set("route", text(ROUTE));
        members.set("content_type", text(BOUNDARY_TYPE));
        members.set(
            "request_content_digest",
            text(&RequestContentDigest::from_raw(fixture.request).to_hex()),
        );
        members.set(
            "envelope_digest",
            text(&EnvelopeDigest::from_raw(fixture.envelope).to_hex()),
        );
        members.set(
            "payload_canonical_digest",
            text(&PayloadCanonicalDigest::from_raw(fixture.canonical).to_hex()),
        );
        members.set(
            "payload_transport_digest",
            text(&PayloadTransportDigest::from_raw(fixture.transport).to_hex()),
        );
        members.set("uploader_key_id", text(&fixture.key.to_hex()));
        members.set(
            "authorization_epoch",
            Value::Int(fixture.epoch.cast_signed()),
        );
        members.set("authorization_timestamp", text(fixture.at));
        members.set("signature_algorithm", text("ed25519"));
        members
    }

    /// Sign the fixture attempt with `seed`: the preimage is framed by
    /// the protocol derivation directly, the signature appended, and
    /// the whole record parsed back — so every positive test exercises
    /// the parse-and-frame path end to end.
    fn signed_attempt(seed: &[u8; 32], fixture: &AttemptFixture) -> AttemptAuthorization {
        let mut members = attempt_members(fixture);
        let input = derivation::ingest_attempt_signing_input(
            HTTP_METHOD,
            ROUTE,
            BOUNDARY_TYPE,
            &RequestContentDigest::from_raw(fixture.request),
            &EnvelopeDigest::from_raw(fixture.envelope),
            &BlobDigest::from_raw(fixture.canonical),
            &IncomingChecksum::from_raw(fixture.transport),
            &fixture.key,
            fixture.epoch,
            &instant(fixture.at),
        );
        let signature = ed25519::sign(seed, &input);
        members.set(
            "signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        AttemptAuthorization::parse(&Value::Object(members)).expect("the fixture attempt parses")
    }

    fn good_attempt() -> AttemptAuthorization {
        signed_attempt(&KEY1_SEED, &AttemptFixture::default())
    }

    /// The decision under test, at a named verifier clock.
    fn decide(
        authorization: &AttemptAuthorization,
        presented: &PresentedRequest,
        linked: Option<&LinkedUploader>,
        delegation: Option<&DelegationRecord>,
        now: &str,
    ) -> Result<AuthorizedAttempt, RequestRejection> {
        verify_request(authorization, presented, linked, delegation, &instant(now))
    }

    /// An active delegation of the fixture origin to the fixture
    /// uploader, signed by the fixture authority.
    fn delegation_fixture(state: DelegationState) -> DelegationRecord {
        let relay_scopes = DelegationScopes::new(vec![harness()], vec![ScopeOperation::Ingest])
            .expect("the fixture delegation scope builds");
        let publication = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            &origin_client(),
            state,
            &relay_scopes,
            1,
            None,
            &instant(DELEGATE_INSTANT),
        )
        .expect("the fixture delegation publishes");
        DelegationRecord::verify(
            &root_for(tenant()),
            publication.envelope(),
            |_| None,
            &client(),
            &origin_client(),
        )
        .expect("the fixture delegation verifies")
    }

    #[test]
    fn parse_pins_the_closed_attempt_record() {
        let authorization = good_attempt();
        assert_eq!(authorization.content_type().as_str(), BOUNDARY_TYPE);
        assert_eq!(authorization.uploader_key_id(), &key_id(&KEY1_SEED));
        assert_eq!(authorization.authorization_epoch(), 1);
        assert_eq!(
            authorization.authorization_timestamp(),
            &instant(AUTH_INSTANT)
        );
        assert_eq!(
            AttemptAuthorization::parse(&Value::Bool(true)).unwrap_err(),
            RequestRejection::MalformedAuthorization
        );

        // Every shape refusal is the same malformed class: an extra or
        // absent member, a pinned constant that does not hold, a
        // grammar or calendar failure, a zero or negative epoch.
        let violation = |edit: &dyn Fn(&mut Object)| {
            let mut members = attempt_members(&AttemptFixture::default());
            edit(&mut members);
            members.set(
                "signature",
                text(&Ed25519Signature::from_raw([0; 64]).to_hex()),
            );
            AttemptAuthorization::parse(&Value::Object(members)).unwrap_err()
        };
        let malformed = RequestRejection::MalformedAuthorization;
        assert_eq!(violation(&|m| m.set("extra", Value::Int(1))), malformed);
        assert_eq!(violation(&|m| m.set("http_method", Value::Null)), malformed);
        assert_eq!(violation(&|m| m.set("http_method", text("GET"))), malformed);
        assert_eq!(
            violation(&|m| m.set("route", text("/v2/ingest"))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("signature_algorithm", text("rsa"))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("content_type", text("text/plain"))),
            malformed
        );
        assert_eq!(
            violation(&|m| {
                m.set("request_content_digest", text(&"zz".repeat(32)));
            }),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("authorization_epoch", Value::Int(0))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("authorization_epoch", Value::Int(-1))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("authorization_timestamp", text("2026-02-30T12:00:00Z"))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("authorization_timestamp", text("not a time"))),
            malformed
        );
        assert_eq!(
            violation(&|m| m.set("uploader_key_id", text(&"ab".repeat(31)))),
            malformed
        );
        // The signature member itself: a grammar failure, and its
        // absence — the one member the shared builder above always
        // appends last, so both shapes get their own record.
        let unsigned = {
            let mut members = attempt_members(&AttemptFixture::default());
            members.set("signature", text(&"zz".repeat(128)));
            members
        };
        assert_eq!(
            AttemptAuthorization::parse(&Value::Object(unsigned)).unwrap_err(),
            malformed
        );
        let missing = attempt_members(&AttemptFixture::default());
        assert_eq!(
            AttemptAuthorization::parse(&Value::Object(missing)).unwrap_err(),
            malformed
        );
    }

    #[test]
    fn direct_upload_authorizes_and_anchors_itself() {
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let authorized = decide(
            &good_attempt(),
            &presented(),
            Some(&uploader),
            None,
            NOW_FRESH,
        )
        .expect("a fresh, signed, linked direct attempt authorizes");
        assert_eq!(authorized.uploader_client_id(), &client());
        assert_eq!(authorized.anchor_client_id(), &client());
        assert_eq!(authorized.key_id(), &key_id(&KEY1_SEED));
        assert_eq!(authorized.authorization_epoch(), 1);
    }

    #[test]
    fn digest_disagreement_decides_first() {
        let mut altered = presented();
        altered.payload_transport_digest = PayloadTransportDigest::from_raw(OTHER_DIGEST);
        // No linked evidence and a clock far past the window: the digest
        // decision is still the one that fires, in contract order.
        assert_eq!(
            decide(&good_attempt(), &altered, None, None, NOW_PAST_WINDOW),
            Err(RequestRejection::AlteredRequest)
        );
    }

    #[test]
    fn freshness_bounds_are_window_plus_skew_on_each_edge() {
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let authorization = good_attempt();
        let presented = presented();
        // Exactly window + skew behind the timestamp: accepted.
        assert!(
            decide(
                &authorization,
                &presented,
                Some(&uploader),
                None,
                NOW_WINDOW_EDGE
            )
            .is_ok()
        );
        // One second past it: expired.
        assert_eq!(
            decide(
                &authorization,
                &presented,
                Some(&uploader),
                None,
                NOW_PAST_WINDOW
            ),
            Err(RequestRejection::ExpiredAuthorization)
        );
        // Exactly the skew allowance ahead of the timestamp: accepted.
        assert!(
            decide(
                &authorization,
                &presented,
                Some(&uploader),
                None,
                NOW_SKEW_EDGE
            )
            .is_ok()
        );
        // One second further ahead: premature.
        assert_eq!(
            decide(
                &authorization,
                &presented,
                Some(&uploader),
                None,
                NOW_PAST_SKEW
            ),
            Err(RequestRejection::PrematureAuthorization)
        );
    }

    #[test]
    fn unlinked_uploader_refuses() {
        assert_eq!(
            decide(&good_attempt(), &presented(), None, None, NOW_FRESH),
            Err(RequestRejection::UnlinkedUploader)
        );
    }

    #[test]
    fn cross_tenant_linkage_refuses() {
        let other_tenant = TenantId::parse(OTHER_TENANT).expect("pinned tenant uuid");
        let uploader = uploader_for(&other_tenant, CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        assert_eq!(
            decide(
                &good_attempt(),
                &presented(),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::CrossTenant)
        );
    }

    #[test]
    fn revoked_key_refuses() {
        let pointer = verified_pointer_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let publication = publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            1,
            &key_id(&KEY1_SEED),
            &pointer,
            &instant(REVOKE_INSTANT),
        )
        .expect("the fixture revocation publishes");
        let record = RevocationRecord::verify(
            &root_for(tenant()),
            publication.envelope(),
            |_| None,
            &client(),
            1,
        )
        .expect("the fixture revocation verifies");
        let mut view = ClientTrustView::new(pointer);
        view.record_revocation(&record)
            .expect("the fixture revocation folds");
        let uploader =
            LinkedUploader::new(&root_for(tenant()), view, public_half(&KEY1_SEED), scopes())
                .expect("the fixture evidence is consistent");
        assert_eq!(
            decide(
                &good_attempt(),
                &presented(),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::Trust(AttemptRejection::Revoked))
        );
    }

    #[test]
    fn stale_epoch_refuses() {
        // The pointer has moved to epoch 2; the attempt still presents
        // epoch 1. Staleness is decided before any rotation window is
        // consulted.
        let uploader = uploader_for(&tenant(), CLIENT, 2, &KEY2_SEED, LINK_INSTANT);
        let fixture = AttemptFixture {
            epoch: 1,
            key: key_id(&KEY1_SEED),
            ..AttemptFixture::default()
        };
        let authorization = signed_attempt(&KEY1_SEED, &fixture);
        assert_eq!(
            decide(
                &authorization,
                &presented(),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::Trust(AttemptRejection::StaleEpoch))
        );
    }

    #[test]
    fn rotation_overlap_admits_the_previous_half() {
        // The pointer stands at epoch 2; the establishing rotation's
        // window still covers the attempt instant, so the attempt may
        // sign with the previous half at the current epoch.
        let pointer = verified_pointer_for(&tenant(), CLIENT, 2, &KEY2_SEED, ROTATE_INSTANT);
        let publication = publish_rotation(
            &AUTHORITY_SEED,
            &tenant(),
            &client(),
            &public_half(&KEY1_SEED),
            &public_half(&KEY2_SEED),
            &pointer,
            &instant(ROTATE_INSTANT),
        )
        .expect("the fixture rotation publishes");
        let record = RotationRecord::verify(
            &root_for(tenant()),
            publication.envelope(),
            |_| None,
            &client(),
            2,
        )
        .expect("the fixture rotation verifies");
        let mut view = ClientTrustView::new(pointer);
        view.record_rotation(&record)
            .expect("the fixture rotation folds");
        let uploader =
            LinkedUploader::new(&root_for(tenant()), view, public_half(&KEY2_SEED), scopes())
                .expect("the fixture evidence is consistent");
        let fixture = AttemptFixture {
            epoch: 2,
            key: key_id(&KEY1_SEED),
            ..AttemptFixture::default()
        };
        let authorization = signed_attempt(&KEY1_SEED, &fixture);
        let authorized = decide(
            &authorization,
            &presented(),
            Some(&uploader),
            None,
            NOW_FRESH,
        )
        .expect("the previous half admits inside the overlap window");
        assert_eq!(authorized.key_id(), &key_id(&KEY1_SEED));
        assert_eq!(authorized.authorization_epoch(), 2);
    }

    #[test]
    fn invalid_signature_refuses() {
        // The record presents the linked key's ID but the signature is
        // the impostor's: linkage admits the attempt, the signature
        // refuses it.
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let authorization = signed_attempt(&IMPOSTOR_SEED, &AttemptFixture::default());
        assert_eq!(
            decide(
                &authorization,
                &presented(),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::InvalidSignature)
        );
    }

    #[test]
    fn scope_outside_the_presenters_own_grant_refuses() {
        let other_scopes = LinkedClientScopes::new(
            vec![HarnessId::parse(OTHER_HARNESS).expect("pinned harness")],
            vec![ScopeOperation::Ingest],
        )
        .expect("the other scope builds");
        let pointer = verified_pointer_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let uploader = LinkedUploader::new(
            &root_for(tenant()),
            ClientTrustView::new(pointer),
            public_half(&KEY1_SEED),
            other_scopes,
        )
        .expect("the fixture evidence is consistent");
        assert_eq!(
            decide(
                &good_attempt(),
                &presented(),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::ScopeNotGranted)
        );
    }

    #[test]
    fn relay_without_delegation_refuses() {
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        assert_eq!(
            decide(
                &good_attempt(),
                &presented_for(origin_client()),
                Some(&uploader),
                None,
                NOW_FRESH
            ),
            Err(RequestRejection::DelegationMissing)
        );
    }

    #[test]
    fn relay_with_active_delegation_anchors_the_origin() {
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let grant = delegation_fixture(DelegationState::Active);
        let authorized = decide(
            &good_attempt(),
            &presented_for(origin_client()),
            Some(&uploader),
            Some(&grant),
            NOW_FRESH,
        )
        .expect("a relay attempt under an active grant authorizes");
        assert_eq!(authorized.uploader_client_id(), &client());
        assert_eq!(authorized.anchor_client_id(), &origin_client());
    }

    #[test]
    fn relay_with_withdrawn_delegation_refuses() {
        let uploader = uploader_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        let grant = delegation_fixture(DelegationState::Withdrawn);
        assert_eq!(
            decide(
                &good_attempt(),
                &presented_for(origin_client()),
                Some(&uploader),
                Some(&grant),
                NOW_FRESH
            ),
            Err(RequestRejection::DelegationRefused(
                crate::delegation::DelegationRejection::Withdrawn
            ))
        );
    }

    #[test]
    fn evidence_refuses_an_inconsistent_half() {
        let pointer = verified_pointer_for(&tenant(), CLIENT, 1, &KEY1_SEED, LINK_INSTANT);
        assert!(
            LinkedUploader::new(
                &root_for(tenant()),
                ClientTrustView::new(pointer),
                public_half(&KEY2_SEED),
                scopes(),
            )
            .is_none(),
            "a half that does not derive the pointer's key ID is not evidence"
        );
    }

    #[test]
    fn rejection_classes_stay_content_free() {
        assert_eq!(
            RequestRejection::AlteredRequest.class_text(),
            "altered-request"
        );
        assert_eq!(
            RequestRejection::DelegationRefused(crate::delegation::DelegationRejection::Withdrawn)
                .class_text(),
            "delegation-refused"
        );
        assert_eq!(
            RequestRejection::Trust(AttemptRejection::Revoked).trust_rejection(),
            Some(AttemptRejection::Revoked)
        );
        assert_eq!(RequestRejection::CrossTenant.trust_rejection(), None);
        assert_eq!(
            RequestRejection::MalformedAuthorization.delegation_rejection(),
            None
        );
    }
}
