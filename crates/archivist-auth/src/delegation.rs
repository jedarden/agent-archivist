// SPDX-License-Identifier: Apache-2.0

//! The delegation record: the tenant-authority-signed relay grant, and
//! the four-dimension decision an ingestion replica renders from it
//! (plan Section 5; Phase 3: "Implement origin/uploader delegation for
//! approved relays"; ID-005).
//!
//! A relay is a linked client presenting another client's frozen
//! occurrences. The plan's rule is a conjunction, never a union: "relay
//! authority is the conjunction of tenant, origin, harness, and
//! operation scopes". The record
//! (`schemas/v1/control-delegation.json`) is what makes that true by
//! construction: it names one origin, carries explicit harness and
//! operation allowlists, lives under exactly one tenant's control
//! prefix, and is the only current object for its `(relay, origin)`
//! pair at
//! `tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json` —
//! so there is no set of grants a reader could union over, and no
//! dimension another grant could satisfy. Self-delegation is not a
//! record shape: the origin's own linked-client grants already cover
//! self-upload, so a grant naming the same client on both sides is
//! refused at publication and at verification alike.
//!
//! Four surfaces cover the replica's and the authority's sides:
//!
//! - [`DelegationRecord::verify`] is the evidence gate. It runs the
//!   family's closed member set and every VAL-002 cross-field check —
//!   the record must agree with the address it was served at (both
//!   client segments, order-sensitively), the tenant with the pinned
//!   root, and the two clients with each other — then the signature,
//!   through [`crate::authority::verify_control_record`]'s
//!   fetch-verify-adopt chain walk from the pinned root. Unverified
//!   bytes never become a [`DelegationRecord`], so every downstream
//!   decision is over authenticated evidence by construction.
//! - [`DelegationRecord::authorize`] is the conjunction decision: the
//!   attempt's tenant, relay, origin, harness, and operation against
//!   the verified record and the relay's own allowlists, rejected as
//!   [`CrossTenant`](DelegationRejection::CrossTenant),
//!   [`RelayMismatch`](DelegationRejection::RelayMismatch),
//!   [`OriginMismatch`](DelegationRejection::OriginMismatch),
//!   [`Withdrawn`](DelegationRejection::Withdrawn),
//!   [`HarnessNotGranted`](DelegationRejection::HarnessNotGranted), or
//!   [`OperationNotGranted`](DelegationRejection::OperationNotGranted)
//!   — every failure closed, none retried at a weaker class. The
//!   harness and operation dimensions intersect with the relay's own
//!   linked-client allowlists, which the caller supplies from the
//!   relay's verified record: neither allowlist is ever added to the
//!   other.
//! - [`publish_delegation`] is the authority's write surface: grant,
//!   revise, narrow, or withdraw, always as the next strictly
//!   higher-epoch record at the same key. Withdrawal is the one
//!   representation the current-pointer shape permits — the store has
//!   no delete — and its scopes are inert: a withdrawn record grants
//!   nothing whatever it names.
//! - [`delegation_object_key`] is the address both sides derive, the
//!   layout `schemas/v1/control-delegation.json`'s `objectKey` pattern
//!   pins.
//!
//! # Origin provenance
//!
//! The decision returns the origin, not a verdict: an authorized relay
//! attempt may present [`DelegationRecord::origin_client_id`] and
//! nothing else, so the caller's next step — the occurrence and
//! attestation it writes — is anchored to the origin the authority
//! named, and a relay can never silently replace origin identity with
//! its own (ID-005; SID-006). The storage family records the same
//! relation durably (`archivist-storage`'s relay attestation
//! relation), and the decision here is its precondition.
//!
//! # Composition with the relay's own standing
//!
//! The grant is one gate of two. The relay's own linked-client
//! standing — current epoch, live key, no revocation — is the
//! revocation family's decision
//! ([`crate::revocation::ClientTrustView::evaluate`]), and it stays
//! independent: "revoking or rotating the relay does not touch this
//! object, and a revoked relay fails closed through its own pointer
//! and revocation record regardless of how active its grants are"
//! (`schemas/v1/control-delegation.json`). The module's tests prove
//! the composition: a relay whose own view rejects is refused even
//! when this module's decision alone would accept, and neither gate's
//! acceptance reaches the wire without the other's.
//!
//! Propagation of a revision or withdrawal is bounded by the reader's
//! 60-second trust-record cache (plan Section 5; EC-09) and by nothing
//! in the record — a grant carries no expiry, exactly as the
//! linked-client pointer does not; the epoch is the relation's logical
//! order and `signed_at` its wall-clock context.

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, Ed25519Signature, HarnessId, KeyId, TenantId, Timestamp,
};

use crate::authority::{AuthorityChainError, PinnedAuthorityRoot, verify_control_record};
use crate::ed25519;
use crate::link::ScopeOperation;

/// The control trust namespace every record here is written in.
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// The closed member set of a delegation record
/// (`schemas/v1/control-delegation.json`; `additionalProperties: false`).
const DELEGATION_MEMBERS: [&str; 12] = [
    "schema",
    "record_type",
    "record_kind",
    "tenant_id",
    "relay_client_id",
    "origin_client_id",
    "delegation_state",
    "scopes",
    "authorization_epoch",
    "signed_at",
    "authority_key_id",
    "authority_signature",
];

/// Why delegation evidence or a delegation decision failed: a closed
/// class of failure carrying no echoed material (CFG-027).
///
/// The classes mirror the revocation family's error taxonomy: a
/// malformed record never parsed as its own shape, a disagreement
/// between the record and the address, tenant, or client pair it
/// claims, and an authority that does not verify. Callers match
/// exhaustively; a new failure class has to be added here first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DelegationError {
    /// The envelope is not a delegation record: not JSON, not an
    /// object, a member outside the closed shape, a missing or
    /// non-canonical member, a value failing its grammar, or an instant
    /// that is not a real calendar moment. Nothing about the offending
    /// input is echoed.
    MalformedRecord,
    /// The record parsed but disagrees with its context: a foreign
    /// namespace, record type, or write class, a tenant other than the
    /// pinned root's, clients that equal each other, or a record served
    /// at an address its own members do not name.
    RecordDisagreement,
    /// The authority signature does not verify: the signer does not
    /// resolve through the pinned root's chain, was not established at
    /// the record's instant, or the signature is not the signer's. The
    /// record is not a grant whoever else signed it.
    UntrustedAuthority,
}

impl DelegationError {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRecord => "malformed-record",
            Self::RecordDisagreement => "record-disagreement",
            Self::UntrustedAuthority => "untrusted-authority",
        }
    }
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for DelegationError {}

impl From<AuthorityChainError> for DelegationError {
    fn from(error: AuthorityChainError) -> Self {
        match error {
            AuthorityChainError::RecordDisagreement => Self::RecordDisagreement,
            // Every other chain failure — a signer that does not resolve,
            // a broken link, a signature that is not the signer's, an
            // instant outside the acceptance window — is, to the
            // delegation decision, the same fact: the authority named is
            // not one the pinned root vouches for.
            _ => Self::UntrustedAuthority,
        }
    }
}

/// Whether a delegation record currently grants.
///
/// The closed token set `schemas/v1/control-delegation.json` pins; an
/// unknown token fails closed at parse — a reader never guesses whether
/// a grant it cannot interpret is live.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DelegationState {
    /// The relay may present the origin's occurrences under exactly this
    /// record's scopes.
    Active,
    /// The grant is gone. The store has no delete, so withdrawal is a
    /// strictly higher-epoch record at the same key carrying this
    /// state; its scopes are inert, retained only so the record still
    /// names the shape of the grant it withdraws.
    Withdrawn,
}

impl DelegationState {
    /// Every known token, in schema order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["active", "withdrawn"]
    }

    /// The canonical wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Withdrawn => "withdrawn",
        }
    }

    /// Parse one state token, rejecting anything outside the closed set.
    fn from_token(token: &str) -> Option<Self> {
        match token {
            "active" => Some(Self::Active),
            "withdrawn" => Some(Self::Withdrawn),
            _ => None,
        }
    }
}

/// The harness and operation dimensions of a grant's conjunction
/// (`schemas/v1/control-delegation.json` `scopes`;
/// `additionalProperties: false`).
///
/// The allowlists are the record's own half of the intersection: an
/// authorized attempt's harness must appear here **and** in the relay's
/// own linked-client allowlist, and likewise its operation — the
/// dimensions are intersected, never added to. There is no wildcard
/// token in v1: the harness grammar cannot express one, and the
/// operation set is the closed [`ScopeOperation`] enum, so a new
/// harness or operation is a new epoch of this record, granted as
/// deliberately as the first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationScopes {
    harnesses: Vec<HarnessId>,
    operations: Vec<ScopeOperation>,
}

impl DelegationScopes {
    /// The allowlist bound both scope schemas pin: 1–64 entries, unique.
    const BOUND: usize = 64;

    /// Build a scope, rejecting empty lists, lists past the bound, and
    /// duplicate tokens the way the record schema does. The lists are
    /// stored sorted — the writer discipline that makes equivalent
    /// grants produce identical canonical bytes.
    ///
    /// # Errors
    /// [`DelegationError::MalformedRecord`] when either list is empty,
    /// longer than 64, or contains duplicates — a record that cannot be
    /// granted as written is refused at construction, not at
    /// verification.
    pub fn new(
        mut harnesses: Vec<HarnessId>,
        mut operations: Vec<ScopeOperation>,
    ) -> Result<Self, DelegationError> {
        let within_bounds = |len: usize| (1..=Self::BOUND).contains(&len);
        if !within_bounds(harnesses.len()) || !within_bounds(operations.len()) {
            return Err(DelegationError::MalformedRecord);
        }
        harnesses.sort();
        operations.sort();
        if has_duplicates(&harnesses) || has_duplicates(&operations) {
            return Err(DelegationError::MalformedRecord);
        }
        Ok(Self {
            harnesses,
            operations,
        })
    }

    /// Parse the record's `scopes` member: an object carrying exactly
    /// the `harnesses` and `operations` allowlists, each a non-empty,
    /// duplicate-free array of at most 64 entries — harness tokens under
    /// the common harness grammar, operation tokens inside the closed
    /// [`ScopeOperation`] set. Issued sorted, but a reader accepts any
    /// order: sortedness is writer discipline, not schema syntax, and
    /// rejection must never rest on it.
    fn parse(value: Option<&Value>) -> Result<Self, DelegationError> {
        const MALFORMED: DelegationError = DelegationError::MalformedRecord;
        let Some(Value::Object(scopes)) = value else {
            return Err(MALFORMED);
        };
        if scopes.len() != 2 || !scopes.contains("harnesses") || !scopes.contains("operations") {
            return Err(MALFORMED);
        }
        let harnesses = Self::parse_allowlist(scopes.get("harnesses"), |token| {
            HarnessId::parse(token).ok()
        })?;
        let operations = Self::parse_allowlist(scopes.get("operations"), |token| match token {
            "ingest" => Some(ScopeOperation::Ingest),
            _ => None,
        })?;
        Ok(Self {
            harnesses,
            operations,
        })
    }

    /// Parse one allowlist array: non-empty, within the bound,
    /// duplicate-free, every token resolved by `token_of` — `None` for a
    /// token outside the list's grammar, which fails closed.
    fn parse_allowlist<T: Ord>(
        value: Option<&Value>,
        token_of: impl Fn(&str) -> Option<T>,
    ) -> Result<Vec<T>, DelegationError> {
        let Some(Value::Array(items)) = value else {
            return Err(DelegationError::MalformedRecord);
        };
        if items.is_empty() || items.len() > Self::BOUND {
            return Err(DelegationError::MalformedRecord);
        }
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            let Value::Text(token) = item else {
                return Err(DelegationError::MalformedRecord);
            };
            let Some(value) = token_of(token) else {
                // An unknown token fails closed: a reader never guesses
                // whether a scope it cannot interpret was meant to
                // grant.
                return Err(DelegationError::MalformedRecord);
            };
            parsed.push(value);
        }
        parsed.sort();
        if has_duplicates(&parsed) {
            return Err(DelegationError::MalformedRecord);
        }
        Ok(parsed)
    }

    /// Whether `harness` is inside this record's harness allowlist —
    /// one half of the harness dimension's intersection.
    #[must_use]
    pub fn contains_harness(&self, harness: &HarnessId) -> bool {
        self.harnesses.binary_search(harness).is_ok()
    }

    /// Whether `operation` is inside this record's operation allowlist —
    /// one half of the operation dimension's intersection.
    #[must_use]
    pub fn contains_operation(&self, operation: ScopeOperation) -> bool {
        self.operations.contains(&operation)
    }

    /// The granted harness IDs, sorted ascending.
    pub fn harnesses(&self) -> impl Iterator<Item = &HarnessId> {
        self.harnesses.iter()
    }

    /// The granted operations, ascending by token.
    pub fn operations(&self) -> impl Iterator<Item = ScopeOperation> + '_ {
        self.operations.iter().copied()
    }

    /// The canonical JSON object: sorted `harnesses` and `operations`,
    /// the shape the record schema and the linked-client record share.
    fn to_json(&self) -> Object {
        let mut scopes = Object::new();
        scopes.set(
            "harnesses",
            Value::Array(
                self.harnesses
                    .iter()
                    .map(|harness| Value::Text(harness.as_str().to_owned()))
                    .collect(),
            ),
        );
        scopes.set(
            "operations",
            Value::Array(
                self.operations
                    .iter()
                    .map(|operation| Value::Text(operation.token().to_owned()))
                    .collect(),
            ),
        );
        scopes
    }
}

/// Whether a sorted slice carries the same token twice — the schema's
/// `uniqueItems`, checked as one step after the sort.
fn has_duplicates<T: PartialEq>(sorted: &[T]) -> bool {
    sorted.windows(2).any(|window| window[0] == window[1])
}

/// One verified delegation record: the tenant authority's statement that
/// `relay_client_id` may present `origin_client_id`'s frozen
/// occurrences under the record's own scopes, while `state` says the
/// grant is live.
///
/// Construction is [`DelegationRecord::verify`] and nothing else; the
/// type cannot hold unverified bytes. Every member is an identifier, a
/// state token, an allowlist, a timestamp, or a signature — public
/// material only, and no key material at all, because the record grants
/// a relation between two linked clients, each of whose keys live in
/// their own linked-client records (SEC-006).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationRecord {
    tenant_id: TenantId,
    relay_client_id: ClientId,
    origin_client_id: ClientId,
    state: DelegationState,
    scopes: DelegationScopes,
    epoch: u64,
    signed_at: Timestamp,
}

impl DelegationRecord {
    /// Verify one delegation record served at the pair-addressed key
    /// `tenants/<tenant>/v1/control/delegations/<addressed_relay>/
    /// <addressed_origin>.json`.
    ///
    /// The family checks run before the signature: the closed member
    /// set, the namespace and the `delegation`/`current-pointer`
    /// identity pair, every member grammar, a calendar-valid
    /// `signed_at`, and the VAL-002 cross-field checks — the record's
    /// relay and origin must equal the two address segments
    /// order-sensitively (a swapped key is not the reverse grant), and
    /// the two clients must differ. Only then does the authority
    /// signature verify, through the pinned root's chain walk.
    ///
    /// # Errors
    /// [`DelegationError::MalformedRecord`] for any shape or grammar
    /// failure, [`DelegationError::RecordDisagreement`] for a record
    /// that disagrees with its namespace, class, tenant, clients, or
    /// address, and [`DelegationError::UntrustedAuthority`] when the
    /// signature does not verify against the pinned root.
    pub fn verify(
        root: &PinnedAuthorityRoot,
        envelope: &[u8],
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
        addressed_relay: &ClientId,
        addressed_origin: &ClientId,
    ) -> Result<Self, DelegationError> {
        const MALFORMED: DelegationError = DelegationError::MalformedRecord;
        let Value::Object(object) = json::parse(envelope).map_err(|_| MALFORMED)? else {
            return Err(MALFORMED);
        };
        verify_member_set(&object, &DELEGATION_MEMBERS)?;
        if text_member(&object, "record_type") != Some("delegation")
            || text_member(&object, "record_kind") != Some("current-pointer")
            || text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
        {
            return Err(DelegationError::RecordDisagreement);
        }
        let tenant = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if tenant != *root.tenant_id() {
            // The conjunction's tenant dimension is the prefix the
            // record lives under and the root that vouches for it: a
            // record claiming another tenant is not this tenant's
            // grant, whatever it names and whoever signed it.
            return Err(DelegationError::RecordDisagreement);
        }
        let relay = ClientId::parse(text_member(&object, "relay_client_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        let origin = ClientId::parse(text_member(&object, "origin_client_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if &relay != addressed_relay || &origin != addressed_origin {
            // The two segments are order-sensitive: a record served
            // under one pair's key naming the reverse pair is a torn or
            // forged store, not a naming oddity.
            return Err(DelegationError::RecordDisagreement);
        }
        if relay == origin {
            // Self-delegation is not a grant: the origin's own base
            // grants already cover self-upload, and a self-grant is
            // redundant authority at best.
            return Err(DelegationError::RecordDisagreement);
        }
        let state =
            DelegationState::from_token(text_member(&object, "delegation_state").ok_or(MALFORMED)?)
                .ok_or(MALFORMED)?;
        let scopes = DelegationScopes::parse(object.get("scopes"))?;
        let epoch = epoch_member(&object)?;
        let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
        if !signed_at.calendar_valid() {
            return Err(MALFORMED);
        }
        verify_control_record(root, envelope, fetch)?;
        Ok(Self {
            tenant_id: tenant,
            relay_client_id: relay,
            origin_client_id: origin,
            state,
            scopes,
            epoch,
            signed_at,
        })
    }

    /// The tenant whose authority issued the grant — the conjunction's
    /// tenant dimension.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The linked installation granted relay authority.
    #[must_use]
    pub const fn relay_client_id(&self) -> &ClientId {
        &self.relay_client_id
    }

    /// The linked client on whose behalf the relay may present frozen
    /// occurrences — the conjunction's origin dimension, and the
    /// provenance every occurrence an authorized attempt writes carries.
    #[must_use]
    pub const fn origin_client_id(&self) -> &ClientId {
        &self.origin_client_id
    }

    /// Whether the grant is currently live.
    #[must_use]
    pub const fn state(&self) -> DelegationState {
        self.state
    }

    /// The grant's own scopes — the harness and operation dimensions'
    /// record half.
    #[must_use]
    pub const fn scopes(&self) -> &DelegationScopes {
        &self.scopes
    }

    /// The grant's current epoch — the `(relay, origin)` relation's own
    /// monotonic sequence, not a client's.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The wall-clock instant the authority signed the grant — audit
    /// context only; the grant carries no expiry.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }

    /// Decide one relay attempt: may it present this grant's origin's
    /// occurrences, under the intersection of this record's scopes and
    /// the relay's own?
    ///
    /// `relay_scopes` is the relay's own verified scope — the allowlists
    /// its linked-client record carries, supplied by whatever verified
    /// that record. The harness dimension grants only when the attempt's
    /// harness is in **both** allowlists, and likewise the operation
    /// dimension: intersected, never added to.
    ///
    /// The decision order is the module's contract: tenant, relay,
    /// origin, state, then the two scope dimensions. A withdrawn record
    /// refuses before its scopes are read — they are inert — and a
    /// scope failure is reported per dimension, so a widened attempt is
    /// distinguishable from an unauthorized one in replica metrics
    /// without echoing any identifier.
    ///
    /// # Errors
    /// The matching [`DelegationRejection`] class. `Ok` carries the
    /// origin the authorized attempt may present: the caller's
    /// occurrence and attestation are anchored to it, never to the
    /// relay.
    pub fn authorize(
        &self,
        attempt: &RelayAttempt,
        relay_scopes: &LinkedClientScopes,
    ) -> Result<&ClientId, DelegationRejection> {
        if attempt.tenant_id != self.tenant_id {
            return Err(DelegationRejection::CrossTenant);
        }
        if attempt.relay_client_id != self.relay_client_id {
            return Err(DelegationRejection::RelayMismatch);
        }
        if attempt.origin_client_id != self.origin_client_id {
            return Err(DelegationRejection::OriginMismatch);
        }
        if self.state == DelegationState::Withdrawn {
            return Err(DelegationRejection::Withdrawn);
        }
        if !self.scopes.contains_harness(&attempt.harness)
            || !relay_scopes.contains_harness(&attempt.harness)
        {
            return Err(DelegationRejection::HarnessNotGranted);
        }
        if !self.scopes.contains_operation(attempt.operation)
            || !relay_scopes.contains_operation(attempt.operation)
        {
            return Err(DelegationRejection::OperationNotGranted);
        }
        Ok(&self.origin_client_id)
    }
}

/// One relay attempt as the delegation decision sees it: the tenant the
/// attempt declares, the presenting relay, the origin it claims to
/// present, and the harness and operation it proposes.
///
/// The members are already-validated vocabulary types; every rule the
/// decision applies is relative between the attempt and the verified
/// record, so no constructor invariant exists beyond the types' own
/// grammars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAttempt {
    /// The tenant the attempt declares — the conjunction's tenant
    /// dimension as the wire presents it.
    pub tenant_id: TenantId,
    /// The linked client presenting the attempt (the uploader).
    pub relay_client_id: ClientId,
    /// The origin the attempt claims to present.
    pub origin_client_id: ClientId,
    /// The harness whose session the attempt carries.
    pub harness: HarnessId,
    /// The operation the attempt proposes.
    pub operation: ScopeOperation,
}

/// The relay's own scope — the harness and operation allowlists its
/// linked-client record carries, the second half of both scope
/// dimensions' intersection.
///
/// This is what a caller hands [`DelegationRecord::authorize`] after
/// verifying the relay's record, so the intersection is computed over
/// evidence the relay cannot widen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkedClientScopes {
    harnesses: Vec<HarnessId>,
    operations: Vec<ScopeOperation>,
}

impl LinkedClientScopes {
    /// Build the relay's scope from its verified allowlists. Empty
    /// allowlists are structurally impossible in a linked-client record
    /// and refused here with `None`.
    #[must_use]
    pub fn new(mut harnesses: Vec<HarnessId>, mut operations: Vec<ScopeOperation>) -> Option<Self> {
        if harnesses.is_empty() || operations.is_empty() {
            return None;
        }
        harnesses.sort();
        operations.sort();
        Some(Self {
            harnesses,
            operations,
        })
    }

    /// Whether the relay's own record grants `harness`.
    #[must_use]
    pub fn contains_harness(&self, harness: &HarnessId) -> bool {
        self.harnesses.binary_search(harness).is_ok()
    }

    /// Whether the relay's own record grants `operation`.
    #[must_use]
    pub fn contains_operation(&self, operation: ScopeOperation) -> bool {
        self.operations.contains(&operation)
    }
}

/// Why a relay attempt is refused under this grant: the closed decision
/// classes a replica reports. Every variant is fail-closed — none is
/// retryable against the same evidence, and none carries the offending
/// identifiers (CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DelegationRejection {
    /// The attempt declares a tenant other than the grant's: the grant
    /// is valid nowhere else.
    CrossTenant,
    /// The attempt presents a relay other than the grant's.
    RelayMismatch,
    /// The attempt presents an origin other than the grant's.
    OriginMismatch,
    /// The grant is withdrawn: its scopes are inert whatever they name.
    Withdrawn,
    /// The attempt's harness is outside the intersection of the grant's
    /// and the relay's own harness allowlists: a widened scope, and a
    /// widened scope is no scope.
    HarnessNotGranted,
    /// The attempt's operation is outside the intersection of the
    /// grant's and the relay's own operation allowlists.
    OperationNotGranted,
}

impl DelegationRejection {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::CrossTenant => "cross-tenant",
            Self::RelayMismatch => "relay-mismatch",
            Self::OriginMismatch => "origin-mismatch",
            Self::Withdrawn => "withdrawn",
            Self::HarnessNotGranted => "harness-not-granted",
            Self::OperationNotGranted => "operation-not-granted",
        }
    }
}

impl std::fmt::Display for DelegationRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for DelegationRejection {}

/// Why the offline authority refused to publish a delegation: the
/// closed set of write-time rejections the family pins, mirroring the
/// corpus's classes. A refused publication produced no bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DelegationPublicationError {
    /// A member the authority supplies is outside its grammar: a zero
    /// epoch or a `signed_at` that is not a real calendar instant.
    MalformedInput,
    /// The grant names the same client as relay and origin:
    /// self-delegation is not a record shape.
    SelfDelegation,
    /// The published epoch does not strictly increase over the standing
    /// record's: a revision or withdrawal at or below the current epoch
    /// is a stale write (the corpus's `stale-epoch`).
    StaleEpoch,
}

impl DelegationPublicationError {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed-input",
            Self::SelfDelegation => "self-delegation",
            Self::StaleEpoch => "stale-epoch",
        }
    }
}

impl std::fmt::Display for DelegationPublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for DelegationPublicationError {}

/// A published delegation: the byte-exact canonical envelope and the
/// object key the offline store writes it to, in one value so the two
/// can never drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationPublication {
    envelope: Vec<u8>,
    object_key: String,
}

impl DelegationPublication {
    /// The canonical record bytes. A lost-response retry re-derives
    /// these byte-identically, which is what makes the store's
    /// identical-bytes rule an idempotent repair.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The object key
    /// `tenants/<tenant>/v1/control/delegations/<relay>/<origin>.json`
    /// the envelope is written to (`schemas/v1/control-delegation.json`).
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// Publish one delegation: build the record from validated members,
/// enforce the current-pointer epoch rule against the pair's standing
/// record, sign it with the tenant authority's key, and return the
/// envelope with the object key it is written to.
///
/// Grant, revision, narrowing, and withdrawal are all this one move:
/// the next strictly higher epoch of the same `(relay, origin)` object.
/// `standing_epoch` is the epoch the record at the key carries now —
/// `None` for a pair's first grant — and the published epoch must
/// strictly exceed it; equal or lower is
/// [`DelegationPublicationError::StaleEpoch`], the corpus's
/// `stale-epoch`. Withdrawal is the same call with
/// [`DelegationState::Withdrawn`], carrying the withdrawn grant's
/// scopes inert. The relay's own client epoch is a separate sequence
/// this function never reads: revoking or rotating the relay is the
/// linked-client family's move, and a revoked relay fails closed
/// through its own pointer regardless of how active its grants are.
///
/// The signing seed is the tenant authority's private half and enters
/// only as a borrowed slice, the same discipline every signing surface
/// here holds (SEC-004, SEC-006); the record carries its public
/// derivation only.
///
/// # Errors
/// [`DelegationPublicationError::MalformedInput`] for a zero epoch or a
/// calendar-invalid instant,
/// [`DelegationPublicationError::SelfDelegation`] for a grant naming
/// one client on both sides, and
/// [`DelegationPublicationError::StaleEpoch`] for a non-increasing
/// epoch.
#[allow(clippy::too_many_arguments)] // the arguments are the record schema's own members
pub fn publish_delegation(
    authority_seed: &[u8; 32],
    tenant: &TenantId,
    relay: &ClientId,
    origin: &ClientId,
    state: DelegationState,
    scopes: &DelegationScopes,
    epoch: u64,
    standing_epoch: Option<u64>,
    signed_at: &Timestamp,
) -> Result<DelegationPublication, DelegationPublicationError> {
    if epoch == 0 || !signed_at.calendar_valid() {
        return Err(DelegationPublicationError::MalformedInput);
    }
    if relay == origin {
        return Err(DelegationPublicationError::SelfDelegation);
    }
    if standing_epoch.is_some_and(|standing| epoch <= standing) {
        return Err(DelegationPublicationError::StaleEpoch);
    }
    let authority_public = ed25519::public_key_from_seed(authority_seed);
    let authority_key_id = KeyId::from_public_key(&Ed25519PublicKey::from_raw(authority_public));
    let mut members = Object::new();
    members.set("schema", text(CONTROL_NAMESPACE));
    members.set("record_type", text("delegation"));
    members.set("record_kind", text("current-pointer"));
    members.set("tenant_id", text(tenant.as_str()));
    members.set("relay_client_id", text(relay.as_str()));
    members.set("origin_client_id", text(origin.as_str()));
    members.set("delegation_state", text(state.token()));
    members.set("scopes", Value::Object(scopes.to_json()));
    members.set(
        "authorization_epoch",
        Value::Int(i64::try_from(epoch).map_err(|_| DelegationPublicationError::MalformedInput)?),
    );
    members.set("signed_at", text(signed_at.as_str()));
    members.set("authority_key_id", text(&authority_key_id.to_hex()));
    let signature = ed25519::sign(
        authority_seed,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    let envelope = Value::Object(members).canonical_bytes();
    Ok(DelegationPublication {
        object_key: delegation_object_key(tenant, relay, origin),
        envelope,
    })
}

/// The object key of one delegation record — the current-pointer key
/// one `(relay, origin)` pair occupies, the layout
/// `schemas/v1/control-delegation.json`'s `objectKey` pattern pins.
/// The client segments are order-sensitive: relay first, origin second.
#[must_use]
pub fn delegation_object_key(tenant: &TenantId, relay: &ClientId, origin: &ClientId) -> String {
    format!(
        "tenants/{}/v1/control/delegations/{}/{}.json",
        tenant.as_str(),
        relay.as_str(),
        origin.as_str()
    )
}

/// Reject any member set other than exactly `expected` — the closed
/// shape's `additionalProperties: false`, checked as one step so an
/// extra member is a malformed record and not a smuggled payload.
fn verify_member_set(object: &Object, expected: &[&str]) -> Result<(), DelegationError> {
    if object.len() != expected.len() {
        return Err(DelegationError::MalformedRecord);
    }
    for name in expected {
        if !object.contains(name) {
            return Err(DelegationError::MalformedRecord);
        }
    }
    Ok(())
}

/// Read one text member, failing closed when it is absent or not text.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Read the signed `authorization_epoch`: a positive integer inside the
/// u64 range the 18-digit ceiling bounds.
fn epoch_member(object: &Object) -> Result<u64, DelegationError> {
    match object.get("authorization_epoch") {
        Some(Value::Int(value)) if *value >= 1 => {
            u64::try_from(*value).map_err(|_| DelegationError::MalformedRecord)
        }
        _ => Err(DelegationError::MalformedRecord),
    }
}

/// A canonical text value, for the record builders.
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::revocation::{
        AttemptRejection, AuthorizationAttempt, ClientTrustView, LinkedClientPointer,
        RevocationRecord,
    };

    /// The tenant and client identifiers the committed corpus pins —
    /// synthetic fixture UUIDs, stable across the family's vectors. The
    /// relay is the corpus's control-client-b, the origin its
    /// control-client-a, matching the delegation-lifecycle scenario's
    /// own pair.
    const TENANT: &str = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30";
    const RELAY: &str = "c7d8e9f0-1a2b-4c3d-9e4f-5a6b7c8d9e0f";
    const ORIGIN: &str = "9a4c2f18-6b37-4e59-8d20-1f3a5c7e9b42";
    /// Instants inside the authority chain's acceptance windows: the
    /// records' own `signed_at` values, never the read time.
    const GRANT_INSTANT: &str = "2026-09-13T00:00:00Z";
    const WITHDRAW_INSTANT: &str = "2026-09-13T04:00:00Z";

    /// The authority's and the relay's keys, fixed by test vector so
    /// every record in this module's tests is reproducible. The relay's
    /// seed exists to prove its signatures do not grant.
    const AUTHORITY_SEED: [u8; 32] = [7; 32];
    const RELAY_SEED: [u8; 32] = [21; 32];

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("pinned tenant uuid")
    }

    fn relay() -> ClientId {
        ClientId::parse(RELAY).expect("pinned relay uuid")
    }

    fn origin() -> ClientId {
        ClientId::parse(ORIGIN).expect("pinned origin uuid")
    }

    fn root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant(), public_half(&AUTHORITY_SEED))
    }

    fn public_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    fn key_id(seed: &[u8; 32]) -> KeyId {
        KeyId::from_public_key(&public_half(seed))
    }

    fn instant(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("pinned test instant")
    }

    fn harness(name: &str) -> HarnessId {
        HarnessId::parse(name).expect("fixture harness id")
    }

    /// The grant the corpus's first vector carries: claude-code, ingest.
    fn claude_code_only() -> DelegationScopes {
        DelegationScopes::new(vec![harness("claude-code")], vec![ScopeOperation::Ingest])
            .expect("fixture scopes")
    }

    /// The relay's own linked-client scope: claude-code only, ingest
    /// only — deliberately narrower than some fixtures' grants so the
    /// intersection's relay half is exercisable.
    fn relay_scopes() -> LinkedClientScopes {
        LinkedClientScopes::new(vec![harness("claude-code")], vec![ScopeOperation::Ingest])
            .expect("fixture relay scopes")
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

    /// Publish a grant (or withdrawal) for the fixture pair at `epoch`.
    fn grant_at(
        state: DelegationState,
        scopes: &DelegationScopes,
        epoch: u64,
        standing: Option<u64>,
        signed_at: &str,
    ) -> Vec<u8> {
        publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            state,
            scopes,
            epoch,
            standing,
            &instant(signed_at),
        )
        .expect("fixture grant publishes")
        .envelope()
        .to_vec()
    }

    /// Verify `envelope` at the fixture pair's own address.
    fn verify_fixture(envelope: &[u8]) -> Result<DelegationRecord, DelegationError> {
        DelegationRecord::verify(&root(), envelope, |_| None, &relay(), &origin())
    }

    fn attempt_for(tenant: &TenantId, relay: &ClientId, origin: &ClientId) -> RelayAttempt {
        RelayAttempt {
            tenant_id: tenant.clone(),
            relay_client_id: relay.clone(),
            origin_client_id: origin.clone(),
            harness: harness("claude-code"),
            operation: ScopeOperation::Ingest,
        }
    }

    fn authorized_attempt() -> RelayAttempt {
        attempt_for(&tenant(), &relay(), &origin())
    }

    /// Replace the fixture record's `scopes` member with `f` applied to
    /// a copy of the current one — the test-side widen.
    fn with_scopes(members: &mut Object, f: impl FnOnce(&mut Object)) {
        let mut scopes = match members.get("scopes") {
            Some(Value::Object(scopes)) => scopes.clone(),
            _ => panic!("fixture members carry a scopes object"),
        };
        f(&mut scopes);
        members.set("scopes", Value::Object(scopes));
    }

    /// The twelve delegation members every hand-built fixture starts
    /// from, minus the signature.
    fn base_members(
        state: DelegationState,
        scopes: &DelegationScopes,
        epoch: u64,
        signed_at: &str,
    ) -> Object {
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text("delegation"));
        members.set("record_kind", text("current-pointer"));
        members.set("tenant_id", text(TENANT));
        members.set("relay_client_id", text(RELAY));
        members.set("origin_client_id", text(ORIGIN));
        members.set("delegation_state", text(state.token()));
        members.set("scopes", Value::Object(scopes.to_json()));
        members.set("authorization_epoch", Value::Int(epoch.cast_signed()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&key_id(&AUTHORITY_SEED).to_hex()));
        members
    }

    /// The linked-client pointer the composition fixture builds: the
    /// relay, at epoch 1, holding the half `RELAY_SEED` derives, with
    /// the relay's own narrow scope.
    fn linked_relay_pointer() -> Vec<u8> {
        let half = public_half(&RELAY_SEED);
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text("linked-client"));
        members.set("record_kind", text("current-pointer"));
        members.set("tenant_id", text(TENANT));
        members.set("client_id", text(RELAY));
        members.set("key_id", text(&KeyId::from_public_key(&half).to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&half.to_hex()));
        let mut scopes = Object::new();
        scopes.set("harnesses", Value::Array(vec![text("claude-code")]));
        scopes.set("operations", Value::Array(vec![text("ingest")]));
        members.set("scopes", Value::Object(scopes));
        members.set("authorization_epoch", Value::Int(1));
        members.set("signed_at", text(GRANT_INSTANT));
        members.set("authority_key_id", text(&key_id(&AUTHORITY_SEED).to_hex()));
        signed(&AUTHORITY_SEED, members)
    }

    /// The revocation completing the composition fixture: the relay's
    /// epoch-1 half, dead, with the pointer bumped past it — folded as
    /// two publications, never one.
    fn relay_revocation() -> Vec<u8> {
        let pointer =
            LinkedClientPointer::verify(&root(), &linked_relay_pointer(), |_| None, &relay())
                .expect("the fixture relay pointer verifies");
        crate::revocation::publish_revocation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            1,
            &key_id(&RELAY_SEED),
            &pointer,
            &instant(WITHDRAW_INSTANT),
        )
        .expect("the fixture revocation names the pointer's own half")
        .envelope()
        .to_vec()
    }

    // -----------------------------------------------------------------
    // Verification: the evidence gate
    // -----------------------------------------------------------------

    #[test]
    fn an_authoritative_grant_verifies_at_its_own_pair_key() {
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        let record = verify_fixture(&envelope).expect("the authority's grant verifies");
        assert_eq!(record.tenant_id(), &tenant());
        assert_eq!(record.relay_client_id(), &relay());
        assert_eq!(record.origin_client_id(), &origin());
        assert_eq!(record.state(), DelegationState::Active);
        assert_eq!(record.epoch(), 1);
        assert_eq!(record.signed_at(), &instant(GRANT_INSTANT));
        assert!(record.scopes().contains_harness(&harness("claude-code")));
        assert!(record.scopes().contains_operation(ScopeOperation::Ingest));
    }

    #[test]
    fn a_record_served_at_a_swapped_pair_key_is_not_the_reverse_grant() {
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        // The segments are order-sensitive: serving relay's grant at
        // (origin, relay) — the reverse grant's key — is a disagreement,
        // not a naming oddity.
        let error = DelegationRecord::verify(&root(), &envelope, |_| None, &origin(), &relay())
            .expect_err("a swapped address is a disagreement");
        assert_eq!(error, DelegationError::RecordDisagreement);
    }

    #[test]
    fn a_foreign_tenant_record_is_not_this_tenant_s_grant() {
        let foreign_tenant =
            TenantId::parse("4a6d1c90-8d24-4f67-a1b9-2c7d6e5f4a30").expect("fixture tenant");
        let foreign_root = PinnedAuthorityRoot::new(foreign_tenant, public_half(&AUTHORITY_SEED));
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        // The envelope names the fixture tenant; a verifier pinned to
        // another tenant's root refuses it before the walk.
        let error =
            DelegationRecord::verify(&foreign_root, &envelope, |_| None, &relay(), &origin())
                .expect_err("a foreign tenant's root refuses the record");
        assert_eq!(error, DelegationError::RecordDisagreement);
    }

    #[test]
    fn a_self_delegation_record_is_not_a_shape_the_verifier_accepts() {
        // Hand-built, because publication refuses the shape: relay and
        // origin both the fixture relay.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        members.set("origin_client_id", text(RELAY));
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = DelegationRecord::verify(&root(), &envelope, |_| None, &relay(), &relay())
            .expect_err("self-delegation is refused even authority-signed");
        assert_eq!(error, DelegationError::RecordDisagreement);
    }

    #[test]
    fn a_forged_grant_is_rejected_whose_signature_the_authority_did_not_make() {
        // The same record the relay signed, naming the authority's key.
        // The named authority_key_id is unchanged, so the only evidence
        // is the signature itself — and it is not the signer's.
        let members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        let relay_signed = signed(&RELAY_SEED, members);
        let error =
            verify_fixture(&relay_signed).expect_err("a grant the relay signed is not a grant");
        assert_eq!(error, DelegationError::UntrustedAuthority);
    }

    #[test]
    fn an_unknown_state_token_fails_closed() {
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        members.set("delegation_state", text("paused"));
        let envelope = signed(&AUTHORITY_SEED, members);
        let error =
            verify_fixture(&envelope).expect_err("an unknown state is never guessed into a grant");
        assert_eq!(error, DelegationError::MalformedRecord);
    }

    #[test]
    fn an_extra_member_is_malformed_not_a_smuggled_payload() {
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        members.set("notes", text("widen everything"));
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = verify_fixture(&envelope).expect_err("the closed shape has no notes member");
        assert_eq!(error, DelegationError::MalformedRecord);
    }

    #[test]
    fn scope_shape_violations_fail_closed() {
        // Duplicate harness tokens: uniqueItems is schema syntax, so a
        // duplicate is a shape violation, not a longer allowlist.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        with_scopes(&mut members, |scopes| {
            scopes.set(
                "harnesses",
                Value::Array(vec![text("claude-code"), text("claude-code")]),
            );
        });
        let envelope = signed(&AUTHORITY_SEED, members);
        let error =
            verify_fixture(&envelope).expect_err("a duplicated token is not a second grant");
        assert_eq!(error, DelegationError::MalformedRecord);

        // An operation token outside the closed enum: unknown scopes
        // fail closed.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        with_scopes(&mut members, |scopes| {
            scopes.set(
                "operations",
                Value::Array(vec![text("ingest"), text("delete")]),
            );
        });
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = verify_fixture(&envelope).expect_err("no v1 operation deletes");
        assert_eq!(error, DelegationError::MalformedRecord);

        // An empty harness allowlist: a grant that grants nothing is a
        // withdrawn record, never an active one with empty arrays.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        with_scopes(&mut members, |scopes| {
            scopes.set("harnesses", Value::Array(vec![]));
        });
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = verify_fixture(&envelope).expect_err("empty allowlists are not active grants");
        assert_eq!(error, DelegationError::MalformedRecord);

        // A harness token outside the common grammar: the grammar has
        // no wildcard and no uppercase, so a widened-token grant cannot
        // even be expressed.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        with_scopes(&mut members, |scopes| {
            scopes.set("harnesses", Value::Array(vec![text("*")]));
        });
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = verify_fixture(&envelope).expect_err("the grammar cannot express a wildcard");
        assert_eq!(error, DelegationError::MalformedRecord);
    }

    #[test]
    fn a_zero_epoch_is_malformed_and_a_dead_calendar_instant_too() {
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        members.set("authorization_epoch", Value::Int(0));
        let envelope = signed(&AUTHORITY_SEED, members);
        let error =
            verify_fixture(&envelope).expect_err("epoch zero was never established for any pair");
        assert_eq!(error, DelegationError::MalformedRecord);

        // The grammar alone accepts an impossible date; the semantic
        // check refuses it.
        let mut members = base_members(
            DelegationState::Active,
            &claude_code_only(),
            1,
            GRANT_INSTANT,
        );
        members.set("signed_at", text("2026-02-30T00:00:00Z"));
        let envelope = signed(&AUTHORITY_SEED, members);
        let error = verify_fixture(&envelope).expect_err("February 30 never happened");
        assert_eq!(error, DelegationError::MalformedRecord);
    }

    // -----------------------------------------------------------------
    // Publication: the authority's write surface
    // -----------------------------------------------------------------

    #[test]
    fn publication_refuses_self_delegation_and_impossible_inputs() {
        // Self-delegation.
        let error = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &relay(),
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            &instant(GRANT_INSTANT),
        )
        .expect_err("self-delegation is refused at write time");
        assert_eq!(error, DelegationPublicationError::SelfDelegation);

        // Epoch zero.
        let error = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            DelegationState::Active,
            &claude_code_only(),
            0,
            None,
            &instant(GRANT_INSTANT),
        )
        .expect_err("epoch zero publishes nothing");
        assert_eq!(error, DelegationPublicationError::MalformedInput);

        // A calendar-impossible instant.
        let impossible = Timestamp::parse("2026-02-30T00:00:00Z").expect("the grammar parses");
        let error = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            &impossible,
        )
        .expect_err("a calendar-impossible instant publishes nothing");
        assert_eq!(error, DelegationPublicationError::MalformedInput);
    }

    #[test]
    fn publication_refuses_epochs_that_do_not_strictly_increase() {
        // Equal epoch over a standing record.
        let error = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            DelegationState::Active,
            &claude_code_only(),
            3,
            Some(3),
            &instant(GRANT_INSTANT),
        )
        .expect_err("an equal epoch is a stale write");
        assert_eq!(error, DelegationPublicationError::StaleEpoch);

        // Lower epoch over a standing record.
        let error = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            DelegationState::Active,
            &claude_code_only(),
            1,
            Some(4),
            &instant(GRANT_INSTANT),
        )
        .expect_err("a lower epoch is a stale write");
        assert_eq!(error, DelegationPublicationError::StaleEpoch);
    }

    #[test]
    fn withdrawal_publishes_the_next_epoch_with_inert_scopes() {
        let grant = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            3,
            Some(2),
            GRANT_INSTANT,
        );
        let record = verify_fixture(&grant).expect("the grant verifies");
        assert_eq!(record.state(), DelegationState::Active);

        let withdrawal = grant_at(
            DelegationState::Withdrawn,
            &claude_code_only(),
            4,
            Some(3),
            WITHDRAW_INSTANT,
        );
        let withdrawn = verify_fixture(&withdrawal).expect("the withdrawal verifies");
        assert_eq!(withdrawn.state(), DelegationState::Withdrawn);
        assert_eq!(withdrawn.epoch(), 4);
        // The withdrawal still names the shape of the grant it
        // withdraws — and grants nothing whatever it names.
        assert!(withdrawn.scopes().contains_harness(&harness("claude-code")));
        let rejection = withdrawn
            .authorize(&authorized_attempt(), &relay_scopes())
            .expect_err("a withdrawn record's scopes are inert");
        assert_eq!(rejection, DelegationRejection::Withdrawn);
    }

    #[test]
    fn the_publication_lands_at_the_pair_addressed_key() {
        let publication = publish_delegation(
            &AUTHORITY_SEED,
            &tenant(),
            &relay(),
            &origin(),
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            &instant(GRANT_INSTANT),
        )
        .expect("the fixture grant publishes");
        assert_eq!(
            publication.object_key(),
            delegation_object_key(&tenant(), &relay(), &origin())
        );
        assert_eq!(
            publication.object_key(),
            format!("tenants/{TENANT}/v1/control/delegations/{RELAY}/{ORIGIN}.json")
        );
    }

    // -----------------------------------------------------------------
    // The conjunction decision
    // -----------------------------------------------------------------

    #[test]
    fn an_authorized_relay_presents_the_origin_not_itself() {
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        let record = verify_fixture(&envelope).expect("the grant verifies");
        let presented = record
            .authorize(&authorized_attempt(), &relay_scopes())
            .expect("the fixture attempt is inside every dimension");
        // Provenance: the decision returns the origin the attempt may
        // carry, never the relay.
        assert_eq!(presented, record.origin_client_id());
        assert_ne!(presented, record.relay_client_id());
    }

    #[test]
    fn every_dimension_of_the_conjunction_rejects_alone() {
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        let record = verify_fixture(&envelope).expect("the grant verifies");

        // Cross-tenant: the grant is valid nowhere else.
        let foreign_tenant =
            TenantId::parse("4a6d1c90-8d24-4f67-a1b9-2c7d6e5f4a30").expect("fixture tenant");
        let rejection = record
            .authorize(
                &attempt_for(&foreign_tenant, &relay(), &origin()),
                &relay_scopes(),
            )
            .expect_err("a cross-tenant attempt is refused");
        assert_eq!(rejection, DelegationRejection::CrossTenant);

        // A different relay: the grant is not that client's.
        let other_relay =
            ClientId::parse("0e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30").expect("fixture client");
        let rejection = record
            .authorize(
                &attempt_for(&tenant(), &other_relay, &origin()),
                &relay_scopes(),
            )
            .expect_err("another relay's attempt is refused");
        assert_eq!(rejection, DelegationRejection::RelayMismatch);

        // A different origin: a grant for one origin is nothing for any
        // other.
        let other_origin =
            ClientId::parse("1e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30").expect("fixture client");
        let rejection = record
            .authorize(
                &attempt_for(&tenant(), &relay(), &other_origin),
                &relay_scopes(),
            )
            .expect_err("another origin's attempt is refused");
        assert_eq!(rejection, DelegationRejection::OriginMismatch);
    }

    #[test]
    fn a_widened_scope_is_no_scope_on_either_dimension() {
        // The grant names claude-code and codex; the relay's own record
        // names claude-code only. The intersection is claude-code, never
        // the union.
        let both_harnesses = DelegationScopes::new(
            vec![harness("claude-code"), harness("codex")],
            vec![ScopeOperation::Ingest],
        )
        .expect("fixture scopes");
        let envelope = grant_at(
            DelegationState::Active,
            &both_harnesses,
            2,
            Some(1),
            GRANT_INSTANT,
        );
        let record = verify_fixture(&envelope).expect("the grant verifies");

        // Widened past the relay's own allowlist: the grant names the
        // harness, the relay's record does not, and the union is not
        // the answer.
        let mut widened = authorized_attempt();
        widened.harness = harness("codex");
        let rejection = record
            .authorize(&widened, &relay_scopes())
            .expect_err("the relay's own record narrows the grant");
        assert_eq!(rejection, DelegationRejection::HarnessNotGranted);

        // A narrowed grant: claude-code only, against the relay's
        // two-harness record. The grant narrows the relay.
        let relay_codex = LinkedClientScopes::new(
            vec![harness("claude-code"), harness("codex")],
            vec![ScopeOperation::Ingest],
        )
        .expect("fixture relay scopes");
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            3,
            Some(2),
            GRANT_INSTANT,
        );
        let narrowed_grant = verify_fixture(&envelope).expect("the grant verifies");
        let rejection = narrowed_grant
            .authorize(&widened, &relay_codex)
            .expect_err("the grant narrows the relay's own record");
        assert_eq!(rejection, DelegationRejection::HarnessNotGranted);

        // Inside the intersection on both halves: accepted, origin
        // presented.
        let presented = record
            .authorize(&authorized_attempt(), &relay_scopes())
            .expect("claude-code is inside both allowlists");
        assert_eq!(presented, record.origin_client_id());
    }

    // -----------------------------------------------------------------
    // Composition with the relay's own standing
    // -----------------------------------------------------------------

    #[test]
    fn a_revoked_relay_fails_closed_through_its_own_view_despite_an_active_grant() {
        // The relay's own standing: linked at epoch 1 with its key, then
        // revoked there. The delegation knows none of this — by design.
        let pointer =
            LinkedClientPointer::verify(&root(), &linked_relay_pointer(), |_| None, &relay())
                .expect("the fixture relay pointer verifies");
        let mut view = ClientTrustView::new(pointer);
        let revocation =
            RevocationRecord::verify(&root(), &relay_revocation(), |_| None, &relay(), 1)
                .expect("the fixture revocation verifies");
        view.record_revocation(&revocation)
            .expect("the revocation folds");

        // The grant is active and would accept the attempt alone.
        let envelope = grant_at(
            DelegationState::Active,
            &claude_code_only(),
            1,
            None,
            GRANT_INSTANT,
        );
        let record = verify_fixture(&envelope).expect("the grant verifies");
        record
            .authorize(&authorized_attempt(), &relay_scopes())
            .expect("the delegation gate alone accepts");

        // The relay's own gate refuses, and the composition is the wire
        // answer: no delegation activity resurrects a revoked relay.
        let relay_attempt =
            AuthorizationAttempt::new(relay(), 1, key_id(&RELAY_SEED)).expect("fixture attempt");
        let rejection = view
            .evaluate(&relay_attempt)
            .expect_err("the revoked relay's own view refuses");
        assert_eq!(rejection, AttemptRejection::Revoked);
    }

    // -----------------------------------------------------------------
    // The committed corpus, replayed through this module
    // -----------------------------------------------------------------

    /// The corpus directory, relative to this crate — the same pinned
    /// bytes `control_corpus.rs` replays at the fold level, read here
    /// through the record-level verifier that delegation work actually
    /// ships.
    fn corpus_object(name: &str) -> Object {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../schemas/v1/examples/control/"
        );
        let bytes =
            std::fs::read_to_string(format!("{path}{name}")).expect("committed corpus file");
        match json::parse(bytes.as_bytes()).expect("committed corpus parses") {
            Value::Object(object) => object,
            _ => panic!("{name}: the corpus file is an object"),
        }
    }

    /// The pinned tenant-authority root: the `keys.json` entry whose
    /// role is the tenant authority root, public half only.
    fn corpus_root() -> PinnedAuthorityRoot {
        let keys = corpus_object("keys.json");
        let Some(Value::Array(entries)) = keys.get("keys") else {
            panic!("keys.json holds an array of key entries")
        };
        let entry = entries
            .iter()
            .filter_map(|value| match value {
                Value::Object(object) => Some(object),
                _ => None,
            })
            .find(|object| text_member(object, "role") == Some("tenant-authority-root"))
            .expect("keys.json names one tenant-authority-root");
        let tenant = TenantId::parse(text_member(entry, "tenant_id").expect("root tenant"))
            .expect("corpus tenant parses");
        let public = Ed25519PublicKey::parse(text_member(entry, "public_key").expect("root half"))
            .expect("corpus half parses");
        PinnedAuthorityRoot::new(tenant, public)
    }

    /// Replay the lifecycle's history through the verifier: every
    /// accepted record verifies against the corpus root and carries the
    /// epoch and state its vector pins; the fold's `stale-epoch`
    /// rejection is a write-class rule this module's publication
    /// refuses; the forged record is untrusted exactly once — at the
    /// signature. Returns the accepted records in history order.
    fn replay_corpus_history(root: &PinnedAuthorityRoot) -> Vec<DelegationRecord> {
        let lifecycle = corpus_object("delegation-lifecycle.json");
        let Some(Value::Array(history)) = lifecycle.get("history") else {
            panic!("the lifecycle holds a history array")
        };
        let mut standing: Option<u64> = None;
        let mut verified_records = Vec::new();
        for entry in history {
            let Value::Object(entry) = entry else {
                panic!("corpus history entries are objects")
            };
            let name = text_member(entry, "name").expect("entry name");
            let Some(Value::Object(record)) = entry.get("record") else {
                panic!("{name}: the record is an object")
            };
            let envelope = Value::Object(record.clone()).canonical_bytes();
            match text_member(entry, "expected").expect("pinned expectation") {
                "accepted" => {
                    let verified =
                        DelegationRecord::verify(root, &envelope, |_| None, &relay(), &origin())
                            .unwrap_or_else(|error| {
                                panic!("{name}: the accepted record verifies: {error}")
                            });
                    assert_eq!(
                        verified.epoch(),
                        epoch_member(record).unwrap_or_else(|_| panic!("{name}: pinned epoch")),
                        "{name}: the verified epoch is the record's own"
                    );
                    assert_eq!(
                        verified.state().token(),
                        text_member(record, "delegation_state").expect("pinned state"),
                        "{name}: the verified state is the record's own"
                    );
                    standing = Some(verified.epoch());
                    verified_records.push(verified);
                }
                "rejected" => match text_member(entry, "reason").expect("pinned reason") {
                    // Authentic bytes at a stale epoch: the record
                    // verifies, the write is what the authority refuses.
                    "stale-epoch" => {
                        let epoch = epoch_member(record).expect("stale record's epoch");
                        DelegationRecord::verify(root, &envelope, |_| None, &relay(), &origin())
                            .unwrap_or_else(|error| {
                                panic!("{name}: the stale record still verifies: {error}")
                            });
                        let error = publish_delegation(
                            &AUTHORITY_SEED,
                            &tenant(),
                            &relay(),
                            &origin(),
                            DelegationState::Active,
                            &claude_code_only(),
                            epoch,
                            standing,
                            &instant(GRANT_INSTANT),
                        )
                        .expect_err("{name}: the fold's stale-epoch is the publisher's rule too");
                        assert_eq!(error, DelegationPublicationError::StaleEpoch);
                    }
                    "untrusted-signer" => {
                        let error = DelegationRecord::verify(
                            root,
                            &envelope,
                            |_| None,
                            &relay(),
                            &origin(),
                        )
                        .expect_err("{name}: the forged record is no grant");
                        assert_eq!(error, DelegationError::UntrustedAuthority, "{name}");
                    }
                    other => panic!("{name}: unexpected corpus reason {other}"),
                },
                other => panic!("{name}: unexpected corpus expectation {other}"),
            }
        }
        verified_records
    }

    #[test]
    fn the_committed_corpus_family_replays_through_the_verifier() {
        let root = corpus_root();
        let verified = replay_corpus_history(&root);
        // Grant, revision, withdrawal, regrant — four accepted records
        // at strictly increasing epochs; the stale regrant and the
        // forged grant never landed.
        let epochs: Vec<u64> = verified.iter().map(DelegationRecord::epoch).collect();
        assert_eq!(epochs, vec![1, 2, 3, 4], "the accepted history in order");
        assert_eq!(verified[2].state(), DelegationState::Withdrawn);
        assert_eq!(verified[3].state(), DelegationState::Active);
        assert_eq!(
            verified[3].tenant_id(),
            verified[0].tenant_id(),
            "every record of the family lives under the one tenant"
        );
    }

    #[test]
    fn the_corpus_final_state_reads_through_the_decisions() {
        let lifecycle = corpus_object("delegation-lifecycle.json");
        let verified = replay_corpus_history(&corpus_root());

        // The fold's landing state: the epoch-4 regrant is the record
        // at the pair's key — the key this module derives.
        let Some(Value::Object(final_state)) = lifecycle.get("final_state") else {
            panic!("the final state is an object")
        };
        let Some((pinned_key, _)) = final_state.iter().next() else {
            panic!("the final state pins one key")
        };
        assert_eq!(
            pinned_key,
            delegation_object_key(&tenant(), &relay(), &origin()),
            "the corpus's pair key is the object key this module derives"
        );
        let last = verified
            .last()
            .expect("the accepted history ends at the regrant");
        assert_eq!(last.epoch(), 4);
        assert_eq!(last.state(), DelegationState::Active);

        // Provenance holds through the final grant; the narrowed scope
        // refuses the harness epoch 2 allowed; and the withdrawn epoch
        // is inert whatever it names.
        let presented = last
            .authorize(&authorized_attempt(), &relay_scopes())
            .expect("the final grant authorizes the corpus pair");
        assert_eq!(presented, last.origin_client_id());
        let mut codex = authorized_attempt();
        codex.harness = harness("codex");
        assert_eq!(
            last.authorize(&codex, &relay_scopes()),
            Err(DelegationRejection::HarnessNotGranted),
            "epoch 4 narrowed the grant back to claude-code"
        );
        let withdrawn = &verified[2];
        assert_eq!(withdrawn.state(), DelegationState::Withdrawn);
        assert_eq!(
            withdrawn.authorize(&authorized_attempt(), &relay_scopes()),
            Err(DelegationRejection::Withdrawn)
        );
    }
}
