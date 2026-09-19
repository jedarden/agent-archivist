// SPDX-License-Identifier: Apache-2.0

//! The link request: the one document an installation emits to ask for
//! linking, carrying public identity and requested scope and nothing else
//! (plan Phase 3: "a link request that exposes only public identity and
//! requested scope").
//!
//! The type is constructed from an
//! [`InstallationIdentity`](crate::identity::InstallationIdentity)'s
//! [`PublicIdentity`](crate::identity::PublicIdentity), so private halves
//! are unreachable by construction — there is no accessor, constructor, or
//! serialization path here that a seed could enter. The requested scope
//! mirrors the linked-client record's `scopes` shape
//! (`schemas/v1/control-client.json`): sorted harness and operation
//! allowlists, so equivalent requests produce identical canonical bytes.
//!
//! Approval is the authority side of the same document, and it lives here
//! because the refusal grammar is the request's: [`approve_link_request`]
//! takes the administrator-supplied request bytes, refuses every draft the
//! linked-client record could not carry — an operation token outside the
//! closed [`ScopeOperation`] set, an allowlist past its bounds or out of
//! order, a foreign tenant — with a typed [`ApprovalError`], resolves the
//! signing half through the pinned authority root and refuses an instant
//! its acceptance window does not cover, and only then signs the
//! linked-client current-pointer envelope: the record
//! [`crate::revocation::LinkedClientPointer::verify`] accepts from the
//! pinned root. The authority's private half enters as a borrowed seed,
//! the same discipline every signing surface in this crate holds; nothing
//! public here can hand one back.

use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, Ed25519Signature, HarnessId, KeyId, TenantId, Timestamp,
};

use crate::authority::{AuthorityChainError, PinnedAuthorityRoot, verify_signing_authority};
use crate::ed25519;
use crate::revocation::client_pointer_object_key;

/// The link request namespace token. A request is a document a host emits
/// for an administrator to read; the per-command result schema is
/// registered with `tools/cli-commands.toml` when the `link request`
/// command phase lands.
const LINK_REQUEST_SCHEMA: &str = "archivist.link-request/v1";

/// An operation an installation may ask to perform. The v1 set mirrors the
/// linked-client record's closed `operations` enum; a new operation arrives
/// there first and here with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeOperation {
    /// Present upload attempts (plan Section 7.2).
    Ingest,
}

impl ScopeOperation {
    /// Every known token, in schema order.
    #[must_use]
    pub fn tokens() -> &'static [&'static str] {
        &["ingest"]
    }

    /// The canonical wire token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Ingest => "ingest",
        }
    }
}

/// The scope an installation requests: explicit harness and operation
/// allowlists. Issued sorted, like the record the authority will write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestedScopes {
    /// Harness IDs this installation asks to capture (1–64, sorted,
    /// unique).
    pub harnesses: Vec<HarnessId>,
    /// Operations this installation asks to perform (1–64, sorted,
    /// unique).
    pub operations: Vec<ScopeOperation>,
}

impl RequestedScopes {
    /// Build a scope from unsorted input, rejecting empties, duplicates,
    /// and oversized lists the way the record schema does.
    ///
    /// # Errors
    /// [`IdentityError::IdentityCorrupt`](crate::error::IdentityError::IdentityCorrupt)
    /// when the lists are empty, longer
    /// than 64, or contain duplicates — a request that cannot be approved
    /// as written is refused at construction, not at approval.
    pub fn new(
        mut harnesses: Vec<HarnessId>,
        mut operations: Vec<ScopeOperation>,
    ) -> Result<Self, crate::error::IdentityError> {
        let sorted = |mut tokens: Vec<String>| {
            tokens.sort();
            tokens.dedup();
            tokens
        };
        let harness_tokens = sorted(harnesses.iter().map(|h| h.as_str().to_owned()).collect());
        let operation_tokens = sorted(operations.iter().map(|op| op.token().to_owned()).collect());
        let duplicated =
            harness_tokens.len() != harnesses.len() || operation_tokens.len() != operations.len();
        if harnesses.is_empty()
            || operations.is_empty()
            || harnesses.len() > 64
            || operations.len() > 64
            || duplicated
        {
            return Err(crate::error::IdentityError::IdentityCorrupt);
        }
        harnesses.sort();
        operations.sort();
        Ok(Self {
            harnesses,
            operations,
        })
    }

    /// The canonical object: sorted `harnesses` and `operations`.
    fn to_json(&self) -> Object {
        let mut members = Object::new();
        let _ = members.insert(
            "harnesses",
            Value::Array(
                self.harnesses
                    .iter()
                    .map(|harness| Value::Text(harness.as_str().to_owned()))
                    .collect(),
            ),
        );
        let _ = members.insert(
            "operations",
            Value::Array(
                self.operations
                    .iter()
                    .map(|operation| Value::Text(operation.token().to_owned()))
                    .collect(),
            ),
        );
        members
    }
}

/// A link request: public identity, requested tenant, requested scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRequest {
    /// The requesting installation's public identity.
    pub identity: crate::identity::PublicIdentity,
    /// The tenant the installation asks to be linked to.
    pub tenant_id: TenantId,
    /// The scope the installation requests.
    pub scopes: RequestedScopes,
}

impl LinkRequest {
    /// Compose the request. Only public material is accepted by the
    /// constructor: the identity parameter is the public half, so a private
    /// seed has no path into any [`LinkRequest`].
    #[must_use]
    pub fn new(
        identity: crate::identity::PublicIdentity,
        tenant_id: TenantId,
        scopes: RequestedScopes,
    ) -> Self {
        Self {
            identity,
            tenant_id,
            scopes,
        }
    }

    /// The canonical JSON document (RFC 8785 bytes), the form the `link
    /// request` command writes to stdout and an administrator validates.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut members = Object::new();
        let _ = members.insert("schema", text(LINK_REQUEST_SCHEMA));
        let _ = members.insert("client_id", text(self.identity.client_id.as_str()));
        let _ = members.insert("key_algorithm", text(self.identity.algorithm.token()));
        let _ = members.insert("key_id", text(&self.identity.key_id.to_hex()));
        let _ = members.insert("public_key", text(&self.identity.public_key.to_hex()));
        let _ = members.insert("requested_tenant_id", text(self.tenant_id.as_str()));
        let _ = members.insert("requested_scopes", Value::Object(self.scopes.to_json()));
        Value::Object(members).canonical_bytes()
    }
}

/// Insert a text member.
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

/// The control trust namespace the approval's record carries
/// (`archivist.control/v1`): the envelope every consumer verifies, and the
/// namespace the authority-rotation links the signing-window walk reads
/// are written in.
const CONTROL_NAMESPACE: &str = "archivist.control/v1";

/// The closed member set of a link request: exactly the namespace token
/// plus the six public members [`LinkRequest::canonical_bytes`] writes. A
/// draft carrying anything else is a different document, not an extensible
/// one — the administrator approves what the client declared, nothing
/// more.
const LINK_REQUEST_MEMBERS: [&str; 7] = [
    "client_id",
    "key_algorithm",
    "key_id",
    "public_key",
    "requested_scopes",
    "requested_tenant_id",
    "schema",
];

/// The entry bound both scope allowlists are pinned to
/// (`schemas/v1/control-client.json`: each array `minItems: 1`,
/// `maxItems: 64`).
const SCOPE_BOUND: usize = 64;

/// Why the tenant authority refused to approve a link request.
///
/// Every variant is a unit: diagnostics name the failure class and never
/// carry a scope token, an identity value, or any other draft content
/// (SEC-004), exactly like [`crate::error::IdentityError`]. Each refusal
/// is decided before the authority's key signs anything — an unapprovable
/// draft never becomes a signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalError {
    /// The draft is not a well-formed link request: not JSON, not an
    /// object, not the closed seven-member shape, the namespace token not
    /// this request's, a member failing its grammar, a key algorithm the
    /// v1 record cannot carry, or a `key_id` that is not the pinned
    /// derivation of the draft's own public half. Nothing about the
    /// offending input is echoed.
    MalformedRequest,
    /// A requested operation is a token outside the closed
    /// [`ScopeOperation`] v1 set — the record schema's own rule, that an
    /// unknown token fails closed, applied at approval before anything is
    /// signed.
    UnknownScopeToken,
    /// A scope allowlist is empty or past the 64-entry bound both lists
    /// are pinned to.
    ScopeOutOfBounds,
    /// A scope allowlist is not in strictly ascending token order — the
    /// order the record's writer discipline pins, so equivalent grants
    /// produce identical canonical bytes. A repeated token is not
    /// strictly ascending either: duplicates are refused here, not
    /// silently deduplicated into a grant the client did not write.
    ScopeNotSorted,
    /// The draft asks for a tenant other than the approving authority's:
    /// this authority's signature would have no force there, and a record
    /// placed under one tenant's control prefix signed by another
    /// tenant's key is exactly the cross-tenant forgery the envelope
    /// exists to refuse.
    TenantMismatch,
    /// The half the authority's seed derives does not resolve to a valid
    /// signer from the pinned root: no chain names it, or a link on the
    /// path is broken. Signing anyway would produce an envelope no
    /// verifier accepts.
    AuthorityUnreachable,
    /// The signing half's acceptance window does not include the
    /// approval's `signed_at`: the instant precedes the link that
    /// established the half, or falls past the 24-hour dual-key overlap
    /// after the link that retired it. The envelope would fail closed at
    /// its own instant, so it is never made.
    SigningWindowClosed,
    /// The approval instant is not a real calendar moment (VAL-002).
    InvalidSigningInstant,
}

impl ApprovalError {
    /// The class's content-free display text.
    #[must_use]
    pub const fn class_text(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed-request",
            Self::UnknownScopeToken => "unknown-scope-token",
            Self::ScopeOutOfBounds => "scope-out-of-bounds",
            Self::ScopeNotSorted => "scope-not-sorted",
            Self::TenantMismatch => "tenant-mismatch",
            Self::AuthorityUnreachable => "authority-unreachable",
            Self::SigningWindowClosed => "signing-window-closed",
            Self::InvalidSigningInstant => "invalid-signing-instant",
        }
    }

    /// Narrow a chain failure to the two classes an approval reports: the
    /// signing half's window does not cover the instant, or the half
    /// cannot be established from the pinned root at all. Every link-level
    /// failure lands in the second class — from the approval's side they
    /// are one outcome, a signing half the chain does not stand behind.
    fn from_chain(error: AuthorityChainError) -> Self {
        match error {
            AuthorityChainError::NotEstablished | AuthorityChainError::Retired => {
                Self::SigningWindowClosed
            }
            _ => Self::AuthorityUnreachable,
        }
    }
}

impl std::fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.class_text())
    }
}

impl std::error::Error for ApprovalError {}

/// An approved link: the byte-exact canonical linked-client envelope and
/// the object key the offline store writes it to, in one value so the two
/// can never drift.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientLinkPublication {
    envelope: Vec<u8>,
    object_key: String,
}

impl ClientLinkPublication {
    /// The canonical record bytes. A lost-response retry re-derives these
    /// byte-identically — Ed25519 signs deterministically and every member
    /// is validated before signing — which is what makes re-approving an
    /// equivalent request an idempotent repair, the same rule the store's
    /// identical-bytes write class gives it.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// The object key
    /// `tenants/<tenant>/v1/control/clients/<client>.json` the envelope is
    /// written to (plan Section 7.5) — the current-pointer key a
    /// replacement only ever occupies at a strictly higher epoch.
    #[must_use]
    pub fn object_key(&self) -> &str {
        &self.object_key
    }
}

/// Approve one link request: validate the administrator-supplied draft,
/// check the signing half's acceptance window at the approval's own
/// instant, and sign the linked-client current-pointer record the request
/// asks for.
///
/// `draft` is the request document the installation emitted and the
/// administrator read — the canonical bytes [`LinkRequest::
/// canonical_bytes`] produces, parsed here rather than trusted as a typed
/// value, because every refusal the record schema pins is a property of
/// the bytes: an operation token outside the closed [`ScopeOperation`]
/// set, an allowlist empty, past [`SCOPE_BOUND`], or not in strictly
/// ascending order, a `key_id` that is not the derivation of the draft's
/// own public half, a tenant other than `root`'s. Each is its own
/// [`ApprovalError`], and every one of them — and every malformed-draft
/// class — is decided before the signing half's acceptance window
/// ([`ResolvedAuthority`](crate::authority::ResolvedAuthority)) is
/// consulted and before the authority's key signs anything.
///
/// The window check is the verifier's own rule run in advance:
/// `verify_signing_authority` resolves the seed's half through the chain
/// anchored at `root` and requires the approval's `signed_at` inside its
/// acceptance window, so a publication the chain would refuse at its own
/// instant is never made. What survives verifies: the envelope is the
/// linked-client record
/// [`LinkedClientPointer::verify`](crate::revocation::LinkedClientPointer::verify)
/// accepts from the pinned root, at authorization epoch 1 — the epoch the
/// record schema's own rule starts every link at.
///
/// The signing seed is the tenant authority's private half and enters only
/// as a borrowed slice, the same discipline every signing surface here
/// holds (SEC-004, SEC-006); the record carries its public derivation
/// only, and no public type in this module can hand a private half back.
///
/// # Errors
/// The matching [`ApprovalError`] class for every refused draft; the
/// publication on success.
pub fn approve_link_request(
    authority_seed: &[u8; 32],
    root: &PinnedAuthorityRoot,
    draft: &[u8],
    signed_at: &Timestamp,
    fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
) -> Result<ClientLinkPublication, ApprovalError> {
    // Draft refusals first: an unapprovable request is refused as itself,
    // whatever the chain looks like.
    let validated = validated_draft(root, draft)?;

    if !signed_at.calendar_valid() {
        return Err(ApprovalError::InvalidSigningInstant);
    }

    // The signing window, by the verifier's own rule: resolve the seed's
    // half from the pinned root and require the instant inside its
    // acceptance window. A retired half past the dual-key overlap, a half
    // not yet established, and a half no chain names are all refused
    // before anything is signed.
    let authority_public = ed25519::public_key_from_seed(authority_seed);
    let authority_key_id = KeyId::from_public_key(&Ed25519PublicKey::from_raw(authority_public));
    let resolved = verify_signing_authority(root, &authority_key_id, signed_at, fetch)
        .map_err(ApprovalError::from_chain)?;
    if *resolved.public_key() != Ed25519PublicKey::from_raw(authority_public) {
        // Unreachable while key IDs are the pinned derivations they are
        // defined as, refused rather than assumed: the envelope must name
        // the half the chain resolved, never a near miss.
        return Err(ApprovalError::AuthorityUnreachable);
    }

    // The control-record-v1 construction: canonical bytes without the
    // signature member, then the signature appended — the exact bytes
    // `verify_control_record` re-derives on the reading side.
    let mut members = Object::new();
    members.set("schema", text(CONTROL_NAMESPACE));
    members.set("record_type", text("linked-client"));
    members.set("record_kind", text("current-pointer"));
    members.set("tenant_id", text(root.tenant_id().as_str()));
    members.set("client_id", text(validated.client_id.as_str()));
    members.set("key_id", text(&validated.key_id.to_hex()));
    members.set("key_algorithm", text("ed25519"));
    members.set("public_key", text(&validated.public_key.to_hex()));
    members.set("scopes", Value::Object(validated.scopes));
    members.set("authorization_epoch", Value::Int(1));
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
    Ok(ClientLinkPublication {
        envelope: Value::Object(members).canonical_bytes(),
        object_key: client_pointer_object_key(root.tenant_id(), &validated.client_id),
    })
}

/// The draft members approval carries into the record, each validated.
struct ValidatedDraft {
    client_id: ClientId,
    public_key: Ed25519PublicKey,
    key_id: KeyId,
    /// The scope object rebuilt from the validated allowlists, in the
    /// ascending order the record's writer discipline pins.
    scopes: Object,
}

/// Parse and validate one administrator-supplied link-request draft.
///
/// The refusal order is shape, bounds, token grammar, order: a draft that
/// fails at an earlier layer is refused there, so an oversized allowlist
/// is [`ApprovalError::ScopeOutOfBounds`] even when it also carries an
/// unknown token, and an unknown token is
/// [`ApprovalError::UnknownScopeToken`] even when the list is also
/// unsorted.
fn validated_draft(
    root: &PinnedAuthorityRoot,
    draft: &[u8],
) -> Result<ValidatedDraft, ApprovalError> {
    const MALFORMED: ApprovalError = ApprovalError::MalformedRequest;
    let Value::Object(object) = json::parse(draft).map_err(|_| MALFORMED)? else {
        return Err(MALFORMED);
    };
    if !is_member_set(&object, &LINK_REQUEST_MEMBERS) {
        return Err(MALFORMED);
    }
    if text_member(&object, "schema") != Some(LINK_REQUEST_SCHEMA) {
        return Err(MALFORMED);
    }
    let client_id = ClientId::parse(text_member(&object, "client_id").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    // v1 pins Ed25519 (`key_algorithm`, the record schema's own closed
    // value); the request constructor cannot produce anything else, so a
    // foreign algorithm is a corrupt draft, not a future feature to wait
    // for.
    if text_member(&object, "key_algorithm") != Some("ed25519") {
        return Err(MALFORMED);
    }
    let public_key = Ed25519PublicKey::parse(text_member(&object, "public_key").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    let key_id =
        KeyId::parse(text_member(&object, "key_id").ok_or(MALFORMED)?).map_err(|_| MALFORMED)?;
    if key_id != KeyId::from_public_key(&public_key) {
        // The same VAL-002 derivation check the linked-client record
        // applies to itself: an asserted identity is refused before the
        // authority is asked to bless it.
        return Err(MALFORMED);
    }
    let requested_tenant =
        TenantId::parse(text_member(&object, "requested_tenant_id").ok_or(MALFORMED)?)
            .map_err(|_| MALFORMED)?;
    if requested_tenant != *root.tenant_id() {
        return Err(ApprovalError::TenantMismatch);
    }
    let Some(Value::Object(scopes)) = object.get("requested_scopes") else {
        return Err(MALFORMED);
    };
    if scopes.len() != 2 || !scopes.contains("harnesses") || !scopes.contains("operations") {
        return Err(MALFORMED);
    }
    let harnesses = text_array(scopes.get("harnesses")).ok_or(MALFORMED)?;
    let operations = text_array(scopes.get("operations")).ok_or(MALFORMED)?;
    if harnesses.is_empty()
        || operations.is_empty()
        || harnesses.len() > SCOPE_BOUND
        || operations.len() > SCOPE_BOUND
    {
        return Err(ApprovalError::ScopeOutOfBounds);
    }
    for token in &operations {
        if !ScopeOperation::tokens().contains(token) {
            return Err(ApprovalError::UnknownScopeToken);
        }
    }
    for token in &harnesses {
        if HarnessId::parse(token).is_err() {
            return Err(MALFORMED);
        }
    }
    if !strictly_ascending(&harnesses) || !strictly_ascending(&operations) {
        return Err(ApprovalError::ScopeNotSorted);
    }
    // Rebuild the scope object from the validated tokens: the record's
    // `scopes` member is the ascending order the draft declared, and
    // nothing it did not declare.
    let mut canonical_scopes = Object::new();
    canonical_scopes.set(
        "harnesses",
        Value::Array(harnesses.iter().map(|token| text(token)).collect()),
    );
    canonical_scopes.set(
        "operations",
        Value::Array(operations.iter().map(|token| text(token)).collect()),
    );
    Ok(ValidatedDraft {
        client_id,
        public_key,
        key_id,
        scopes: canonical_scopes,
    })
}

/// Whether `object` carries exactly `expected` and nothing else.
fn is_member_set(object: &Object, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|name| object.contains(name))
}

/// Read one text member, failing closed when it is absent or not text.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

/// Read one array of text tokens, failing closed on anything else.
fn text_array(value: Option<&Value>) -> Option<Vec<&str>> {
    match value {
        Some(Value::Array(items)) => {
            let mut tokens = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Text(token) => tokens.push(token.as_str()),
                    _ => return None,
                }
            }
            Some(tokens)
        }
        _ => None,
    }
}

/// Whether every token is strictly less than the next: the ascending order
/// the record schema pins, which excludes duplicates by the same
/// comparison.
fn strictly_ascending(tokens: &[&str]) -> bool {
    tokens.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::IdentityError;
    use crate::identity::InstallationIdentity;

    /// A synthetic tenant from the conformance corpus.
    const TENANT_ID: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

    fn sample_request() -> LinkRequest {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let tenant = TenantId::parse(TENANT_ID).expect("grammar");
        let harnesses = vec![
            HarnessId::parse("claude-code").expect("grammar"),
            HarnessId::parse("codex").expect("grammar"),
        ];
        let scopes = RequestedScopes::new(harnesses, vec![ScopeOperation::Ingest])
            .expect("well-formed scope");
        LinkRequest::new(identity.public_identity(), tenant, scopes)
    }

    /// The canonical document carries exactly the six public members, in
    /// canonical (sorted) key order, with the requested scope sorted.
    #[test]
    fn document_is_canonical_and_public_only() {
        let request = sample_request();
        let bytes = request.canonical_bytes();
        let document = String::from_utf8(bytes).expect("canonical JSON is utf-8");
        // RFC 8785 sorts object keys by UTF-16 code units; assert the order
        // directly so the byte form is pinned.
        let expected_order = [
            "\"client_id\":",
            "\"key_algorithm\":",
            "\"key_id\":",
            "\"public_key\":",
            "\"requested_scopes\":{\"harnesses\":[\"claude-code\",\"codex\"],\"operations\":[\"ingest\"]}",
            "\"requested_tenant_id\":",
            "\"schema\":\"archivist.link-request/v1\"",
        ];
        let mut cursor = 0;
        for fragment in expected_order {
            let at = document[cursor..]
                .find(fragment)
                .unwrap_or_else(|| panic!("fragment {fragment} missing from {document}"));
            cursor += at + fragment.len();
        }
    }

    /// Unsorted scope input is normalized into sorted canonical form.
    #[test]
    fn scopes_are_sorted_on_construction() {
        let harnesses = vec![
            HarnessId::parse("zeta").expect("grammar"),
            HarnessId::parse("alpha").expect("grammar"),
        ];
        let scopes = RequestedScopes::new(harnesses, vec![ScopeOperation::Ingest])
            .expect("well-formed scope");
        let tokens: Vec<&str> = scopes.harnesses.iter().map(HarnessId::as_str).collect();
        assert_eq!(tokens, ["alpha", "zeta"]);
    }

    /// Empty, oversized, and duplicate scopes fail at construction.
    #[test]
    fn malformed_scopes_fail_construction() {
        let one = vec![HarnessId::parse("claude-code").expect("grammar")];
        let many: Vec<_> = (0..65)
            .map(|i| HarnessId::parse(&format!("harness-{i}")).expect("grammar"))
            .collect();
        assert_eq!(
            RequestedScopes::new(Vec::new(), vec![ScopeOperation::Ingest]),
            Err(IdentityError::IdentityCorrupt)
        );
        assert_eq!(
            RequestedScopes::new(one.clone(), Vec::new()),
            Err(IdentityError::IdentityCorrupt)
        );
        assert_eq!(
            RequestedScopes::new(many, vec![ScopeOperation::Ingest]),
            Err(IdentityError::IdentityCorrupt)
        );
        assert_eq!(
            RequestedScopes::new(
                one.clone(),
                vec![ScopeOperation::Ingest, ScopeOperation::Ingest]
            ),
            Err(IdentityError::IdentityCorrupt)
        );
        // Dedup-free well-formed scope still constructs.
        assert!(RequestedScopes::new(one, vec![ScopeOperation::Ingest]).is_ok());
    }

    /// Two requests with equivalent (differently ordered) scopes produce
    /// identical canonical bytes.
    #[test]
    fn equivalent_scopes_produce_identical_bytes() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let public = identity.public_identity();
        let tenant = TenantId::parse(TENANT_ID).expect("grammar");
        let a = RequestedScopes::new(
            vec![
                HarnessId::parse("claude-code").expect("grammar"),
                HarnessId::parse("codex").expect("grammar"),
            ],
            vec![ScopeOperation::Ingest],
        )
        .expect("well-formed");
        let b = RequestedScopes::new(
            vec![
                HarnessId::parse("codex").expect("grammar"),
                HarnessId::parse("claude-code").expect("grammar"),
            ],
            vec![ScopeOperation::Ingest],
        )
        .expect("well-formed");
        assert_eq!(
            LinkRequest::new(public.clone(), tenant.clone(), a).canonical_bytes(),
            LinkRequest::new(public, tenant, b).canonical_bytes()
        );
    }

    /// The operation token set is the record schema's v1 enum.
    #[test]
    fn operation_tokens_match_v1() {
        assert_eq!(ScopeOperation::tokens(), &["ingest"]);
        assert_eq!(ScopeOperation::Ingest.token(), "ingest");
    }

    /// The request and everything it prints contain the public identity
    /// and never the installation's seed. Paired with the leak test in the
    /// integration suite, this pins the acceptance property at the type
    /// level.
    #[test]
    fn request_carries_public_identity() {
        let request = sample_request();
        let document = request.canonical_bytes();
        let text = std::str::from_utf8(&document).expect("utf-8");
        assert!(text.contains(request.identity.client_id.as_str()));
        assert!(text.contains(&request.identity.public_key.to_hex()));
        assert!(text.contains(&request.identity.key_id.to_hex()));
        assert_eq!(request.identity.algorithm.token(), "ed25519");
    }

    // ------------------------------------------------------------------
    // Approval: the tenant-authority side of the link request
    // ------------------------------------------------------------------

    use std::collections::HashMap;

    use crate::authority::PinnedAuthorityRoot;
    use crate::ed25519;
    use crate::revocation::LinkedClientPointer;
    use archivist_protocol::vocabulary::{Ed25519PublicKey, Ed25519Signature, KeyId};

    /// A deterministic authority seed: every approval signature below is
    /// reproducible byte for byte.
    const AUTHORITY_SEED: [u8; 32] = [0x17; 32];
    const SUCCESSOR_SEED: [u8; 32] = [0x18; 32];
    const STRANGER_SEED: [u8; 32] = [0x19; 32];
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";
    /// The approval instant, and the rotation instants the window tests
    /// walk: a link signed at `LINK_INSTANT` retires the root and
    /// establishes the successor, whose dual-key overlap ends
    /// `OVERLAP_END` inclusive.
    const APPROVAL_INSTANT: &str = "2026-09-19T00:00:00Z";
    const LINK_INSTANT: &str = "2026-09-10T00:00:00Z";
    const OVERLAP_END: &str = "2026-09-11T00:00:00Z";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT_ID).expect("grammar")
    }

    fn other_tenant() -> TenantId {
        TenantId::parse(OTHER_TENANT).expect("grammar")
    }

    fn authority_half(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    fn authority_root() -> PinnedAuthorityRoot {
        PinnedAuthorityRoot::new(tenant(), authority_half(&AUTHORITY_SEED))
    }

    fn instant(text: &str) -> Timestamp {
        Timestamp::parse(text).expect("pinned test instant")
    }

    /// Build the signed link that retires `predecessor_seed` and
    /// establishes `successor_seed` at `signed_at` — the same fixture the
    /// authority module's own tests pin, rebuilt here so the window tests
    /// exercise a one-link chain end to end.
    fn signed_link(
        predecessor_seed: &[u8; 32],
        successor_seed: &[u8; 32],
        signed_at: &str,
        link_tenant: &TenantId,
    ) -> Vec<u8> {
        let previous_public = authority_half(predecessor_seed);
        let public = authority_half(successor_seed);
        let previous_key_id = KeyId::from_public_key(&previous_public);
        let mut members = Object::new();
        members.set("schema", text(CONTROL_NAMESPACE));
        members.set("record_type", text("authority-rotation"));
        members.set("record_kind", text("immutable"));
        members.set("tenant_id", text(link_tenant.as_str()));
        members.set("previous_public_key", text(&previous_public.to_hex()));
        members.set("previous_key_id", text(&previous_key_id.to_hex()));
        members.set("key_algorithm", text("ed25519"));
        members.set("public_key", text(&public.to_hex()));
        members.set("key_id", text(&KeyId::from_public_key(&public).to_hex()));
        members.set("signed_at", text(signed_at));
        members.set("authority_key_id", text(&previous_key_id.to_hex()));
        let signature = ed25519::sign(
            predecessor_seed,
            &Value::Object(members.clone()).canonical_bytes(),
        );
        members.set(
            "authority_signature",
            text(&Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
        );
        Value::Object(members).canonical_bytes()
    }

    /// A chain store: the bytes at each predecessor address, exactly as a
    /// `ControlReadStore` would serve them. The address is the pinned
    /// derivation of the predecessor's public half.
    fn chain_store(links: Vec<(&[u8; 32], Vec<u8>)>) -> HashMap<KeyId, Vec<u8>> {
        let mut store = HashMap::new();
        for (predecessor_seed, bytes) in links {
            store.insert(
                KeyId::from_public_key(&authority_half(predecessor_seed)),
                bytes,
            );
        }
        store
    }

    fn fetch_from(store: &HashMap<KeyId, Vec<u8>>) -> impl FnMut(&KeyId) -> Option<Vec<u8>> + '_ {
        move |key| store.get(key).cloned()
    }

    /// One link-request document with the draft's own scope arrays — the
    /// hand-built form a refusal case needs, since the typed constructor
    /// cannot express a malformed scope.
    fn draft_document(
        identity: &crate::identity::PublicIdentity,
        request_tenant: &TenantId,
        harnesses: &[&str],
        operations: &[&str],
    ) -> Vec<u8> {
        let mut scopes = Object::new();
        scopes.set(
            "harnesses",
            Value::Array(harnesses.iter().map(|token| text(token)).collect()),
        );
        scopes.set(
            "operations",
            Value::Array(operations.iter().map(|token| text(token)).collect()),
        );
        let mut members = Object::new();
        members.set("schema", text(LINK_REQUEST_SCHEMA));
        members.set("client_id", text(identity.client_id.as_str()));
        members.set("key_algorithm", text(identity.algorithm.token()));
        members.set("key_id", text(&identity.key_id.to_hex()));
        members.set("public_key", text(&identity.public_key.to_hex()));
        members.set("requested_tenant_id", text(request_tenant.as_str()));
        members.set("requested_scopes", Value::Object(scopes));
        Value::Object(members).canonical_bytes()
    }

    /// A well-formed draft for `identity`: one harness, the one v1
    /// operation.
    fn valid_draft(identity: &crate::identity::PublicIdentity) -> Vec<u8> {
        draft_document(identity, &tenant(), &["claude-code"], &["ingest"])
    }

    /// Approve `draft` under `root` at `signed_at`, reading chain links
    /// from `store`.
    fn approve(
        root: &PinnedAuthorityRoot,
        draft: &[u8],
        signed_at: &str,
        store: &HashMap<KeyId, Vec<u8>>,
    ) -> Result<ClientLinkPublication, ApprovalError> {
        approve_link_request(
            &AUTHORITY_SEED,
            root,
            draft,
            &instant(signed_at),
            fetch_from(store),
        )
    }

    /// The approval signs the linked-client current-pointer record the
    /// pinned root verifies: the pointer triple is the draft's own
    /// identity at epoch 1, the scopes are the draft's own allowlists, and
    /// the object key is the current-pointer key. Re-approving the same
    /// request is byte-identical.
    #[test]
    fn approval_signs_a_pointer_the_pinned_root_verifies() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let root = authority_root();
        let store = chain_store(Vec::new());
        let publication = approve(
            &root,
            &valid_draft(&identity.public_identity()),
            APPROVAL_INSTANT,
            &store,
        )
        .expect("the draft is approvable");

        let pointer = LinkedClientPointer::verify(
            &root,
            publication.envelope(),
            |_| None,
            &identity.public_identity().client_id,
        )
        .expect("the envelope verifies against the pinned root");
        assert_eq!(pointer.client_id(), &identity.public_identity().client_id);
        assert_eq!(pointer.epoch(), 1);
        assert_eq!(pointer.key_id(), &identity.public_identity().key_id);

        // The scope the authority signed is the scope the draft declared,
        // in the draft's own ascending order.
        let Value::Object(record) =
            archivist_protocol::json::parse(publication.envelope()).expect("canonical json")
        else {
            panic!("the envelope is an object");
        };
        assert_eq!(
            record.get("scopes"),
            Some(&Value::Object({
                let mut scopes = Object::new();
                scopes.set("harnesses", Value::Array(vec![text("claude-code")]));
                scopes.set("operations", Value::Array(vec![text("ingest")]));
                scopes
            }))
        );
        assert_eq!(
            publication.object_key(),
            format!(
                "tenants/{}/v1/control/clients/{}.json",
                TENANT_ID,
                identity.public_identity().client_id.as_str()
            )
        );

        let again = approve(
            &root,
            &valid_draft(&identity.public_identity()),
            APPROVAL_INSTANT,
            &store,
        )
        .expect("re-approval succeeds");
        assert_eq!(publication.envelope(), again.envelope());
    }

    /// Equivalent request documents — same members, different order and
    /// whitespace — approve to identical canonical bytes.
    #[test]
    fn equivalent_drafts_approve_to_identical_bytes() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let public = identity.public_identity();
        let root = authority_root();
        let store = chain_store(Vec::new());
        let typed_scopes = RequestedScopes::new(
            vec![HarnessId::parse("claude-code").expect("grammar")],
            vec![ScopeOperation::Ingest],
        )
        .expect("well-formed scope");
        let typed_request = LinkRequest::new(public.clone(), tenant(), typed_scopes);
        let typed = approve(
            &root,
            &typed_request.canonical_bytes(),
            APPROVAL_INSTANT,
            &store,
        )
        .expect("the typed draft approves");
        let hand_written = format!(
            "{{ \"requested_scopes\": {{\"operations\": [\"ingest\"], \
             \"harnesses\": [\"claude-code\"]}}, \"requested_tenant_id\": \"{tenant}\", \
             \"public_key\": \"{pk}\", \"key_id\": \"{kid}\", \
             \"key_algorithm\": \"ed25519\", \"client_id\": \"{cid}\", \
             \"schema\": \"{schema}\" }}",
            tenant = TENANT_ID,
            pk = public.public_key.to_hex(),
            kid = public.key_id.to_hex(),
            cid = public.client_id.as_str(),
            schema = LINK_REQUEST_SCHEMA,
        );
        let loose = approve_link_request(
            &AUTHORITY_SEED,
            &root,
            hand_written.as_bytes(),
            &instant(APPROVAL_INSTANT),
            fetch_from(&store),
        )
        .expect("the hand-written equivalent approves");
        assert_eq!(typed.envelope(), loose.envelope());
    }

    /// An operation token outside the closed v1 set is refused — and it is
    /// refused as itself even when the signing window is closed too:
    /// draft validation precedes the window check.
    #[test]
    fn unknown_scope_tokens_are_refused_before_the_window_is_consulted() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let root = authority_root();
        let store = chain_store(vec![(
            &AUTHORITY_SEED,
            signed_link(&AUTHORITY_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
        )]);
        let draft = draft_document(
            &identity.public_identity(),
            &tenant(),
            &["claude-code"],
            &["admin"],
        );
        assert_eq!(
            approve(&root, &draft, "2026-09-12T00:00:00Z", &store),
            Err(ApprovalError::UnknownScopeToken)
        );
    }

    /// Empty and oversized allowlists are refused at their bound.
    #[test]
    fn out_of_bounds_allowlists_are_refused() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let public = identity.public_identity();
        let root = authority_root();
        let store = chain_store(Vec::new());
        let many: Vec<String> = (0..65).map(|i| format!("harness-{i}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert_eq!(
            approve(
                &root,
                &draft_document(&public, &tenant(), &many, &["ingest"]),
                APPROVAL_INSTANT,
                &store
            ),
            Err(ApprovalError::ScopeOutOfBounds)
        );
        assert_eq!(
            approve(
                &root,
                &draft_document(&public, &tenant(), &[], &["ingest"]),
                APPROVAL_INSTANT,
                &store
            ),
            Err(ApprovalError::ScopeOutOfBounds)
        );
        assert_eq!(
            approve(
                &root,
                &draft_document(&public, &tenant(), &["claude-code"], &[]),
                APPROVAL_INSTANT,
                &store
            ),
            Err(ApprovalError::ScopeOutOfBounds)
        );
    }

    /// An allowlist not in strictly ascending order is refused, a
    /// repeated token included — approval signs the order the client
    /// declared or nothing.
    #[test]
    fn unsorted_allowlists_are_refused() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let public = identity.public_identity();
        let root = authority_root();
        let store = chain_store(Vec::new());
        assert_eq!(
            approve(
                &root,
                &draft_document(&public, &tenant(), &["codex", "claude-code"], &["ingest"]),
                APPROVAL_INSTANT,
                &store
            ),
            Err(ApprovalError::ScopeNotSorted)
        );
        assert_eq!(
            approve(
                &root,
                &draft_document(&public, &tenant(), &["claude-code"], &["ingest", "ingest"]),
                APPROVAL_INSTANT,
                &store
            ),
            Err(ApprovalError::ScopeNotSorted)
        );
    }

    /// A draft for another tenant is refused: this authority's signature
    /// would have no force there.
    #[test]
    fn foreign_tenant_drafts_are_refused() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let root = authority_root();
        let store = chain_store(Vec::new());
        let draft = draft_document(
            &identity.public_identity(),
            &other_tenant(),
            &["claude-code"],
            &["ingest"],
        );
        assert_eq!(
            approve(&root, &draft, APPROVAL_INSTANT, &store),
            Err(ApprovalError::TenantMismatch)
        );
    }

    /// Malformed drafts are refused as malformed: garbage bytes, a
    /// foreign namespace token, a missing member, an extra member, and a
    /// key ID that is not the derivation of the draft's own public half.
    #[test]
    fn malformed_drafts_are_refused() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let other = InstallationIdentity::generate().expect("entropy is available");
        let public = identity.public_identity();
        let root = authority_root();
        let store = chain_store(Vec::new());
        let refuse = |draft: Vec<u8>| approve(&root, &draft, APPROVAL_INSTANT, &store);

        assert_eq!(
            refuse(b"not json at all".to_vec()),
            Err(ApprovalError::MalformedRequest)
        );

        let wrong_schema = draft_document(&public, &tenant(), &["claude-code"], &["ingest"]);
        let wrong_schema = String::from_utf8(wrong_schema)
            .expect("utf-8")
            .replace(LINK_REQUEST_SCHEMA, "archivist.link-request/v2");
        assert_eq!(
            refuse(wrong_schema.into_bytes()),
            Err(ApprovalError::MalformedRequest)
        );

        let mut missing = draft_document(&public, &tenant(), &["claude-code"], &["ingest"]);
        let Ok(Value::Object(mut object)) = archivist_protocol::json::parse(&missing) else {
            panic!("the draft is an object");
        };
        let _ = object.remove("public_key");
        missing = Value::Object(object).canonical_bytes();
        assert_eq!(refuse(missing), Err(ApprovalError::MalformedRequest));

        let extra = format!(
            "{{\"schema\":\"{schema}\",\"client_id\":\"{cid}\",\"key_algorithm\":\"ed25519\",\
             \"key_id\":\"{kid}\",\"public_key\":\"{pk}\",\"requested_tenant_id\":\"{tenant}\",\
             \"requested_scopes\":{{\"harnesses\":[\"claude-code\"],\"operations\":[\"ingest\"]}},\
             \"note\":\"extra\"}}",
            schema = LINK_REQUEST_SCHEMA,
            cid = public.client_id.as_str(),
            kid = public.key_id.to_hex(),
            pk = public.public_key.to_hex(),
            tenant = TENANT_ID,
        );
        assert_eq!(
            refuse(extra.into_bytes()),
            Err(ApprovalError::MalformedRequest)
        );

        let draft = draft_document(&public, &tenant(), &["claude-code"], &["ingest"]);
        let Ok(Value::Object(mut swapped)) = archivist_protocol::json::parse(&draft) else {
            panic!("the draft is an object");
        };
        swapped.set("key_id", text(&other.public_identity().key_id.to_hex()));
        assert_eq!(
            refuse(Value::Object(swapped).canonical_bytes()),
            Err(ApprovalError::MalformedRequest)
        );
    }

    /// The signing window gates approval by the verifier's own rule: the
    /// predecessor signs through the overlap's last instant and not one
    /// second past; the successor signs from its establishing instant and
    /// never before it.
    #[test]
    fn the_signing_window_gates_approval() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let draft = valid_draft(&identity.public_identity());
        let root = authority_root();
        let store = chain_store(vec![(
            &AUTHORITY_SEED,
            signed_link(&AUTHORITY_SEED, &SUCCESSOR_SEED, LINK_INSTANT, &tenant()),
        )]);

        // The root, inside the overlap's last instant: approved.
        let publication = approve_link_request(
            &AUTHORITY_SEED,
            &root,
            &draft,
            &instant(OVERLAP_END),
            fetch_from(&store),
        )
        .expect("the overlap's last instant is inside the window");
        LinkedClientPointer::verify(
            &root,
            publication.envelope(),
            |_| None,
            &identity.public_identity().client_id,
        )
        .expect("the envelope still verifies: the window rule is the same");

        // One second past the overlap: the root's window is closed.
        assert_eq!(
            approve_link_request(
                &AUTHORITY_SEED,
                &root,
                &draft,
                &instant("2026-09-11T00:00:01Z"),
                fetch_from(&store),
            ),
            Err(ApprovalError::SigningWindowClosed)
        );

        // The successor signs from its establishing instant, inclusive —
        // and long after.
        for at in [LINK_INSTANT, APPROVAL_INSTANT] {
            approve_link_request(
                &SUCCESSOR_SEED,
                &root,
                &draft,
                &instant(at),
                fetch_from(&store),
            )
            .expect("the successor's window is open from its establishment");
        }

        // One second before establishment: the successor's window is not
        // open yet.
        assert_eq!(
            approve_link_request(
                &SUCCESSOR_SEED,
                &root,
                &draft,
                &instant("2026-09-09T23:59:59Z"),
                fetch_from(&store),
            ),
            Err(ApprovalError::SigningWindowClosed)
        );

        // A calendar-impossible instant is refused as itself.
        assert_eq!(
            approve_link_request(
                &SUCCESSOR_SEED,
                &root,
                &draft,
                &instant("2026-02-30T00:00:00Z"),
                fetch_from(&store),
            ),
            Err(ApprovalError::InvalidSigningInstant)
        );
    }

    /// A half no chain names is refused: signing it would produce an
    /// envelope no verifier accepts.
    #[test]
    fn an_unreachable_signing_half_is_refused() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let draft = valid_draft(&identity.public_identity());
        let root = authority_root();
        let store = chain_store(Vec::new());
        assert_eq!(
            approve_link_request(
                &STRANGER_SEED,
                &root,
                &draft,
                &instant(APPROVAL_INSTANT),
                fetch_from(&store),
            ),
            Err(ApprovalError::AuthorityUnreachable)
        );
    }

    /// Nothing public carries the authority's private half: the envelope
    /// and the object key hold neither the seed's bytes nor their hex.
    #[test]
    fn publications_carry_no_private_material() {
        let identity = InstallationIdentity::generate().expect("entropy is available");
        let root = authority_root();
        let store = chain_store(Vec::new());
        let publication = approve(
            &root,
            &valid_draft(&identity.public_identity()),
            APPROVAL_INSTANT,
            &store,
        )
        .expect("the draft is approvable");
        let envelope = publication.envelope();
        for window in AUTHORITY_SEED.windows(8) {
            assert!(
                !envelope.windows(8).any(|bytes| bytes == window),
                "an 8-byte seed window leaked into the envelope"
            );
        }
        let hex_seed = AUTHORITY_SEED.iter().fold(String::new(), |mut hex, byte| {
            use std::fmt::Write as _;
            let _ = write!(hex, "{byte:02x}");
            hex
        });
        let rendered = String::from_utf8(envelope.to_vec()).expect("canonical json is utf-8");
        assert!(!rendered.contains(&hex_seed));
        assert!(!publication.object_key().contains(&hex_seed));
    }

    /// The closed operation set stays in ascending token order — the
    /// order the scope-sortedness check reads the draft in, and the order
    /// the record's writer discipline pins.
    #[test]
    fn operation_tokens_are_ascending_in_enumeration_order() {
        let tokens = ScopeOperation::tokens();
        for pair in tokens.windows(2) {
            assert!(pair[0] < pair[1], "{tokens:?} is not ascending");
        }
    }
}
