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
//! Approval of a request — validating it and signing the linked-client
//! record with the tenant authority — is the `admin approve` deliverable
//! and lives on the control-record side.

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{HarnessId, TenantId};

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
}
