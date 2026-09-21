// SPDX-License-Identifier: Apache-2.0

//! The `admin revoke` command's revocation-draft parsing (plan Phase 3):
//! the operand document read, shaped, and grammar-checked into the draft
//! the command's signing and persistence acts consume.
//!
//! The wiring follows the registry entry
//! (`[commands."admin revoke"]` in `tools/cli-commands.toml`) the same way
//! the `admin approve` command's ([`crate::approve`]) does: the operand
//! path holds the draft. The draft document is the administrator's
//! statement of what to revoke, and it carries exactly the members
//! [`publish_revocation`](archivist_auth::revocation::publish_revocation)
//! consumes from it — the tenant, the client, the revoked authorization
//! epoch, the revoked key ID, and the signed instant — under one closed
//! member set:
//!
//! | Member | Grammar | Consumed as |
//! |---|---|---|
//! | `schema` | `archivist.revocation-draft/v1` | the document's identity |
//! | `tenant_id` | `uuid-v4` | the `tenant` parameter |
//! | `client_id` | `uuid-v4` | the `client` parameter |
//! | `revoked_key_id` | `key-id` | the `revoked_key_id` parameter |
//! | `authorization_epoch` | one-based integer | the `revoke_epoch` parameter |
//! | `signed_at` | RFC 3339 instant | the `signed_at` parameter |
//!
//! # The client's pointer view is not draft material
//!
//! [`publish_revocation`](archivist_auth::revocation::publish_revocation)
//! also consumes the client's current
//! [`LinkedClientPointer`](archivist_auth::revocation::LinkedClientPointer)
//! — the standing state its epoch rules are decided against. That view is
//! deliberately absent from the draft: it is the control plane's verified
//! state, not the draft author's claim about it, and a draft-carried
//! pointer would be exactly the unverified stored-state material the
//! epoch rules exist to check. Where the signing act obtains the verified
//! view — a read through the control plane, or another composition the
//! signing deliverable proves — is that deliverable's decision; this
//! module hands it the draft, and the draft's `client_id` is what the
//! client's pointer key is derived from.
//!
//! # Refusals exit through registered codes
//!
//! Every refusal is a registered condition of `tools/error-codes.toml`
//! (CLI-002), decided before anything is signed or written; the router
//! frames the diagnostic on stderr and stdout stays empty:
//!
//! | Refusal | Registered code | Class exit |
//! |---|---|---|
//! | The document is not a revocation draft the command could act on | `envelope.malformed` | 65 |
//! | No operand path, or the path does not read | `cli.usage_error` | 64 |
//!
//! The malformed class covers every way a document can fail as a draft:
//! not JSON, not an object, a member outside the closed set or a missing
//! one, a foreign namespace, a member failing its grammar, a zero or
//! negative epoch, and an instant that is unparseable or not a real
//! calendar moment — the same two member conditions
//! [`PublicationError::MalformedInput`](archivist_auth::revocation::PublicationError::MalformedInput)
//! refuses at publication, refused here before anything downstream runs.
//! The invocation-shape refusals are the approve command's own convention
//! for operand paths, kept identical so the two admin commands refuse
//! alike.

use archivist_client_core::cli::{CliError, Invocation};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{ClientId, KeyId, TenantId, Timestamp};

/// The registered code for a presented document that is not a revocation
/// draft the command could act on (`tools/error-codes.toml`, class
/// `request_invalid`) — the draft refusal code the `admin approve`
/// command carries, and the code
/// [`PublicationError::MalformedInput`](archivist_auth::revocation::PublicationError::MalformedInput)
/// surfaces as.
const MALFORMED_DRAFT: &str = "envelope.malformed";

/// The draft document's namespace token — the identity member every
/// parser of the shape checks first.
const DRAFT_SCHEMA: &str = "archivist.revocation-draft/v1";

/// The closed member set of a revocation draft
/// (`additionalProperties: false`, the record family's own discipline):
/// the document's identity plus exactly the members
/// [`publish_revocation`](archivist_auth::revocation::publish_revocation)
/// consumes.
const DRAFT_MEMBERS: [&str; 6] = [
    "schema",
    "tenant_id",
    "client_id",
    "revoked_key_id",
    "authorization_epoch",
    "signed_at",
];

/// One parsed revocation draft: the validated members the `admin revoke`
/// command's signing and persistence acts consume.
///
/// Construction is [`parse_draft`] (directly, or through [`read_draft`]'s
/// operand path) and nothing else; every member is an already-validated
/// vocabulary type, so the signing act consumes the draft without
/// re-checking a single grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationDraft {
    tenant_id: TenantId,
    client_id: ClientId,
    revoke_epoch: u64,
    revoked_key_id: KeyId,
    signed_at: Timestamp,
}

impl RevocationDraft {
    /// The tenant whose authority signs the revocation.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The client whose authorization dies at `revoke_epoch`.
    #[must_use]
    pub const fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The revoked authorization epoch — one-based, already refused at
    /// zero by the parse.
    #[must_use]
    pub const fn revoke_epoch(&self) -> u64 {
        self.revoke_epoch
    }

    /// The key ID that dies at `revoke_epoch`.
    #[must_use]
    pub const fn revoked_key_id(&self) -> &KeyId {
        &self.revoked_key_id
    }

    /// The instant the authority signs the revocation at.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }
}

/// Read the command's operand document and parse it into the draft.
///
/// This is the composition point the command's handler wraps: the
/// invocation's first operand is the draft path, per the registry entry's
/// `operand = "path"` grammar. The registry's operand grammar is the
/// parser's to enforce; the operand guard stands for direct composition.
///
/// # Errors
/// No operand path, or a path that does not read, is the registered
/// usage error (exit 64). Everything wrong with the document's own
/// content is [`parse_draft`]'s registered refusal (exit 65); either way
/// stdout stays empty because no document is returned to the router.
pub fn read_draft(invocation: &Invocation) -> Result<RevocationDraft, CliError> {
    let path = invocation.operands().first().ok_or_else(CliError::usage)?;
    let draft = std::fs::read(path).map_err(|_| CliError::usage())?;
    parse_draft(&draft)
}

/// Parse one revocation draft from its document bytes.
///
/// The closed member set is checked as one step — an extra member is a
/// malformed draft, not a smuggled payload — then the namespace, then
/// every member grammar, then the two member conditions publication
/// refuses as
/// [`MalformedInput`](archivist_auth::revocation::PublicationError::MalformedInput):
/// a zero epoch (authorization epochs are one-based) and a `signed_at`
/// that is not a real calendar moment.
///
/// # Errors
/// [`CliError::registered`] with the `envelope.malformed` code (exit 65)
/// for every content refusal; nothing about the offending input is
/// echoed (CFG-027).
pub fn parse_draft(bytes: &[u8]) -> Result<RevocationDraft, CliError> {
    const MALFORMED: CliError = CliError::registered(MALFORMED_DRAFT);
    let Value::Object(object) = json::parse(bytes).map_err(|_| MALFORMED)? else {
        return Err(MALFORMED);
    };
    if object.len() != DRAFT_MEMBERS.len() {
        return Err(MALFORMED);
    }
    for name in &DRAFT_MEMBERS {
        if !object.contains(name) {
            return Err(MALFORMED);
        }
    }
    if text_member(&object, "schema") != Some(DRAFT_SCHEMA) {
        return Err(MALFORMED);
    }
    let tenant_id = TenantId::parse(text_member(&object, "tenant_id").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    let client_id = ClientId::parse(text_member(&object, "client_id").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    let revoked_key_id = KeyId::parse(text_member(&object, "revoked_key_id").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    let revoke_epoch = match object.get("authorization_epoch") {
        Some(Value::Int(value)) if *value >= 1 => u64::try_from(*value).map_err(|_| MALFORMED)?,
        _ => return Err(MALFORMED),
    };
    let signed_at = Timestamp::parse(text_member(&object, "signed_at").ok_or(MALFORMED)?)
        .map_err(|_| MALFORMED)?;
    if !signed_at.calendar_valid() {
        return Err(MALFORMED);
    }
    Ok(RevocationDraft {
        tenant_id,
        client_id,
        revoke_epoch,
        revoked_key_id,
        signed_at,
    })
}

/// Read one text member, failing closed when it is absent or not text.
fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use archivist_client_core::cli::parse::{self, Parsed};
    use archivist_client_core::cli::registry::Registry;

    use super::*;

    /// The tenant, client, key ID, and instant the committed control
    /// corpus pins for the revocation story (the epoch-1 half of the
    /// client whose revocation it narrates) — synthetic fixture values,
    /// stable across the family's vectors.
    const TENANT: &str = "3e5a1c90-8d24-4f67-a1b9-2c7d6e5f4a30";
    const CLIENT: &str = "c7d8e9f0-1a2b-4c3d-9e4f-5a6b7c8d9e0f";
    const REVOKED_KEY: &str = "b45bc7eac06b13093f8393659f7ee2bccba27eea25896a24ab42bce2b53790a6";
    const SIGNED_AT: &str = "2026-09-13T02:00:00Z";

    /// The golden draft document: exactly the closed member set, every
    /// member inside its grammar.
    fn golden() -> Vec<u8> {
        format!(
            "{{\"authorization_epoch\":1,\"client_id\":\"{CLIENT}\",\
             \"revoked_key_id\":\"{REVOKED_KEY}\",\"schema\":\"{DRAFT_SCHEMA}\",\
             \"signed_at\":\"{SIGNED_AT}\",\"tenant_id\":\"{TENANT}\"}}"
        )
        .into_bytes()
    }

    /// `golden()` with its parsed object handed to `edit` and rendered
    /// back to canonical bytes — the malformed-document fixtures below
    /// are one edit away from the golden draft each.
    fn rewritten(edit: impl FnOnce(&mut Object)) -> Vec<u8> {
        let Value::Object(mut object) = json::parse(&golden()).expect("the golden draft parses")
        else {
            panic!("the golden draft is an object");
        };
        edit(&mut object);
        Value::Object(object).canonical_bytes()
    }

    /// Assert one document refuses as the registered malformed draft:
    /// the registered code, the `request_invalid` class exit, and — by
    /// construction of the error path — no document for the router.
    fn assert_malformed(bytes: &[u8]) {
        let error = parse_draft(bytes).expect_err("a malformed draft refuses");
        assert_eq!(error.code(), MALFORMED_DRAFT, "{bytes:?}");
        assert_eq!(error.exit_code(), 65, "{bytes:?}");
    }

    #[test]
    fn valid_draft_parses_into_the_command_draft_type() {
        let draft = parse_draft(&golden()).expect("the golden draft parses");
        assert_eq!(draft.tenant_id().as_str(), TENANT);
        assert_eq!(draft.client_id().as_str(), CLIENT);
        assert_eq!(draft.revoked_key_id().to_hex(), REVOKED_KEY);
        assert_eq!(draft.revoke_epoch(), 1);
        assert_eq!(draft.signed_at().as_str(), SIGNED_AT);
    }

    #[test]
    fn documents_that_are_not_objects_refuse() {
        assert_malformed(b"not json");
        assert_malformed(b"[1]");
        assert_malformed(b"null");
    }

    #[test]
    fn member_sets_outside_the_closed_shape_refuse() {
        // An extra member is a malformed draft, not a smuggled payload.
        assert_malformed(&rewritten(|object| object.set("extra", Value::Int(1))));
        // A missing member is malformed — every one of them.
        for name in [
            "schema",
            "tenant_id",
            "client_id",
            "revoked_key_id",
            "authorization_epoch",
            "signed_at",
        ] {
            assert_malformed(&rewritten(|object| {
                let _ = object.remove(name);
            }));
        }
        // A non-text member where a grammar member belongs.
        assert_malformed(&rewritten(|object| object.set("tenant_id", Value::Int(17))));
    }

    #[test]
    fn a_foreign_namespace_refuses() {
        assert_malformed(&rewritten(|object| {
            object.set("schema", text("archivist.control/v1"));
        }));
    }

    #[test]
    fn member_grammar_failures_refuse() {
        for (name, value) in [
            ("tenant_id", "not-a-uuid"),
            ("client_id", "not-a-uuid"),
            ("revoked_key_id", "zz"),
            ("signed_at", "not-an-instant"),
        ] {
            assert_malformed(&rewritten(|object| object.set(name, text(value))));
        }
    }

    #[test]
    fn a_zero_or_negative_epoch_refuses() {
        // Authorization epochs are one-based: zero was never established,
        // and the publication refuses it as MalformedInput — the same
        // refusal, decided here before anything downstream runs.
        assert_malformed(&rewritten(|object| {
            object.set("authorization_epoch", Value::Int(0));
        }));
        assert_malformed(&rewritten(|object| {
            object.set("authorization_epoch", Value::Int(-1));
        }));
    }

    #[test]
    fn a_calendar_invalid_instant_refuses() {
        // The RFC 3339 grammar alone accepts 2026-02-30; VAL-002's
        // semantic check refuses it, and the publication would refuse it
        // as MalformedInput — the same refusal, decided here.
        assert_malformed(&rewritten(|object| {
            object.set("signed_at", text("2026-02-30T00:00:00Z"));
        }));
    }

    #[test]
    fn a_non_integer_epoch_refuses() {
        assert_malformed(&rewritten(|object| {
            object.set("authorization_epoch", text("1"));
        }));
    }

    /// An invocation of the real command over the real registry, with the
    /// draft path as its operand and the non-interactive mode declared.
    fn invocation(draft_path: Option<&str>) -> Invocation {
        let mut args = vec![
            "--non-interactive".to_owned(),
            "admin".to_owned(),
            "revoke".to_owned(),
        ];
        if let Some(path) = draft_path {
            args.push(path.to_owned());
        }
        let args = args
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>();
        let registry = Registry::pinned();
        match parse::parse(&args, registry).expect("the invocation parses") {
            Parsed::Command(invocation) => invocation,
            other => panic!("the parser returned {other:?} for a command invocation"),
        }
    }

    /// A canonical text value, for the malformed-document fixtures.
    fn text(value: &str) -> Value {
        Value::Text(value.to_owned())
    }

    /// A process-unique scratch path, so concurrent tests never collide.
    fn scratch_name(what: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "archivist-revoke-{}-{}-{}.tmp",
            what,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[test]
    fn read_draft_parses_the_operand_path_document() {
        let path = scratch_name("draft");
        std::fs::write(&path, golden()).expect("the scratch draft writes");
        let draft = read_draft(&invocation(Some(
            path.to_str().expect("utf-8 scratch path"),
        )))
        .expect("the operand draft parses");
        std::fs::remove_file(&path).expect("the scratch draft removes");
        assert_eq!(draft.client_id().as_str(), CLIENT);
        assert_eq!(draft.revoke_epoch(), 1);
    }

    #[test]
    fn read_draft_refuses_a_missing_operand_with_usage() {
        // The registry's `operand = "path"` grammar accepts a bare
        // command, so the operand guard is the command's own refusal.
        let error = read_draft(&invocation(None)).expect_err("a bare command refuses");
        assert_eq!(error.code(), CliError::usage().code());
        assert_eq!(error.exit_code(), 64);
    }

    #[test]
    fn read_draft_refuses_an_unreadable_operand_with_usage() {
        let path = scratch_name("absent");
        let error = read_draft(&invocation(Some(
            path.to_str().expect("utf-8 scratch path"),
        )))
        .expect_err("an unreadable operand refuses");
        assert_eq!(error.code(), CliError::usage().code());
        assert_eq!(error.exit_code(), 64);
    }
}
