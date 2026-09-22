// SPDX-License-Identifier: Apache-2.0

//! The `admin revoke` command (plan Phase 3): the operand document read,
//! shaped, and grammar-checked into the draft ([`parse_draft`],
//! [`read_draft`]), and the signing-and-persistence act that consumes it
//! ([`revoke_over`]) — the client's standing pointer verified, the
//! revocation signed with the tenant authority, and the signed record
//! published through the offline administration store.
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
//! epoch rules exist to check.
//!
//! The signing act's decision, recorded here and on the deliverable's
//! bead: the act reads the pointer from the control plane through the
//! administration store's own request seam
//! ([`ControlAdminBackend::get_control_object`] at the derived
//! linked-client key), and verifies it from the pinned authority root
//! before the epoch rules consume it. The seam ride-along is the
//! discipline `admin approve` established for its authority-chain walk —
//! the signing act reads the same plane its publication writes through,
//! so the epoch rules decide against exactly the state the record will
//! land in and the two transports can never disagree. A dedicated
//! control-read transport
//! ([`S3ControlReadStore`](archivist_storage_s3::control_read::S3ControlReadStore))
//! would observe a second credential and a second configuration the
//! command's registry entry does not declare, and it deliberately
//! verifies nothing;
//! the verification is what makes the view standing state rather than
//! bytes, so it happens here either way. A client with no stored pointer
//! has nothing to revoke against: the corpus folds the absent standing
//! pointer into its `epoch-unreached` class, and the act refuses with the
//! same registered code.
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
//! | The draft names a tenant other than the administration configuration's | `auth.forbidden` | 78 |
//! | The client has no standing pointer, or the draft names an epoch above it | `auth.epoch_unreached` | 65 |
//! | The draft names the pointer's current epoch with a half the pointer does not hold | `auth.key_id_mismatch` | 65 |
//! | The stored pointer does not verify from the pinned root | `storage.integrity_conflict` | 80 |
//! | The store refuses the write (the epoch's key holds different bytes) | `storage.integrity_conflict` | 80 |
//! | The administration transport is unreachable | `transport.connection_failed` | 75 |
//! | A required configuration key resolved from no tier | `cli.decision_missing` | 64 |
//! | The configuration is unusable, or the credential split is violated | `cli.usage_error` | 64 |
//! | The seed reference did not resolve to protected material | `client.secret_ref_refused` | 64 |
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
//!
//! # Where the binary attaches this
//!
//! [`CommandHandler`](archivist_client_core::cli::CommandHandler) is a
//! plain function pointer, so the handler the binary registers names one
//! concrete administration backend; [`run`] is the function it wraps, and
//! the registration and result envelope are the wiring deliverable's to
//! attach. The behavior itself is complete and proven here over the seam.

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::ed25519;
use archivist_auth::revocation::{LinkedClientPointer, PublicationError, publish_revocation};
use archivist_client_core::cli::{CliError, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{ClientId, Ed25519PublicKey, KeyId, TenantId, Timestamp};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage_s3::config::{S3ConfigError, S3ConfigErrorKind};
use archivist_storage_s3::control_admin::{ControlAdminBackend, ControlObjectKey};

/// The registered code for a presented document that is not a revocation
/// draft the command could act on (`tools/error-codes.toml`, class
/// `request_invalid`) — the draft refusal code the `admin approve`
/// command carries, and the code
/// [`PublicationError::MalformedInput`](archivist_auth::revocation::PublicationError::MalformedInput)
/// surfaces as.
const MALFORMED_DRAFT: &str = "envelope.malformed";

/// The registered configuration key naming the tenant authority's signing
/// seed (`tools/config-keys.toml`).
const AUTHORITY_SEED_KEY: &str = "admin.authority_seed_ref";

/// The registered code for a draft naming a tenant other than the one the
/// administration configuration pins (`tools/error-codes.toml`, class
/// `authorization`).
const CROSS_TENANT: &str = "auth.forbidden";

/// The registered code for a revocation the client's standing pointer
/// cannot have reached (`tools/error-codes.toml`, class
/// `request_invalid`) — the corpus's `epoch-unreached` rejection class,
/// registered here for the administrator act that refuses it.
const EPOCH_UNREACHED: &str = "auth.epoch_unreached";

/// The registered code for a revocation naming the standing pointer's
/// current epoch with a half the pointer does not hold
/// (`tools/error-codes.toml`, class `request_invalid`) — the corpus's
/// `key-id-mismatch` rejection class, registered here for the
/// administrator act that refuses it.
const KEY_ID_MISMATCH: &str = "auth.key_id_mismatch";

/// The registered code for stored control state that contradicts the act
/// (`tools/error-codes.toml`, class `integrity_conflict`).
const INTEGRITY_CONFLICT: &str = "storage.integrity_conflict";

/// The registered code for a transport-level failure with no HTTP
/// response (`tools/error-codes.toml`, class `network`).
const TRANSPORT_FAILED: &str = "transport.connection_failed";

/// The registered code for a required configuration field that resolved
/// from no tier (`tools/error-codes.toml`, class `usage`).
const DECISION_MISSING: &str = "cli.decision_missing";

/// The registered code for a secret reference that did not resolve to
/// protected material (`tools/error-codes.toml`, class `usage`, CFG-030).
const SECRET_REF_REFUSED: &str = "client.secret_ref_refused";

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

/// Run one `admin revoke` invocation over the given administration
/// backend: capture the invocation's environment into the configuration
/// snapshot, load the fully-resolved configuration, and perform the
/// command.
///
/// This is the composition point a handler function pointer wraps; the
/// backend is whatever administration transport the composing phase
/// supplies.
///
/// # Errors
/// The registered refusal of the first failing act: configuration
/// acquisition, composition, draft parsing, tenant agreement, pointer
/// verification, signing, or publication.
pub fn run<B: ControlAdminBackend + Sync>(
    invocation: &Invocation,
    backend: B,
) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(|error| config_fault(&error))?;
    let resolved = sources.load().map_err(|error| config_fault(&error))?;
    revoke_over(&resolved, invocation, backend)
}

/// Perform the command over an already-resolved configuration: read the
/// operand draft, verify the client's standing pointer, sign the
/// revocation with the tenant authority, publish it through the offline
/// store, and return the revocation record document.
///
/// `resolved` is the invocation's fully-resolved configuration — the same
/// value [`run`] loads. Split from it so the behavior is provable over a
/// synthetic configuration the way the composition helper's own tests
/// are, without touching the process environment.
///
/// The administration plane is composed exactly as every `admin` command
/// composes it ([`crate::admin::compose_admin_control_plane`]): the store
/// is assembled from the administration configuration alone, with the
/// ingest/administration credential split enforced before any store
/// exists, and the seed is resolved here, at the signing act, under the
/// protected-material checks (CFG-030, SEC-006) — never at composition.
///
/// The pointer view is the act's recorded decision (the module docs carry
/// it): read through the administration store's own request seam at the
/// derived linked-client key, then verified from the pinned root. The
/// epoch rules therefore decide against the same plane the publication
/// writes through.
///
/// # Errors
/// The registered refusal of the first failing act — composition, draft
/// parsing, tenant agreement, seed resolution, pointer read or
/// verification, signing, or publication; each refusal leaves stdout
/// empty because nothing has been returned to the router.
pub fn revoke_over<B: ControlAdminBackend + Sync>(
    resolved: &ResolvedConfig,
    invocation: &Invocation,
    backend: B,
) -> Result<Value, CliError> {
    // The administration plane: the composition helper enforces the
    // authority split before any store exists (the composition child's
    // contract), and carries the seed as the unresolved reference it is.
    let plane =
        crate::admin::compose_admin_control_plane(resolved, backend).map_err(composition_fault)?;

    // The draft: the operand path's bytes, parsed into the validated
    // members. Every document-content refusal is already decided here,
    // before any control-plane act runs.
    let draft = read_draft(invocation)?;

    // The draft's tenant must be the tenant this administration plane
    // acts for: the seed resolves that tenant's authority, and a record
    // signed across that line would verify for no one. The store's own
    // scope check would refuse the write; refusing here names the
    // registered cross-tenant condition before anything is signed.
    let tenant = plane.store().config().tenant().clone();
    if draft.tenant_id() != &tenant {
        return Err(CliError::registered(CROSS_TENANT));
    }

    // The seed: resolved now, at the signing act, under the protected-
    // material checks (CFG-030). Exactly the 32 bytes an Ed25519 signing
    // seed is; anything else is a reference that did not resolve to the
    // protected material the key declares.
    let secret = resolved
        .resolve_secret(AUTHORITY_SEED_KEY)
        .map_err(|error| config_fault(&error))?;
    let seed: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| CliError::registered(SECRET_REF_REFUSED))?;

    // The pinned root: the tenant the administration configuration pins,
    // and the public half the seed derives — the deployment's own anchor,
    // the same one `admin approve` signs and every reader verifies from.
    let root = PinnedAuthorityRoot::new(
        tenant.clone(),
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&seed)),
    );

    // One runtime drives the async acts; the verification fetch runs
    // while no other block is outstanding, so nesting is impossible.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::internal())?;

    // The pointer view: read through the same seam the publication will
    // write through, at the derived linked-client key — then verified
    // from the pinned root, so the epoch rules decide against verified
    // standing state and not merely stored bytes. An absent pointer is
    // the corpus's `epoch-unreached` class (there is no epoch the client
    // holds, so none the draft could name); a pointer that fails
    // verification is stored state the act must not build on, the
    // stop-and-page-operator class.
    let pointer_key = ControlObjectKey::linked_client(&tenant, draft.client_id());
    let pointer = match runtime.block_on(plane.store().backend().get_control_object(&pointer_key)) {
        Ok(Some(bytes)) => {
            let fetch = |key_id: &KeyId| {
                let key = ControlObjectKey::authority_rotation(&tenant, key_id);
                runtime
                    .block_on(plane.store().backend().get_control_object(&key))
                    .ok()
                    .flatten()
            };
            LinkedClientPointer::verify(&root, &bytes, fetch, draft.client_id())
                .map_err(|_| CliError::registered(INTEGRITY_CONFLICT))?
        }
        Ok(None) => return Err(CliError::registered(EPOCH_UNREACHED)),
        Err(error) => return Err(transport_fault(error)),
    };

    // Sign. The two epoch rules are the publication's own; each surfaces
    // as its registered code. The publication is deterministic in the
    // draft's members: the same draft signs the same bytes, which is what
    // makes the store's identical-bytes replay an idempotent repair.
    let publication = publish_revocation(
        &seed,
        &tenant,
        draft.client_id(),
        draft.revoke_epoch(),
        draft.revoked_key_id(),
        &pointer,
        draft.signed_at(),
    )
    .map_err(publication_fault)?;

    // Publish through the offline store: the signed immutable record at
    // its derived revocation key, with the immutable class's write rules
    // — including the byte-identical replay — the store already enforces.
    runtime
        .block_on(plane.store().put_revocation(&publication))
        .map_err(storage_fault)?;

    // The result document is the record itself, parsed back from its
    // canonical bytes; the router frames it (bare document, or the output
    // envelope under `--json`). The registration and framing are the
    // wiring deliverable's.
    json::parse(publication.envelope()).map_err(|_| CliError::internal())
}

/// Map a configuration condition onto its registered CLI code: the code
/// the loader chose already names the registered condition (CLI-002).
fn config_fault(error: &ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

/// Map a composition refusal onto the usage family, exactly as the
/// approve command maps it: a configuration that cannot assemble into a
/// working administration plane is a fix-the-invocation condition (exit
/// 64) whatever the concrete diagnostic, and a missing setting is its own
/// registered code.
fn composition_fault(error: S3ConfigError) -> CliError {
    match error.kind() {
        S3ConfigErrorKind::MissingSetting => CliError::registered(DECISION_MISSING),
        S3ConfigErrorKind::MalformedSetting
        | S3ConfigErrorKind::TransportMismatch
        | S3ConfigErrorKind::DuplicateIdentity => CliError::usage(),
    }
}

/// Map the publication's own refusals onto their registered codes: the
/// two epoch rules are the corpus's rejection classes, registered for
/// this act, and a malformed member is the draft refusal code — the parse
/// has already refused the two member conditions that reach it, so this
/// surface is defense in depth.
fn publication_fault(error: PublicationError) -> CliError {
    match error {
        PublicationError::MalformedInput => CliError::registered(MALFORMED_DRAFT),
        PublicationError::EpochUnreached => CliError::registered(EPOCH_UNREACHED),
        PublicationError::KeyIdMismatch => CliError::registered(KEY_ID_MISMATCH),
    }
}

/// Map a control-plane read or write that failed below the record rules
/// onto its registered code: an unreachable transport is its own class,
/// and every other kind is a store invariant this act's construction
/// already satisfies, refused as internal rather than guessed at.
fn transport_fault(error: StorageError) -> CliError {
    match error.kind() {
        StorageErrorKind::Unavailable | StorageErrorKind::CapabilityUnavailable => {
            CliError::registered(TRANSPORT_FAILED)
        }
        _ => CliError::internal(),
    }
}

/// Map the store's write refusal onto its registered code: the one
/// refusal the immutable class produces beyond a down transport is stored
/// state the write cannot displace — an occupied epoch key holding
/// different bytes — which is the integrity class; every other kind is a
/// store invariant this act's construction already satisfies.
fn storage_fault(error: StorageError) -> CliError {
    match error.kind() {
        StorageErrorKind::StaleEpoch | StorageErrorKind::IntegrityConflict => {
            CliError::registered(INTEGRITY_CONFLICT)
        }
        StorageErrorKind::Unavailable | StorageErrorKind::CapabilityUnavailable => {
            CliError::registered(TRANSPORT_FAILED)
        }
        _ => CliError::internal(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::Permissions;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::sync::{Arc, Mutex};

    use archivist_auth::identity::InstallationIdentity;
    use archivist_auth::link::{LinkRequest, RequestedScopes, ScopeOperation};
    use archivist_auth::revocation::RevocationRecord;
    use archivist_client_core::cli::parse::{self, Parsed};
    use archivist_client_core::cli::registry::Registry;
    use archivist_client_core::config::ConfigSources;
    use archivist_protocol::vocabulary::{Ed25519PublicKey, HarnessId};

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

    // -------------------------------------------------------------------
    // The sign-and-persist act ([`revoke_over`]), over the mock
    // `ControlAdminBackend` seam. The store-level replay idempotence is
    // the control-admin store's own contract (aa-e3097744) and is only
    // ridden here, not re-proven.
    // -------------------------------------------------------------------

    /// The signing authority's seed (synthetic fixture, stable across the
    /// family's vectors) and the client seed whose public half the linked
    /// story's standing pointer certifies.
    const AUTHORITY_SEED: [u8; 32] = [0x17; 32];
    const CLIENT_SEED: [u8; 32] = [0x2a; 32];

    /// A second valid tenant, for the cross-tenant refusal.
    const OTHER_TENANT: &str = "00000000-1111-4222-8333-444444444444";

    fn tenant_id() -> TenantId {
        TENANT.parse().expect("grammar")
    }

    fn client_id() -> ClientId {
        CLIENT.parse().expect("grammar")
    }

    /// The key ID a seed's public half derives — the pinned derivation
    /// every record's `key_id` member must agree with.
    fn key_hex_of(seed: &[u8; 32]) -> String {
        KeyId::from_public_key(&Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(
            seed,
        )))
        .to_hex()
    }

    /// The standing half the fixture's linked-client pointer certifies:
    /// the derivation of the client seed's public half.
    fn standing_half() -> String {
        key_hex_of(&CLIENT_SEED)
    }

    /// A canonical draft document with the fixture's tenant, client, and
    /// instant, and the caller's epoch and revoked key.
    fn act_draft(epoch: u64, revoked_key_hex: &str) -> Vec<u8> {
        act_draft_for(TENANT, epoch, revoked_key_hex)
    }

    /// [`act_draft`] naming an explicit tenant, for the cross-tenant
    /// refusal.
    fn act_draft_for(tenant: &str, epoch: u64, revoked_key_hex: &str) -> Vec<u8> {
        let mut object = Object::new();
        object.set("schema", text(DRAFT_SCHEMA));
        object.set("tenant_id", text(tenant));
        object.set("client_id", text(CLIENT));
        object.set("revoked_key_id", text(revoked_key_hex));
        let epoch_member = i64::try_from(epoch).expect("a fixture epoch fits");
        object.set("authorization_epoch", Value::Int(epoch_member));
        object.set("signed_at", text(SIGNED_AT));
        Value::Object(object).canonical_bytes()
    }

    /// The link-request document the approve command signs to create the
    /// fixture's standing pointer: the client seed's public identity for
    /// this tenant, ingest scope.
    fn link_draft_document() -> Vec<u8> {
        let identity =
            InstallationIdentity::from_seed(client_id(), CLIENT_SEED, public_of(&CLIENT_SEED))
                .expect("derives");
        let scopes = RequestedScopes::new(
            vec![HarnessId::parse("claude-code").expect("grammar")],
            vec![ScopeOperation::Ingest],
        )
        .expect("an in-bounds scope");
        LinkRequest::new(identity.public_identity(), tenant_id(), scopes).canonical_bytes()
    }

    fn public_of(seed: &[u8; 32]) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(seed))
    }

    /// The backend seam: map-backed, shared with the test through a clone
    /// so the test seeds the standing pointer and inspects what the act
    /// wrote. The seam also models the deployment policy a credential
    /// carries: the administration credential's profile grants the
    /// control prefix, and the ingest credential's profile denies every
    /// key below it.
    #[derive(Debug, Default, Clone)]
    struct ActBackend {
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        /// Whether this seam's policy is the ingest credential's: every
        /// key below the control prefix denied, everything else granted.
        ingest_scoped: bool,
        /// Every control-prefix key the policy refused, in request order.
        refusals: Arc<Mutex<Vec<String>>>,
    }

    impl ActBackend {
        /// The seam an ingest-scoped credential drives: the deployment
        /// policy denies the control prefix outright, and the mock grants
        /// everything else, so any out-of-prefix write the act attempted
        /// would land bytes and be seen.
        fn ingest_scoped() -> Self {
            Self {
                ingest_scoped: true,
                ..Self::default()
            }
        }

        /// The deployment policy over one object key: the ingest
        /// credential's profile denies the control prefix with the
        /// refusal the seam contract states for a key outside the
        /// credential's provisioned scope.
        fn policy_permits(&self, key: &str) -> Result<(), StorageError> {
            let prefix = format!("tenants/{TENANT}/v1/control/");
            if self.ingest_scoped && key.starts_with(&prefix) {
                self.refusals
                    .lock()
                    .expect("test backend lock")
                    .push(key.to_owned());
                return Err(StorageError::of_kind(StorageErrorKind::ScopeViolation));
            }
            Ok(())
        }
    }

    impl ControlAdminBackend for ActBackend {
        async fn get_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            self.policy_permits(key.as_str())?;
            Ok(self
                .objects
                .lock()
                .expect("test backend lock")
                .get(key.as_str())
                .cloned())
        }

        async fn put_control_object(
            &self,
            key: &ControlObjectKey,
            envelope: &[u8],
        ) -> Result<(), StorageError> {
            self.policy_permits(key.as_str())?;
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), envelope.to_vec());
            Ok(())
        }
    }

    /// A backend whose transport is down, for the transport-fault mapping.
    #[derive(Debug, Default)]
    struct DownBackend;

    impl ControlAdminBackend for DownBackend {
        async fn get_control_object(
            &self,
            _key: &ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }

        async fn put_control_object(
            &self,
            _key: &ControlObjectKey,
            _envelope: &[u8],
        ) -> Result<(), StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }
    }

    /// The synthetic environment of a fully-declared host, mirroring the
    /// composition fixture: every required key through the snapshot's
    /// environment tier, the administration credential a never-resolved
    /// `env:` target, and the authority seed a protected file the fixture
    /// writes.
    fn base_sources(seed_ref: &str) -> ConfigSources {
        ConfigSources::non_interactive()
            .env("HOME", "/home/operator")
            .env(
                "ARCHIVIST_INGEST_ENDPOINT_URL",
                "https://ingest.example.invalid",
            )
            .env(
                "ARCHIVIST_STORAGE_ENDPOINT_URL",
                "https://s3.example.invalid",
            )
            .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
            .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
            .env("ARCHIVIST_STORAGE_RAW_BUCKET", "archivist-raw-example")
            .env(
                "ARCHIVIST_STORAGE_CONTROL_BUCKET",
                "archivist-control-example",
            )
            .env(
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
                "env:TEST_RAW_CREDENTIAL",
            )
            .env(
                "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
                "env:TEST_CONTROL_CREDENTIAL",
            )
            .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087")
            .env(
                "ARCHIVIST_ADMIN_ENDPOINT_URL",
                "https://control.example.invalid",
            )
            .env("ARCHIVIST_ADMIN_REGION", "us-east-1")
            .env(
                "ARCHIVIST_ADMIN_CONTROL_BUCKET",
                "archivist-control-example",
            )
            .env("ARCHIVIST_ADMIN_TENANT", TENANT)
            .env(
                "ARCHIVIST_ADMIN_CREDENTIALS_REF",
                "env:TEST_ADMIN_CREDENTIAL",
            )
            .env("ARCHIVIST_ADMIN_AUTHORITY_SEED_REF", seed_ref)
    }

    /// Write `bytes` to a process-unique scratch path and return the bare
    /// path — the form an operand or a reference target takes.
    fn write_scratch(what: &str, bytes: &[u8], mode: u32) -> std::path::PathBuf {
        let path = scratch_name(what);
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .expect("scratch file creates");
        std::fs::write(&path, bytes).expect("scratch bytes write");
        std::fs::set_permissions(&path, Permissions::from_mode(mode))
            .expect("scratch file tightens");
        path
    }

    /// Write a protected authority-seed file (mode 0600) and return the
    /// canonical `file:` reference text the configuration tier carries.
    fn protected_seed_ref(bytes: &[u8]) -> String {
        let path = write_scratch("seed", bytes, 0o600);
        format!("file:{}", path.display())
    }

    /// Remove a scratch path a fixture wrote.
    fn remove_scratch(path: &std::path::Path) {
        std::fs::remove_file(path).expect("scratch file removes");
    }

    /// Remove the seed file a `file:` reference names (the reference's
    /// own target, so the text is safe to parse here).
    fn remove_seed_ref(seed_ref: &str) {
        let path = seed_ref.strip_prefix("file:").expect("file reference");
        remove_scratch(std::path::Path::new(path));
    }

    /// An invocation of the `admin approve` command over the real
    /// registry, with the link-request path as its operand — the fixture
    /// publishes the standing pointer through the approve command's own
    /// act, so the revocation act decides against a genuinely published
    /// pointer.
    fn approve_invocation(draft_path: &str) -> Invocation {
        let args = [
            "--non-interactive".to_owned(),
            "admin".to_owned(),
            "approve".to_owned(),
            draft_path.to_owned(),
        ];
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

    /// The derived key the fixture's standing pointer sits at.
    fn pointer_key() -> String {
        ControlObjectKey::linked_client(&tenant_id(), &client_id())
            .as_str()
            .to_owned()
    }

    /// The derived key the fixture's epoch-1 revocation lands at.
    fn revocation_key() -> String {
        archivist_auth::revocation::revocation_object_key(&tenant_id(), &client_id(), 1)
    }

    /// A snapshot of the seam's objects, for unchanged-store assertions.
    fn snapshot(backend: &ActBackend) -> BTreeMap<String, Vec<u8>> {
        backend.objects.lock().expect("test backend lock").clone()
    }

    /// Create the fixture's standing pointer by publishing the approve
    /// command's own linked-client record: the act under test then
    /// decides against a pointer that genuinely landed through the same
    /// plane it writes through.
    fn publish_standing_pointer(resolved: &ResolvedConfig, backend: &ActBackend) {
        let link_path = write_scratch("link", &link_draft_document(), 0o600);
        let link_operand = link_path.to_str().expect("utf-8 scratch path");
        crate::approve::approve_over(resolved, &approve_invocation(link_operand), backend.clone())
            .expect("the fixture link publishes");
        remove_scratch(&link_path);
    }

    #[test]
    fn valid_draft_signs_and_persists_the_revocation_end_to_end() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let document = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect("the golden draft signs and persists");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        // The emitted document is the revocation record: exactly the
        // members the signing act builds, carrying this draft's act.
        let Value::Object(ref members) = document else {
            panic!("the result document is an object");
        };
        let required: &[&str] = &[
            "authority_key_id",
            "authority_signature",
            "authorization_epoch",
            "client_id",
            "record_kind",
            "record_type",
            "revoked_key_id",
            "schema",
            "signed_at",
            "tenant_id",
        ];
        assert_eq!(members.len(), required.len(), "the record is closed");
        for name in required {
            assert!(members.get(name).is_some(), "the record names {name}");
        }
        assert!(
            matches!(members.get("schema"), Some(Value::Text(token)) if token == "archivist.control/v1")
        );
        assert!(
            matches!(members.get("record_type"), Some(Value::Text(token)) if token == "revocation")
        );
        assert!(
            matches!(members.get("record_kind"), Some(Value::Text(token)) if token == "immutable")
        );
        assert!(matches!(
            members.get("authorization_epoch"),
            Some(Value::Int(1))
        ));
        assert!(
            matches!(members.get("revoked_key_id"), Some(Value::Text(token)) if *token == standing_half())
        );

        // The store holds the record at its derived key, and it verifies
        // from the pinned root the way a reader would.
        let stored = backend
            .objects
            .lock()
            .expect("test backend lock")
            .get(&revocation_key())
            .cloned()
            .expect("the record published");
        let root = PinnedAuthorityRoot::new(tenant_id(), public_of(&AUTHORITY_SEED));
        let no_links = |_: &KeyId| None;
        RevocationRecord::verify(&root, &stored, no_links, &client_id(), 1)
            .expect("the stored record verifies from the pinned root");
    }

    /// The lost-response retry of one administrative revoke: the same
    /// draft signs the same bytes, and the store's identical-bytes rule
    /// lands the replay as an idempotent repair — the second act succeeds
    /// and the seam is byte-for-byte unchanged.
    #[test]
    fn replayed_revocation_is_the_idempotent_repair() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let first = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect("the first act publishes");
        let before = snapshot(&backend);
        let second = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect("the replay repairs idempotently");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        // Deterministic signing: the replay's document is byte-identical,
        // and the store holds exactly what it held.
        assert_eq!(
            Value::Object(match first {
                Value::Object(members) => members,
                other => panic!("the first document is an object, got {other:?}"),
            })
            .canonical_bytes(),
            Value::Object(match second {
                Value::Object(members) => members,
                other => panic!("the replay document is an object, got {other:?}"),
            })
            .canonical_bytes(),
        );
        assert_eq!(snapshot(&backend), before);
    }

    /// A draft naming an epoch above the standing pointer refuses through
    /// the registered unreached code, and nothing is written.
    #[test]
    fn an_epoch_above_the_pointer_refuses_with_the_unreached_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(5, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a forward-dated revocation refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), EPOCH_UNREACHED);
        assert_eq!(error.exit_code(), 65);
        // Only the standing pointer is in the seam; no revocation landed.
        let objects = snapshot(&backend);
        assert_eq!(objects.len(), 1, "only the pointer is stored");
        assert!(objects.contains_key(&pointer_key()));
    }

    /// A draft naming the pointer's current epoch with a half the pointer
    /// does not hold refuses through the registered mismatch code, and
    /// nothing is written.
    #[test]
    fn a_foreign_half_at_the_current_epoch_refuses_with_the_mismatch_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let foreign = key_hex_of(&[0x99; 32]);
        let draft_path = write_scratch("draft", &act_draft(1, &foreign), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a mismatched half refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), KEY_ID_MISMATCH);
        assert_eq!(error.exit_code(), 65);
        let objects = snapshot(&backend);
        assert_eq!(objects.len(), 1, "only the pointer is stored");
        assert!(objects.contains_key(&pointer_key()));
    }

    /// A client with no standing pointer has no epoch the draft could
    /// name: the corpus folds the absent pointer into its
    /// `epoch-unreached` class, and the act refuses with the same
    /// registered code.
    #[test]
    fn a_revocation_without_a_standing_pointer_refuses_as_unreached() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("an unlinked client refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), EPOCH_UNREACHED);
        assert_eq!(error.exit_code(), 65);
        assert!(snapshot(&backend).is_empty());
    }

    /// A draft naming a tenant other than the administration
    /// configuration's refuses through the registered cross-tenant code
    /// before anything is signed.
    #[test]
    fn a_cross_tenant_draft_refuses_with_the_forbidden_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        let draft_path = write_scratch(
            "draft",
            &act_draft_for(OTHER_TENANT, 1, &standing_half()),
            0o600,
        );
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a cross-tenant draft refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), CROSS_TENANT);
        assert_eq!(error.exit_code(), 78);
        assert!(snapshot(&backend).is_empty());
    }

    /// An unreachable administration transport refuses through the
    /// registered transport code at the pointer read, before anything is
    /// signed.
    #[test]
    fn a_transport_that_cannot_read_refuses_with_the_transport_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), DownBackend)
            .expect_err("a down transport refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), TRANSPORT_FAILED);
        assert_eq!(error.exit_code(), 75);
    }

    /// A stored pointer that fails verification from the pinned root is
    /// stored state the act must not build on: the integrity class, with
    /// nothing signed and nothing written.
    #[test]
    fn a_pointer_that_fails_verification_refuses_with_the_integrity_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        // Corrupt the standing pointer in place: shape-plausible bytes
        // that are not a linked-client record the root stands behind.
        backend.objects.lock().expect("test backend lock").insert(
            pointer_key(),
            b"{\"schema\":\"archivist.control/v1\"}".to_vec(),
        );
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a corrupt pointer refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), INTEGRITY_CONFLICT);
        assert_eq!(error.exit_code(), 80);
        // The corrupted pointer is the only object; nothing was written.
        assert_eq!(snapshot(&backend).len(), 1);
    }

    /// A malformed draft refuses through the registered document code
    /// before any control-plane act runs — no pointer read, no signing,
    /// nothing written.
    #[test]
    fn a_malformed_draft_refuses_before_any_control_plane_act() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        let draft_path = write_scratch("draft", b"not json", 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a malformed draft refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), MALFORMED_DRAFT);
        assert_eq!(error.exit_code(), 65);
        assert!(snapshot(&backend).is_empty());
    }

    /// A seed reference whose target is not the protected material the
    /// key declares refuses through the registered secret-reference code
    /// before the pointer is read.
    #[test]
    fn a_wrong_length_seed_refuses_with_the_secret_reference_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED[..31]);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = revoke_over(&resolved, &invocation(Some(draft_operand)), backend.clone())
            .expect_err("a wrong-length seed refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), SECRET_REF_REFUSED);
        assert_eq!(error.exit_code(), 64);
        assert!(snapshot(&backend).is_empty());
    }

    #[test]
    fn publication_refusals_map_onto_their_registered_codes() {
        let malformed = publication_fault(PublicationError::MalformedInput);
        assert_eq!(malformed.code(), MALFORMED_DRAFT);
        assert_eq!(malformed.exit_code(), 65);
        let unreached = publication_fault(PublicationError::EpochUnreached);
        assert_eq!(unreached.code(), EPOCH_UNREACHED);
        assert_eq!(unreached.exit_code(), 65);
        let mismatch = publication_fault(PublicationError::KeyIdMismatch);
        assert_eq!(mismatch.code(), KEY_ID_MISMATCH);
        assert_eq!(mismatch.exit_code(), 65);
    }

    #[test]
    fn storage_and_transport_refusals_map_onto_their_registered_codes() {
        let conflict = storage_fault(StorageError::new(
            StorageErrorKind::IntegrityConflict,
            "the epoch key holds other bytes",
        ));
        assert_eq!(conflict.code(), INTEGRITY_CONFLICT);
        assert_eq!(conflict.exit_code(), 80);
        let stale = storage_fault(StorageError::of_kind(StorageErrorKind::StaleEpoch));
        assert_eq!(stale.code(), INTEGRITY_CONFLICT);
        assert_eq!(stale.exit_code(), 80);
        let down = transport_fault(StorageError::of_kind(StorageErrorKind::Unavailable));
        assert_eq!(down.code(), TRANSPORT_FAILED);
        assert_eq!(down.exit_code(), 75);
        let internal = storage_fault(StorageError::of_kind(StorageErrorKind::MalformedInput));
        assert_eq!(internal.code(), CliError::internal().code());
        assert_eq!(internal.exit_code(), 70);
    }

    /// The production entry loads the resolved configuration from the
    /// invocation's sources: an undeclared host refuses at the load with
    /// the decision-missing code, exactly as the approve entry does.
    #[test]
    fn run_loads_the_invocation_configuration_and_drives_the_command() {
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");
        let error = run(&invocation(Some(draft_operand)), ActBackend::default())
            .expect_err("an undeclared host refuses at the load");
        remove_scratch(&draft_path);

        assert_eq!(error.code(), DECISION_MISSING);
        assert_eq!(error.exit_code(), 64);
    }

    // -------------------------------------------------------------------
    // The production entry ([`run`]) over a fully-declared host. The
    // invocation's `--config` file supplies every required key through the
    // file tier, so the entry's own configuration acquisition succeeds and
    // the real command path runs end to end over the seam — the way a
    // deployment actually drives the command. The environment tier is the
    // test process's own and supplies nothing; the file alone declares the
    // host.
    // -------------------------------------------------------------------

    /// Write the fully-declared host configuration file: every required
    /// key through the file tier — plus `client.state_dir`, whose default
    /// is a template on an environment variable the file's own host
    /// declares instead — the administration section pinning this
    /// fixture's tenant and the protected seed reference, the two
    /// credential references distinct — the authority split composition
    /// enforces. This is the file the production entry's `--config`
    /// consumes.
    fn declared_host_config(seed_ref: &str) -> std::path::PathBuf {
        declared_host_config_with_raw_write("env:TEST_RAW_CREDENTIAL", seed_ref)
    }

    /// The declared host with the ingest write role mapped onto the
    /// administration credential's target — the one misdeclaration the
    /// authority split refuses at composition, before any store exists.
    fn declared_host_config_split(seed_ref: &str) -> std::path::PathBuf {
        declared_host_config_with_raw_write("env:TEST_ADMIN_CREDENTIAL", seed_ref)
    }

    /// The host configuration body over one ingest write reference.
    fn declared_host_config_with_raw_write(
        raw_write_ref: &str,
        seed_ref: &str,
    ) -> std::path::PathBuf {
        let path = scratch_name("host-config");
        let body = format!(
            "[ingest]\n\
             endpoint_url = \"https://ingest.example.invalid\"\n\
             [storage]\n\
             endpoint_url = \"https://s3.example.invalid\"\n\
             region = \"us-east-1\"\n\
             encryption = \"s3_sse\"\n\
             raw_bucket = \"archivist-raw-example\"\n\
             control_bucket = \"archivist-control-example\"\n\
             raw_write_credentials_ref = \"{raw_write_ref}\"\n\
             control_read_credentials_ref = \"env:TEST_CONTROL_CREDENTIAL\"\n\
             [server]\n\
             listen_address = \"127.0.0.1:8087\"\n\
             [client]\n\
             state_dir = \"/home/operator/.local/state/archivist\"\n\
             [admin]\n\
             endpoint_url = \"https://control.example.invalid\"\n\
             region = \"us-east-1\"\n\
             control_bucket = \"archivist-control-example\"\n\
             tenant = \"{TENANT}\"\n\
             credentials_ref = \"env:TEST_ADMIN_CREDENTIAL\"\n\
             authority_seed_ref = \"{seed_ref}\"\n"
        );
        std::fs::write(&path, body).expect("the host configuration writes");
        path
    }

    /// An invocation of the production entry over the real registry: the
    /// declared host configuration file in `--config`, the draft path as
    /// the operand, the non-interactive mode declared — the shape an
    /// operator's shell builds.
    fn declared_invocation(config_path: &std::path::Path, draft_path: &str) -> Invocation {
        let args = [
            "--non-interactive".to_owned(),
            "--config".to_owned(),
            config_path.display().to_string(),
            "admin".to_owned(),
            "revoke".to_owned(),
            draft_path.to_owned(),
        ];
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

    /// The real command path runs end to end through the production entry:
    /// with the host declared through the invocation's `--config` file, a
    /// valid draft signs, publishes, and returns the revocation
    /// publication — the document the router frames as the result
    /// envelope — and the stored record re-reads through the control-admin
    /// store and verifies from the pinned root.
    #[test]
    fn run_drives_a_valid_draft_end_to_end_over_the_declared_host() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let resolved = ConfigSources::non_interactive()
            .config_path(host_config.clone())
            .load()
            .expect("the declared host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let document = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect("the declared host drives the golden draft end to end");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        // The result is the revocation publication, carrying this draft's
        // act under the identity tokens the record family pins.
        let Value::Object(ref members) = document else {
            panic!("the result document is an object");
        };
        assert!(
            matches!(members.get("schema"), Some(Value::Text(token)) if token == "archivist.control/v1")
        );
        assert!(
            matches!(members.get("record_type"), Some(Value::Text(token)) if token == "revocation")
        );
        assert!(matches!(
            members.get("authorization_epoch"),
            Some(Value::Int(1))
        ));
        assert!(
            matches!(members.get("revoked_key_id"), Some(Value::Text(token)) if *token == standing_half())
        );

        // The stored record re-reads through the same control-admin store
        // the command wrote through, and verifies from the pinned root the
        // way a reader would.
        let stored = backend
            .objects
            .lock()
            .expect("test backend lock")
            .get(&revocation_key())
            .cloned()
            .expect("the record published");
        let root = PinnedAuthorityRoot::new(tenant_id(), public_of(&AUTHORITY_SEED));
        let no_links = |_: &KeyId| None;
        RevocationRecord::verify(&root, &stored, no_links, &client_id(), 1)
            .expect("the stored record verifies from the pinned root");
    }

    /// The lost-response retry through the production entry: the same
    /// declared host, the same draft — the second `run` succeeds with the
    /// byte-identical publication and the seam is unchanged, the store's
    /// identical-bytes replay (aa-e3097744) ridden at the command level.
    #[test]
    fn run_replays_the_same_draft_as_the_idempotent_repair() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let resolved = ConfigSources::non_interactive()
            .config_path(host_config.clone())
            .load()
            .expect("the declared host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let first = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect("the first act publishes");
        let before = snapshot(&backend);
        let second = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect("the replay repairs idempotently");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        // Deterministic signing: the replay's document is byte-identical,
        // and the store holds exactly what it held.
        let canonical = |document: Value| match document {
            Value::Object(members) => Value::Object(members).canonical_bytes(),
            other => panic!("the result document is an object, got {other:?}"),
        };
        assert_eq!(canonical(first), canonical(second));
        assert_eq!(snapshot(&backend), before);
    }

    /// A malformed draft refuses through the production entry with the
    /// registered document code — the load and composition succeed on the
    /// declared host, the refusal is the command's own, and stdout stays
    /// empty because nothing was returned to the router. Nothing is
    /// written.
    #[test]
    fn run_refuses_a_malformed_draft_with_the_document_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let backend = ActBackend::default();
        let draft_path = write_scratch("draft", b"not json", 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect_err("a malformed draft refuses through the entry");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        assert_eq!(error.code(), MALFORMED_DRAFT);
        assert_eq!(error.exit_code(), 65);
        assert!(snapshot(&backend).is_empty());
    }

    /// A draft naming an epoch above the standing pointer refuses through
    /// the production entry with the registered unreached code, stdout
    /// empty, and nothing is written beyond the pointer itself.
    #[test]
    fn run_refuses_an_epoch_above_the_pointer_with_the_unreached_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let resolved = ConfigSources::non_interactive()
            .config_path(host_config.clone())
            .load()
            .expect("the declared host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(5, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect_err("a forward-dated revocation refuses through the entry");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        assert_eq!(error.code(), EPOCH_UNREACHED);
        assert_eq!(error.exit_code(), 65);
        let objects = snapshot(&backend);
        assert_eq!(objects.len(), 1, "only the pointer is stored");
        assert!(objects.contains_key(&pointer_key()));
    }

    /// A draft naming the pointer's current epoch with a half the pointer
    /// does not hold refuses through the production entry with the
    /// registered mismatch code, stdout empty, and nothing is written.
    #[test]
    fn run_refuses_a_foreign_half_with_the_mismatch_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let resolved = ConfigSources::non_interactive()
            .config_path(host_config.clone())
            .load()
            .expect("the declared host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let foreign = key_hex_of(&[0x99; 32]);
        let draft_path = write_scratch("draft", &act_draft(1, &foreign), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect_err("a mismatched half refuses through the entry");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        assert_eq!(error.code(), KEY_ID_MISMATCH);
        assert_eq!(error.exit_code(), 65);
        let objects = snapshot(&backend);
        assert_eq!(objects.len(), 1, "only the pointer is stored");
        assert!(objects.contains_key(&pointer_key()));
    }

    /// A deployment that mapped the ingest write role onto the
    /// administration credential's target refuses at composition, through
    /// the production entry and the usage family — the same authority-
    /// split refusal the approve command surfaces, and nothing reaches
    /// the seam at all.
    #[test]
    fn run_refuses_an_ingest_role_on_the_administration_credential_at_composition() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config_split(&seed_ref);
        let backend = ActBackend::default();
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect_err("the authority split refuses through the entry");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        assert_eq!(error.code(), CliError::usage().code());
        assert_eq!(error.exit_code(), 64);
        assert!(snapshot(&backend).is_empty());
    }

    /// A seam modeling the ingest credential's deployment policy refuses
    /// every control-prefix request: the production entry's pointer view
    /// is the first refused read, the act fails closed before anything is
    /// signed or written, and nothing lands anywhere — a control record
    /// is not an ingest credential's to mutate.
    #[test]
    fn run_refuses_an_ingest_scoped_seam_before_any_byte_lands() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let host_config = declared_host_config(&seed_ref);
        let backend = ActBackend::ingest_scoped();
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = run(
            &declared_invocation(&host_config, draft_operand),
            backend.clone(),
        )
        .expect_err("an ingest-scoped seam refuses the act");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);
        remove_scratch(&host_config);

        assert_eq!(error.code(), CliError::internal().code());
        assert_eq!(error.exit_code(), 70);
        assert!(
            snapshot(&backend).is_empty(),
            "no byte lands under an ingest-scoped credential"
        );
        let refusals = backend.refusals.lock().expect("test backend lock").clone();
        assert!(!refusals.is_empty(), "the refusals happened at the seam");
        let prefix = format!("tenants/{TENANT}/v1/control/");
        for key in refusals {
            assert!(
                key.starts_with(&prefix),
                "{key} aimed outside the control prefix"
            );
        }
    }

    /// The const a result-schema member pins, as its text: the identity
    /// tokens the registered schema closes the record's type and kind
    /// with.
    fn schema_const(properties: &Object, member: &str) -> String {
        let Value::Object(contract) = properties.get(member).expect("member contract") else {
            panic!("the {member} contract is an object");
        };
        match contract.get("const") {
            Some(Value::Text(token)) => token.clone(),
            other => panic!("the {member} const is text, not {other:?}"),
        }
    }

    /// The emitted document conforms to the registered result schema
    /// (CLI-015): the schema file the registry entry names is read from
    /// the tree it is committed to, and the record the command emits is
    /// checked against that file's own closed member set and pinned
    /// identity tokens — the registered contract and the emitted
    /// document cannot drift apart unnoticed, and this test keeps no
    /// second copy of either.
    #[test]
    fn the_emitted_document_conforms_to_the_registered_result_schema() {
        let schema_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/control-revocation.json");
        let schema_bytes = std::fs::read(schema_path).expect("the schema is committed");
        let Value::Object(schema) = json::parse(&schema_bytes).expect("the schema parses") else {
            panic!("the schema is an object");
        };
        let Value::Array(required) = schema.get("required").expect("the closed member set") else {
            panic!("the member set is an array of names");
        };
        let Value::Object(properties) = schema.get("properties").expect("the member contracts")
        else {
            panic!("the member contracts are an object");
        };

        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = ActBackend::default();
        publish_standing_pointer(&resolved, &backend);
        let draft_path = write_scratch("draft", &act_draft(1, &standing_half()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let document = revoke_over(&resolved, &invocation(Some(draft_operand)), backend)
            .expect("the golden draft signs and persists");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        let Value::Object(record) = document else {
            panic!("the result document is an object");
        };
        // The closed member set: the record carries exactly the members
        // the registered schema requires and pins, counted against the
        // file itself rather than a restated list.
        assert_eq!(
            record.len(),
            required.len(),
            "the record carries the registered member count"
        );
        for name in required {
            let Value::Text(name) = name else {
                panic!("a member name is text");
            };
            assert!(record.get(name).is_some(), "the record carries {name}");
            assert!(properties.get(name).is_some(), "the schema pins {name}");
        }
        // The identity tokens the schema pins as consts: the file is a
        // revocation record's contract, immutable in the record's own
        // class, and the emitted record is exactly that.
        let recorded_type = match record.get("record_type") {
            Some(Value::Text(token)) => token.clone(),
            other => panic!("the record's record_type is text, not {other:?}"),
        };
        assert_eq!(recorded_type, schema_const(properties, "record_type"));
        let recorded_kind = match record.get("record_kind") {
            Some(Value::Text(token)) => token.clone(),
            other => panic!("the record's record_kind is text, not {other:?}"),
        };
        assert_eq!(recorded_kind, schema_const(properties, "record_kind"));
    }

    /// The shape the router accepts for one command: the reachability
    /// proof's handler, refusing at the usage family should a
    /// composition ever reach it.
    fn composition_proof_handler(_invocation: &Invocation) -> Result<Value, CliError> {
        Err(CliError::usage())
    }

    /// The command is attachable from the binary's composition point:
    /// the registry entry now carries its result schema (CLI-015), so
    /// `register_handler` accepts the command where an entry without one
    /// refuses it as not shipped. The production registration itself
    /// names the concrete administration transport — the module's
    /// attachment note carries that boundary — so the handler here is
    /// the proof's shape, not the composition's.
    #[test]
    fn the_command_is_attachable_from_the_binary_composition() {
        let mut router = archivist_client_core::cli::Router::new();
        router
            .register_handler("admin revoke", composition_proof_handler)
            .expect("the registered entry carries its result schema");
    }
}
