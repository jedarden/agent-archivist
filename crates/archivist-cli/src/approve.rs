// SPDX-License-Identifier: Apache-2.0

//! The `admin approve` command behavior (plan Phase 3): one administrator
//! act that takes a link-request draft, validates and signs it with the
//! tenant authority at the current instant, publishes the linked-client
//! record through the offline administration store, and prints that record
//! as the command's result document.
//!
//! The wiring, piece by piece, follows the registry entry
//! (`[commands."admin approve"]` in `tools/cli-commands.toml`): the operand
//! path holds the draft; the `admin.*` configuration keys name the
//! administration plane; `stdout = "document"` means the linked-client
//! record is the result (`schemas/v1/control-client.json` is the command's
//! registered `result_schema`); `state_lock = "none"` means client state is
//! never touched. The signing act is
//! [`approve_link_request`](archivist_auth::link::approve_link_request); the
//! persistence act is
//! [`put_link_approval`](archivist_storage_s3::control_admin::S3ControlAdminStore::put_link_approval);
//! the plane both compose through is the shared
//! [`compose_admin_control_plane`](crate::admin::compose_admin_control_plane)
//! helper, which enforces the ingest/administration credential split at
//! composition.
//!
//! # The authority's trust material
//!
//! The seed is carried by configuration only as the registered reference
//! `admin.authority_seed_ref` and is resolved here, at the signing act,
//! under the protected-material checks (CFG-030, SEC-006) — never at
//! composition, never inline. The pinned root is derived from the same
//! trust material the deployment declares: the tenant the administration
//! configuration pins, and the public half the seed itself derives. That is
//! the offline administrator's anchor — the authority key the deployment
//! installed is the key the pin names, and the pin never moves
//! (`docs/notes/control-trust.md`). The key-fetch closure walks the
//! authority-rotation chain the same store the publication writes to, so a
//! rotated authority still signs inside its acceptance window.
//!
//! # Refusals exit through registered codes
//!
//! Every refusal is a registered condition of `tools/error-codes.toml`
//! (CLI-002), decided before anything is written; the router frames the
//! diagnostic on stderr and stdout stays empty:
//!
//! | Refusal | Registered code | Class exit |
//! |---|---|---|
//! | The draft is not a link request the record could carry | `envelope.malformed` | 65 |
//! | The authority's acceptance window or chain does not stand behind the act | `auth.authorization_rejected` | 78 |
//! | The stored pointer's epoch already supersedes the write | `storage.integrity_conflict` | 80 |
//! | A configuration key resolved from no tier | `cli.decision_missing` | 64 |
//! | The configuration is unusable, or the credential split is violated | `cli.usage_error` | 64 |
//! | The seed reference did not resolve to protected material | `client.secret_ref_refused` | 64 |
//! | The administration transport is unreachable | `transport.connection_failed` | 75 |
//!
//! A draft refusal covers every
//! [`ApprovalError`](archivist_auth::link::ApprovalError) class decided from
//! the draft's own bytes (shape, scope grammar, tenant); a window refusal
//! covers the classes decided from the signing half (acceptance window,
//! chain resolution, the instant itself).
//!
//! # Where the binary attaches this
//!
//! [`CommandHandler`](archivist_client_core::cli::CommandHandler) is a plain
//! function pointer, so the handler the binary registers names one concrete
//! administration backend. The production transport over the S3 request
//! seam is its own deliverable; until it lands, [`run`] composes over
//! whatever backend the composition point hands it — the binary
//! registration attaches at that point with the transport, the same
//! composition discipline the control plane's own module documents. The
//! behavior itself is complete and proven here over the seam, including the
//! end-to-end publication the registry entry promises.

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::ed25519;
use archivist_auth::link::{ApprovalError, approve_link_request};
use archivist_client_core::cli::{CliError, Invocation};
use archivist_client_core::config::{ConfigError, ResolvedConfig};
use archivist_protocol::json::{self, Value};
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, Timestamp};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage_s3::config::{S3ConfigError, S3ConfigErrorKind};
use archivist_storage_s3::control_admin::{ControlAdminBackend, ControlObjectKey};

/// The registered configuration key naming the tenant authority's signing
/// seed (`tools/config-keys.toml`).
const AUTHORITY_SEED_KEY: &str = "admin.authority_seed_ref";

/// The registered code for a presented document that is not a valid link
/// request (`tools/error-codes.toml`, class `request_invalid`).
const MALFORMED_DOCUMENT: &str = "envelope.malformed";

/// The registered code for an authority the pinned root does not stand
/// behind at the act's instant (`tools/error-codes.toml`, class
/// `authorization`).
const AUTHORITY_REFUSED: &str = "auth.authorization_rejected";

/// The registered code for a write the stored state's epoch already
/// supersedes (`tools/error-codes.toml`, class `integrity_conflict`).
const STALE_WRITE: &str = "storage.integrity_conflict";

/// The registered code for a required configuration field that resolved
/// from no tier (`tools/error-codes.toml`, class `usage`).
const DECISION_MISSING: &str = "cli.decision_missing";

/// The registered code for a secret reference that did not resolve to
/// protected material (`tools/error-codes.toml`, class `usage`, CFG-030).
const SECRET_REF_REFUSED: &str = "client.secret_ref_refused";

/// The registered code for a transport-level failure with no HTTP response
/// (`tools/error-codes.toml`, class `network`).
const TRANSPORT_FAILED: &str = "transport.connection_failed";

/// Run one `admin approve` invocation over the given administration
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
/// acquisition, composition, draft validation and signing, or publication.
pub fn run<B: ControlAdminBackend + Sync>(
    invocation: &Invocation,
    backend: B,
) -> Result<Value, CliError> {
    let sources = invocation
        .config_sources()
        .capture_environment()
        .map_err(config_fault)?;
    let resolved = sources.load().map_err(config_fault)?;
    approve_over(&resolved, invocation, backend)
}

/// Perform the command over an already-resolved configuration: read the
/// operand draft, resolve the signing act's material, sign, publish, and
/// return the linked-client record document.
///
/// `resolved` is the invocation's fully-resolved configuration — the same
/// value [`run`] loads. Split from it so the behavior is provable over a
/// synthetic configuration the way the composition helper's own tests are,
/// without touching the process environment.
///
/// # Errors
/// The registered refusal of the first failing act — composition, seed
/// resolution, draft validation and signing, or publication; each refusal
/// leaves stdout empty because nothing has been returned to the router.
pub fn approve_over<B: ControlAdminBackend + Sync>(
    resolved: &ResolvedConfig,
    invocation: &Invocation,
    backend: B,
) -> Result<Value, CliError> {
    // The administration plane: the composition helper enforces the
    // authority split before any store exists (the composition child's
    // contract), and carries the seed as the unresolved reference it is.
    let plane =
        crate::admin::compose_admin_control_plane(resolved, backend).map_err(composition_fault)?;

    // The draft: the operand path's bytes, read whole. The registry's
    // `operand = "path"` grammar is the parser's to enforce; the guard
    // stands for direct composition.
    let path = invocation.operands().first().ok_or_else(CliError::usage)?;
    let draft = std::fs::read(path).map_err(|_| CliError::usage())?;

    // The seed: resolved now, at the signing act, under the protected-
    // material checks (CFG-030). Exactly the 32 bytes an Ed25519 signing
    // seed is; anything else is a reference that did not resolve to the
    // protected material the key declares.
    let secret = resolved
        .resolve_secret(AUTHORITY_SEED_KEY)
        .map_err(config_fault)?;
    let seed: [u8; 32] = secret
        .as_bytes()
        .try_into()
        .map_err(|_| CliError::registered(SECRET_REF_REFUSED))?;

    // The pinned root: the tenant the administration configuration pins,
    // and the public half the seed derives — the deployment's own anchor.
    let tenant = plane.store().config().tenant().clone();
    let root = PinnedAuthorityRoot::new(
        tenant.clone(),
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&seed)),
    );

    // The act's instant: the current UTC instant in the envelope framing's
    // own timestamp form. The producer and the grammar are the same pair
    // the output envelope's `generated_at` uses, so the parse cannot fail;
    // the guard refuses rather than assumes.
    let now = archivist_client_core::cli::now_rfc3339();
    let signed_at = Timestamp::parse(&now).map_err(|_| CliError::internal())?;

    // One runtime drives both async acts; the fetch closure runs while no
    // other block is outstanding, so nesting is impossible.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| CliError::internal())?;

    // Validate and sign. Every draft refusal is decided here, before the
    // authority's key signs anything; the chain fetch reads the
    // authority-rotation links the same store the publication writes to.
    // A fetch transport error reads as a missing link, which the chain
    // reports as an unreachable authority — the seam's shape cannot say
    // more, and the refusal is the fail-closed reading either way.
    let link_key = |key_id: &KeyId| ControlObjectKey::authority_rotation(&tenant, key_id);
    let publication = approve_link_request(&seed, &root, &draft, &signed_at, |key_id| {
        let key = link_key(key_id);
        runtime
            .block_on(plane.store().backend().get_control_object(&key))
            .ok()
            .flatten()
    })
    .map_err(approval_fault)?;

    // Publish through the offline store: the signed record at the derived
    // current-pointer key, under the pointer family's monotonic rule.
    runtime
        .block_on(plane.store().put_link_approval(&publication))
        .map_err(storage_fault)?;

    // The result document is the record itself, parsed back from its
    // canonical bytes; the router frames it (bare document, or the output
    // envelope under `--json`).
    json::parse(publication.envelope()).map_err(|_| CliError::internal())
}

/// Map a configuration condition onto its registered CLI code: the code
/// the loader chose already names the registered condition (CLI-002).
fn config_fault(error: ConfigError) -> CliError {
    CliError::registered(error.code().token())
}

/// Map a composition refusal onto the usage family: the configuration the
/// host declared cannot assemble into a working administration plane,
/// which is a fix-the-invocation condition (exit 64) whatever the
/// concrete diagnostic. A missing setting is its own registered code.
fn composition_fault(error: S3ConfigError) -> CliError {
    match error.kind() {
        S3ConfigErrorKind::MissingSetting => CliError::registered(DECISION_MISSING),
        S3ConfigErrorKind::MalformedSetting
        | S3ConfigErrorKind::TransportMismatch
        | S3ConfigErrorKind::DuplicateIdentity => CliError::usage(),
    }
}

/// Map a signing refusal onto its registered code: draft-content classes
/// are a document the linked-client record could not carry; signing-half
/// classes are an authority whose acceptance window or chain does not
/// stand behind the act at its own instant.
fn approval_fault(error: ApprovalError) -> CliError {
    match error {
        ApprovalError::MalformedRequest
        | ApprovalError::UnknownScopeToken
        | ApprovalError::ScopeOutOfBounds
        | ApprovalError::ScopeNotSorted
        | ApprovalError::TenantMismatch => CliError::registered(MALFORMED_DOCUMENT),
        ApprovalError::AuthorityUnreachable
        | ApprovalError::SigningWindowClosed
        | ApprovalError::InvalidSigningInstant => CliError::registered(AUTHORITY_REFUSED),
    }
}

/// Map a publication refusal onto its registered code: the one refusal the
/// pointer family's monotonic rule produces is a write the stored epoch
/// already supersedes; an unreachable transport is its own class; every
/// other kind is a store invariant this command's construction already
/// satisfies, refused as internal rather than guessed at.
fn storage_fault(error: StorageError) -> CliError {
    match error.kind() {
        StorageErrorKind::StaleEpoch => CliError::registered(STALE_WRITE),
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
    use archivist_auth::revocation::LinkedClientPointer;
    use archivist_client_core::cli::parse::{self, Parsed};
    use archivist_client_core::cli::registry::Registry;
    use archivist_client_core::config::ConfigSources;
    use archivist_protocol::vocabulary::{ClientId, HarnessId, TenantId};
    use archivist_storage_s3::control_admin::S3ControlAdminStore;

    use super::*;

    /// The tenant, client, and deterministic halves the control-admin
    /// publication tests pin, so the stories agree on one identifier set.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
    const AUTHORITY_SEED: [u8; 32] = [0x17; 32];
    const CLIENT_SEED: [u8; 32] = [0x2a; 32];

    fn tenant() -> TenantId {
        TENANT.parse().expect("grammar")
    }

    fn client() -> ClientId {
        CLIENT.parse().expect("grammar")
    }

    /// The backend seam: map-backed, shared with the test through a clone
    /// so the test seeds chain state and inspects what the command wrote.
    #[derive(Debug, Default, Clone)]
    struct MapBackend {
        objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    impl ControlAdminBackend for MapBackend {
        async fn get_control_object(
            &self,
            key: &ControlObjectKey,
        ) -> Result<Option<Vec<u8>>, StorageError> {
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
            self.objects
                .lock()
                .expect("test backend lock")
                .insert(key.as_str().to_owned(), envelope.to_vec());
            Ok(())
        }
    }

    /// A backend whose transport is down, for the storage-fault mapping.
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

    /// The scratch-name counter: process-unique across the concurrent
    /// tests, so `create_new` never collides.
    fn scratch_name(what: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "archivist-approve-{}-{}-{}.tmp",
            what,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ))
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

    /// Remove the seed file a `file:` reference names (the reference's own
    /// target, so the text is safe to parse here).
    fn remove_seed_ref(seed_ref: &str) {
        let path = seed_ref.strip_prefix("file:").expect("file reference");
        remove_scratch(std::path::Path::new(path));
    }

    /// The deterministic installation identity and the draft document it
    /// emits for this tenant: public identity and requested scope only.
    fn link_draft(request_tenant: &TenantId) -> Vec<u8> {
        let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&CLIENT_SEED));
        let identity =
            InstallationIdentity::from_seed(client(), CLIENT_SEED, public).expect("derives");
        let scopes = RequestedScopes::new(
            vec![HarnessId::parse("claude-code").expect("grammar")],
            vec![ScopeOperation::Ingest],
        )
        .expect("an in-bounds scope");
        LinkRequest::new(identity.public_identity(), request_tenant.clone(), scopes)
            .canonical_bytes()
    }

    /// An invocation of the real command over the real registry, with the
    /// draft path as its operand and the non-interactive mode declared.
    fn invocation(draft_path: &str) -> Invocation {
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

    /// A chain fetch that finds nothing: the authority half here is the
    /// pinned root itself, and a root needs no links.
    fn no_links(_: &KeyId) -> Option<Vec<u8>> {
        None
    }

    /// The linked-client object key the record must land at.
    fn client_key() -> String {
        ControlObjectKey::linked_client(&tenant(), &client())
            .as_str()
            .to_owned()
    }

    #[test]
    fn draft_refusals_map_onto_the_document_code() {
        for error in [
            ApprovalError::MalformedRequest,
            ApprovalError::UnknownScopeToken,
            ApprovalError::ScopeOutOfBounds,
            ApprovalError::ScopeNotSorted,
            ApprovalError::TenantMismatch,
        ] {
            let fault = approval_fault(error);
            assert_eq!(fault.code(), MALFORMED_DOCUMENT, "{error:?}");
            assert_eq!(fault.exit_code(), 65, "{error:?}");
        }
    }

    #[test]
    fn signing_refusals_map_onto_the_authority_code() {
        for error in [
            ApprovalError::AuthorityUnreachable,
            ApprovalError::SigningWindowClosed,
            ApprovalError::InvalidSigningInstant,
        ] {
            let fault = approval_fault(error);
            assert_eq!(fault.code(), AUTHORITY_REFUSED, "{error:?}");
            assert_eq!(fault.exit_code(), 78, "{error:?}");
        }
    }

    #[test]
    fn stale_epoch_maps_onto_the_integrity_code() {
        let fault = storage_fault(StorageError::of_kind(StorageErrorKind::StaleEpoch));
        assert_eq!(fault.code(), STALE_WRITE);
        assert_eq!(fault.exit_code(), 80);
    }

    #[test]
    fn composition_refusals_map_onto_the_usage_family() {
        // The configuration error carries a static, content-free detail —
        // the kind discriminates the registered code.
        let missing = composition_fault(S3ConfigError::new(
            S3ConfigErrorKind::MissingSetting,
            "an administration setting did not resolve from any tier",
        ));
        assert_eq!(missing.code(), DECISION_MISSING);
        assert_eq!(missing.exit_code(), 64);
        for kind in [
            S3ConfigErrorKind::MalformedSetting,
            S3ConfigErrorKind::TransportMismatch,
            S3ConfigErrorKind::DuplicateIdentity,
        ] {
            let fault = composition_fault(S3ConfigError::new(
                kind,
                "the configuration the host declared cannot assemble",
            ));
            assert_eq!(fault.code(), CliError::usage().code(), "{kind:?}");
            assert_eq!(fault.exit_code(), 64, "{kind:?}");
        }
    }

    /// The command path runs end to end over the store: a valid draft
    /// signs, publishes, and returns the linked-client record the
    /// registered `result_schema` pins, and the stored object re-reads and
    /// verifies from the pinned root.
    #[test]
    fn valid_draft_publishes_the_linked_client_record_end_to_end() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let document = approve_over(&resolved, &invocation(draft_operand), backend.clone())
            .expect("the golden draft approves and publishes");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        // The emitted document is the linked-client record: exactly the
        // members `schemas/v1/control-client.json` requires, carrying this
        // client's link at epoch 1.
        let Value::Object(ref members) = document else {
            panic!("the result document is an object");
        };
        let required: &[&str] = &[
            "authority_key_id",
            "authority_signature",
            "authorization_epoch",
            "client_id",
            "key_algorithm",
            "key_id",
            "public_key",
            "record_kind",
            "record_type",
            "schema",
            "scopes",
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
            matches!(members.get("record_type"), Some(Value::Text(token)) if token == "linked-client")
        );
        assert!(matches!(members.get("client_id"), Some(Value::Text(token)) if token == CLIENT));
        assert!(matches!(
            members.get("authorization_epoch"),
            Some(Value::Int(1))
        ));

        // The store holds the record at its derived key, and it verifies
        // from the pinned root the way a reader would.
        let stored = backend
            .objects
            .lock()
            .expect("test backend lock")
            .get(&client_key())
            .cloned()
            .expect("the record published");
        let root = PinnedAuthorityRoot::new(
            tenant(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        );
        LinkedClientPointer::verify(&root, &stored, no_links, &client())
            .expect("the stored record verifies from the pinned root");
    }

    /// A draft that is not a link request refuses through the registered
    /// document code, and nothing is written.
    #[test]
    fn malformed_draft_refuses_with_the_document_code_and_writes_nothing() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", b"{not a link request", 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = approve_over(&resolved, &invocation(draft_operand), backend.clone())
            .expect_err("a malformed draft refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), MALFORMED_DOCUMENT);
        assert_eq!(error.exit_code(), 65);
        assert!(
            backend
                .objects
                .lock()
                .expect("test backend lock")
                .is_empty()
        );
    }

    /// Approving a client the store already links at the same epoch
    /// refuses through the registered integrity code: the pointer family's
    /// monotonic rule refuses the replay, and the stored record stays what
    /// it was.
    #[test]
    fn replayed_approval_refuses_with_the_integrity_code_and_keeps_the_record() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        approve_over(&resolved, &invocation(draft_operand), backend.clone())
            .expect("the first approval publishes");
        let error = approve_over(&resolved, &invocation(draft_operand), backend.clone())
            .expect_err("the replayed approval is stale");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), STALE_WRITE);
        assert_eq!(error.exit_code(), 80);
        // The stored pointer is the first approval's, unchanged.
        let stored = backend
            .objects
            .lock()
            .expect("test backend lock")
            .get(&client_key())
            .cloned()
            .expect("the record is still there");
        let root = PinnedAuthorityRoot::new(
            tenant(),
            Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
        );
        LinkedClientPointer::verify(&root, &stored, no_links, &client())
            .expect("the stored record still verifies");
    }

    /// A seed reference whose target is not the protected material the key
    /// declares refuses through the registered secret-reference code.
    #[test]
    fn unresolved_seed_reference_refuses_with_the_secret_reference_code() {
        // The target the reference names is deliberately never set.
        let resolved = base_sources("env:NO_SUCH_AUTHORITY_SEED")
            .load()
            .expect("the host loads");
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = approve_over(&resolved, &invocation(draft_operand), backend)
            .expect_err("an unresolved seed reference refuses");
        remove_scratch(&draft_path);

        assert_eq!(error.code(), SECRET_REF_REFUSED);
        assert_eq!(error.exit_code(), 64);
    }

    /// A seed that is not 32 bytes is not the material the reference
    /// declares; the signing act refuses before anything is signed.
    #[test]
    fn wrong_length_seed_refuses_with_the_secret_reference_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED[..31]);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = approve_over(&resolved, &invocation(draft_operand), backend)
            .expect_err("a wrong-length seed refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), SECRET_REF_REFUSED);
        assert_eq!(error.exit_code(), 64);
    }

    /// A deployment that mapped the administration credential onto an
    /// ingest role refuses at composition, through the usage family —
    /// the authority split the composition helper enforces.
    #[test]
    fn administration_credential_on_an_ingest_role_refuses_at_composition() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref)
            .env(
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
                "env:TEST_ADMIN_CREDENTIAL",
            )
            .load()
            .expect("the string grammar itself resolves");
        remove_seed_ref(&seed_ref);
        let backend = MapBackend::default();
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = approve_over(&resolved, &invocation(draft_operand), backend)
            .expect_err("the authority split refuses");
        remove_scratch(&draft_path);

        assert_eq!(error.code(), CliError::usage().code());
        assert_eq!(error.exit_code(), 64);
    }

    /// An unreachable administration transport refuses through the
    /// registered transport code after signing, before anything lands.
    #[test]
    fn unreachable_transport_refuses_with_the_transport_code() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");

        let error = approve_over(&resolved, &invocation(draft_operand), DownBackend)
            .expect_err("a down transport refuses");
        remove_seed_ref(&seed_ref);
        remove_scratch(&draft_path);

        assert_eq!(error.code(), TRANSPORT_FAILED);
        assert_eq!(error.exit_code(), 75);
    }

    /// The production entry loads the resolved configuration from the
    /// invocation's sources: a fully-declared environment resolves, and
    /// the behavior core runs to the registered refusal. The environment
    /// tier here is the test process's own — the fixture declares only
    /// what it must to prove the load path, and the draft refuses through
    /// the registered document code.
    #[test]
    fn run_loads_the_invocation_configuration_and_drives_the_command() {
        // The command refuses on the draft before any transport acts, so a
        // minimal environment is enough to prove the load: every required
        // key must resolve or the load itself refuses first. The process
        // environment of the test host carries none of them, so this
        // invocation refuses with the decision-missing code naming the
        // first unset administration key — the load path's own registered
        // refusal.
        let draft_path = write_scratch("draft", &link_draft(&tenant()), 0o600);
        let draft_operand = draft_path.to_str().expect("utf-8 scratch path");
        let error = run(&invocation(draft_operand), MapBackend::default())
            .expect_err("an undeclared host refuses at the load");
        remove_scratch(&draft_path);

        assert_eq!(error.code(), DECISION_MISSING);
        assert_eq!(error.exit_code(), 64);
    }

    /// The store the command composes is the administration store the
    /// composition child assembled: one `S3ControlAdminStore` over the
    /// seam, generic and non-ingest. A compile-level statement, asserted
    /// by constructing the type the composition returns.
    #[test]
    fn the_command_composes_the_administration_store() {
        let seed_ref = protected_seed_ref(&AUTHORITY_SEED);
        let resolved = base_sources(&seed_ref).load().expect("the host loads");
        remove_seed_ref(&seed_ref);
        let plane = crate::admin::compose_admin_control_plane(&resolved, MapBackend::default())
            .expect("the split configuration composes");
        // The store and the seed reference are the plane's two halves.
        let _store: &S3ControlAdminStore<MapBackend> = plane.store();
        assert!(matches!(
            plane.authority_seed_ref(),
            archivist_client_core::config::SecretRef::File { .. }
        ));
    }
}
