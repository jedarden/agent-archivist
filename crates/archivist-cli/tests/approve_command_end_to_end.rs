// SPDX-License-Identifier: Apache-2.0

//! The `admin approve` command driven end to end over the control-admin
//! backend seam: real argv through the real registry parser, the real
//! router, the handler registered the way the binary's composition point
//! registers it, and the real publication acts — with the administration
//! transport behind the seam mocked exactly the way the control-admin
//! store's own publication tests mock it.
//!
//! The process is the observation instrument. A custom harness (`harness
//! = false` for this target) makes the compiled test binary a plain
//! program; it re-executes itself once per scenario as a child process
//! whose stdout, stderr, and exit status are the command's own. That is
//! the only way to observe the router's stream framing empirically — the
//! router writes the process's real streams — and it is the whole point:
//! a valid draft's stdout is the linked-client record's canonical bytes,
//! every refusal's stdout is empty with the diagnostic on stderr, and
//! each scenario's exit status is the registered error class's code.
//!
//! The child's exit status carries one more assertion than the exit code:
//! after the router returns, the child re-reads what landed in the seam
//! and verifies it the way a reader would, so a golden exit of 0 means
//! the stored object re-read and verified too.
//!
//! The authority-window scenario retires the seed's half through a
//! rotation link signed in the past: the dual-key overlap ends 24 hours
//! after the link's own instant, so a link signed 2020-01-01 is past its
//! overlap at any real current instant and the signing window is closed
//! deterministically forever.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::Permissions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::ed25519;
use archivist_auth::identity::InstallationIdentity;
use archivist_auth::link::{LinkRequest, RequestedScopes, ScopeOperation};
use archivist_auth::revocation::LinkedClientPointer;
use archivist_client_core::cli::parse::{self, Parsed};
use archivist_client_core::cli::registry::Registry;
use archivist_client_core::cli::{CliError, Invocation, Router};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, Ed25519Signature, HarnessId, KeyId, TenantId, Timestamp,
};
use archivist_storage::error::StorageError;
use archivist_storage_s3::control_admin::{ControlAdminBackend, ControlObjectKey};

// The deterministic story: the same fixture identifiers the control-admin
// publication tests pin, so the seeds, tenant, and client here are the
// ones every other control-plane story agrees on.
const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";
const AUTHORITY_SEED: [u8; 32] = [0x17; 32];
const CLIENT_SEED: [u8; 32] = [0x2a; 32];
const SUCCESSOR_SEED: [u8; 32] = [0x5c; 32];

/// The rotation link that retires the seed's half: signed long enough ago
/// that its 24-hour dual-key overlap has closed at any real instant.
const RETIRED_LINK_SIGNED_AT: &str = "2020-01-01T00:00:00Z";

/// The environment variable naming the child's scenario; the parent sets
/// it, the child dispatches on it. Deliberately outside the configuration
/// loader's reserved `ARCHIVIST_` namespace, whose names all have to be
/// registered keys.
const SCENARIO_ENV: &str = "APPROVE_E2E_SCENARIO";

/// The environment variable carrying the draft operand's path from the
/// parent to the child.
const DRAFT_ENV: &str = "APPROVE_E2E_DRAFT";

/// The child's own failure exit, distinct from every registered class: a
/// scenario-side check failed after the router returned, and the parent
/// must not read the run as the command's doing.
const SCENARIO_FAULT: i32 = 3;

/// The child's failure exit for a setup act before the router ran.
const SETUP_FAULT: i32 = 4;

/// One end-to-end story: the argv shape, the process exit the command's
/// registered class must produce, and the diagnostic line's registered
/// code where a refusal is expected.
#[derive(Clone, Copy, Debug)]
enum Scenario {
    /// A valid draft, bare output: exit 0, stdout is the record.
    GoldenBare,
    /// A valid draft under `--json`: exit 0, stdout is the output
    /// envelope framing the record as its result.
    GoldenJson,
    /// A draft that is not a link request: exit 65, empty stdout.
    Malformed,
    /// The seed's half retired past its overlap: exit 78, empty stdout.
    WindowClosed,
    /// The client already linked at epoch 1: exit 80, empty stdout.
    StaleEpoch,
}

const SCENARIOS: &[Scenario] = &[
    Scenario::GoldenBare,
    Scenario::GoldenJson,
    Scenario::Malformed,
    Scenario::WindowClosed,
    Scenario::StaleEpoch,
];

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::GoldenBare => "golden-bare",
            Self::GoldenJson => "golden-json",
            Self::Malformed => "malformed",
            Self::WindowClosed => "window-closed",
            Self::StaleEpoch => "stale-epoch",
        }
    }

    fn from_name(text: &str) -> Option<Self> {
        SCENARIOS
            .iter()
            .copied()
            .find(|scenario| scenario.name() == text)
    }

    /// The argv the child hands the router, the command's real shape.
    fn argv(self, draft: &str) -> Vec<OsString> {
        let mut args = vec!["--non-interactive".to_owned()];
        if matches!(self, Self::GoldenJson) {
            args.push("--json".to_owned());
        }
        args.push("admin".to_owned());
        args.push("approve".to_owned());
        args.push(draft.to_owned());
        args.iter().map(OsString::from).collect()
    }

    /// The registered class exit the scenario must produce.
    fn expected_exit(self) -> i32 {
        match self {
            Self::GoldenBare | Self::GoldenJson => 0,
            Self::Malformed => 65,
            Self::WindowClosed => 78,
            Self::StaleEpoch => 80,
        }
    }

    /// The registered code the diagnostic on a refusal's stderr must
    /// name; `None` for a golden scenario, whose stderr stays empty.
    fn expected_diagnostic(self) -> Option<&'static str> {
        match self {
            Self::GoldenBare | Self::GoldenJson => None,
            Self::Malformed => Some("envelope.malformed"),
            Self::WindowClosed => Some("auth.authorization_rejected"),
            Self::StaleEpoch => Some("storage.integrity_conflict"),
        }
    }
}

fn main() {
    match std::env::var(SCENARIO_ENV) {
        Ok(text) => run_child(Scenario::from_name(&text).expect("the parent names a scenario")),
        Err(_) => run_parent(),
    }
}

// ---------------------------------------------------------------------------
// The parent: one child process per scenario, the streams observed.
// ---------------------------------------------------------------------------

/// The parent flow: for each scenario, write the fixture, spawn this
/// binary as the child, and assert on the process's own exit status,
/// stdout, and stderr.
fn run_parent() {
    for scenario in SCENARIOS {
        let fixture = Fixture::write(*scenario);
        let binary = std::env::current_exe().expect("the test binary knows its own path");
        let output = Command::new(binary)
            .env_clear()
            .env(SCENARIO_ENV, scenario.name())
            .env(DRAFT_ENV, fixture.draft.display().to_string())
            .envs(fixture.config_environment())
            .stdin(std::process::Stdio::null())
            .output()
            .expect("the child process spawns");
        let _ = std::fs::remove_dir_all(&fixture.root);

        let story = scenario.name();
        assert_eq!(
            output.status.code(),
            Some(scenario.expected_exit()),
            "{story}: the process exit is the registered class's code (stderr: {})",
            String::from_utf8_lossy(&output.stderr),
        );
        if let Some(code) = scenario.expected_diagnostic() {
            assert!(
                output.stdout.is_empty(),
                "{story}: stdout stays empty on a refusal",
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.starts_with(&format!("archivist {code}:")),
                "{story}: the diagnostic names the registered code, got: {stderr}",
            );
        } else {
            assert!(
                output.stderr.is_empty(),
                "{story}: a golden run writes nothing to stderr (stdout: {})",
                String::from_utf8_lossy(&output.stdout),
            );
            assert_golden_stdout(scenario, &output.stdout);
        }
    }
}

/// The golden scenarios' stdout framing: exactly one canonical JSON
/// document and a newline — the record itself in bare mode, the CLI
/// output envelope with the record as its result under `--json` — and
/// the framed record verifies from the pinned root.
fn assert_golden_stdout(scenario: &Scenario, stdout: &[u8]) {
    let story = scenario.name();
    let framed = stdout
        .strip_suffix(b"\n")
        .unwrap_or_else(|| panic!("{story}: stdout is one newline-terminated document"));
    let document =
        json::parse(framed).unwrap_or_else(|error| panic!("{story}: stdout parses: {error}"));
    assert_eq!(
        framed,
        document.canonical_bytes().as_slice(),
        "{story}: the framed document is the canonical bytes",
    );

    let root = authority_root();
    if matches!(scenario, Scenario::GoldenJson) {
        let Value::Object(members) = &document else {
            panic!("{story}: the output envelope is an object");
        };
        assert_eq!(members.len(), 4, "{story}: the envelope is closed");
        assert!(
            matches!(members.get("schema"), Some(Value::Text(token)) if token == "archivist.cli-output/v1"),
            "{story}: the envelope names its schema",
        );
        assert!(
            matches!(members.get("command"), Some(Value::Text(token)) if token == "admin-approve"),
            "{story}: the envelope names the command",
        );
        let Some(Value::Text(generated_at)) = members.get("generated_at") else {
            panic!("{story}: the envelope carries a generated_at timestamp");
        };
        Timestamp::parse(generated_at)
            .unwrap_or_else(|error| panic!("{story}: generated_at parses: {error:?}"));
        let result = members
            .get("result")
            .unwrap_or_else(|| panic!("{story}: the envelope carries the result"));
        assert_linked_client_record(story, result, &root);
    } else {
        assert_linked_client_record(story, &document, &root);
    }
}

/// The record assertions every golden story makes: exactly the members
/// the registered result schema pins, this client's link at epoch 1, and
/// a signature that verifies from the pinned root.
fn assert_linked_client_record(story: &str, record: &Value, root: &PinnedAuthorityRoot) {
    let Value::Object(members) = record else {
        panic!("{story}: the result is an object");
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
    assert_eq!(
        members.len(),
        required.len(),
        "{story}: the record is closed"
    );
    for name in required {
        assert!(
            members.get(name).is_some(),
            "{story}: the record names {name}"
        );
    }
    assert!(
        matches!(members.get("schema"), Some(Value::Text(token)) if token == "archivist.control/v1"),
        "{story}: the record names its schema",
    );
    assert!(
        matches!(members.get("record_type"), Some(Value::Text(token)) if token == "linked-client"),
        "{story}: the record is a linked-client",
    );
    assert!(
        matches!(members.get("record_kind"), Some(Value::Text(token)) if token == "current-pointer"),
        "{story}: the record is a current-pointer",
    );
    assert!(
        matches!(members.get("tenant_id"), Some(Value::Text(token)) if token == TENANT),
        "{story}: the record names the tenant",
    );
    assert!(
        matches!(members.get("client_id"), Some(Value::Text(token)) if token == CLIENT),
        "{story}: the record names the client",
    );
    assert!(
        matches!(members.get("authorization_epoch"), Some(Value::Int(1))),
        "{story}: the link is at epoch 1",
    );
    let client_public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&CLIENT_SEED));
    assert!(
        matches!(members.get("key_id"), Some(Value::Text(token))
            if token.as_str() == KeyId::from_public_key(&client_public).to_hex()),
        "{story}: the record carries the draft client's key id",
    );
    let authority_public =
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED));
    assert!(
        matches!(members.get("authority_key_id"), Some(Value::Text(token))
            if token.as_str() == KeyId::from_public_key(&authority_public).to_hex()),
        "{story}: the record names the pinned authority's key id",
    );

    // The framed bytes verify from the pinned root the way a reader
    // would. The fetch finds nothing because the store holds no rotation
    // links in these scenarios: the pinned root is the signer.
    LinkedClientPointer::verify(root, &record.canonical_bytes(), |_| None, &client())
        .unwrap_or_else(|error| panic!("{story}: the framed record verifies: {error:?}"));
}

// ---------------------------------------------------------------------------
// The fixture: the deterministic host, seed file, and draft operand.
// ---------------------------------------------------------------------------

/// One scenario's scratch tree: the protected seed file the
/// `admin.authority_seed_ref` reference names and the draft operand file.
struct Fixture {
    root: std::path::PathBuf,
    draft: std::path::PathBuf,
}

impl Fixture {
    /// Write the scenario's fixture: a process-unique scratch directory,
    /// the authority seed as a mode-0600 file, and the scenario's draft.
    fn write(scenario: Scenario) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "archivist-approve-e2e-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::create_dir_all(&root).expect("the scratch directory creates");
        let seed_path = root.join("authority.seed");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&seed_path)
            .expect("the seed file creates");
        std::fs::write(&seed_path, AUTHORITY_SEED).expect("the seed bytes write");
        std::fs::set_permissions(&seed_path, Permissions::from_mode(0o600))
            .expect("the seed file tightens");

        let draft_bytes = match scenario {
            Scenario::Malformed => b"{not a link request".to_vec(),
            Scenario::GoldenBare
            | Scenario::GoldenJson
            | Scenario::WindowClosed
            | Scenario::StaleEpoch => link_draft(&tenant()),
        };
        let draft = root.join("link-request.json");
        std::fs::write(&draft, draft_bytes).expect("the draft bytes write");

        Self { root, draft }
    }

    /// The fully-declared host environment, mirrored from the
    /// composition fixture every other control-plane test declares: the
    /// administration credential and the ingest write credential are
    /// distinct references, each pointing at a target this fixture never
    /// resolves — the authority split the composition enforces stays
    /// intact, and no scenario maps one credential onto the other's role.
    fn config_environment(&self) -> Vec<(String, String)> {
        let seed_ref = format!("file:{}", self.root.join("authority.seed").display());
        vec![
            ("HOME".to_owned(), self.root.display().to_string()),
            (
                "ARCHIVIST_INGEST_ENDPOINT_URL".to_owned(),
                "https://ingest.example.invalid".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_ENDPOINT_URL".to_owned(),
                "https://s3.example.invalid".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_REGION".to_owned(),
                "us-east-1".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_ENCRYPTION".to_owned(),
                "s3_sse".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_RAW_BUCKET".to_owned(),
                "archivist-raw-example".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_CONTROL_BUCKET".to_owned(),
                "archivist-control-example".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF".to_owned(),
                "env:TEST_RAW_CREDENTIAL".to_owned(),
            ),
            (
                "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF".to_owned(),
                "env:TEST_CONTROL_CREDENTIAL".to_owned(),
            ),
            (
                "ARCHIVIST_SERVER_LISTEN_ADDRESS".to_owned(),
                "127.0.0.1:8087".to_owned(),
            ),
            (
                "ARCHIVIST_ADMIN_ENDPOINT_URL".to_owned(),
                "https://control.example.invalid".to_owned(),
            ),
            ("ARCHIVIST_ADMIN_REGION".to_owned(), "us-east-1".to_owned()),
            (
                "ARCHIVIST_ADMIN_CONTROL_BUCKET".to_owned(),
                "archivist-control-example".to_owned(),
            ),
            ("ARCHIVIST_ADMIN_TENANT".to_owned(), TENANT.to_owned()),
            (
                "ARCHIVIST_ADMIN_CREDENTIALS_REF".to_owned(),
                "env:TEST_ADMIN_CREDENTIAL".to_owned(),
            ),
            ("ARCHIVIST_ADMIN_AUTHORITY_SEED_REF".to_owned(), seed_ref),
        ]
    }
}

// ---------------------------------------------------------------------------
// The child: the command's own process.
// ---------------------------------------------------------------------------

/// The child flow: set up the scenario's store state, run the real
/// router, then hold the run's postconditions before exiting with the
/// router's own status.
fn run_child(scenario: Scenario) -> ! {
    let draft = std::env::var(DRAFT_ENV).expect("the parent passes the draft operand");
    let argv = scenario.argv(&draft);

    match scenario {
        Scenario::WindowClosed => seed_retired_root(),
        Scenario::StaleEpoch => seed_first_approval(&argv),
        _ => {}
    }

    let mut router = Router::new();
    router
        .register_handler("admin approve", approve_handler)
        .expect("the registered entry carries its result schema");
    let code = router.run(&argv);

    // The exit status the parent asserts stands on these: what the run
    // left in the store must be exactly what the scenario's class says.
    match scenario {
        Scenario::GoldenBare | Scenario::GoldenJson | Scenario::StaleEpoch => {
            verify_published_record();
        }
        Scenario::Malformed => {
            let untouched = seam().objects.lock().expect("test backend lock").is_empty();
            if !untouched {
                eprintln!("the refused run wrote to the store");
                std::process::exit(SCENARIO_FAULT);
            }
        }
        Scenario::WindowClosed => {
            let linked = seam()
                .objects
                .lock()
                .expect("test backend lock")
                .contains_key(&client_key());
            if linked {
                eprintln!("the refused run published a record");
                std::process::exit(SCENARIO_FAULT);
            }
        }
    }
    std::process::exit(code);
}

/// The handler the binary's composition point registers: one concrete
/// administration backend behind the seam, the generic command behavior
/// over it. `CommandHandler` is a plain function pointer, so this is the
/// exact shape the production registration takes when the real transport
/// lands — the backend name is the only thing that changes.
fn approve_handler(invocation: &Invocation) -> Result<Value, CliError> {
    archivist_cli::approve::run(invocation, seam())
}

/// The seam: map-backed, shared with the scenario through a clone so the
/// child can seed chain state and inspect what the command wrote — the
/// control-admin store's own publication-test pattern.
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

/// The process-global seam instance: the handler and the scenario's setup
/// and postcondition checks all see the same map.
static SEAM: OnceLock<MapBackend> = OnceLock::new();

fn seam() -> MapBackend {
    SEAM.get_or_init(MapBackend::default).clone()
}

/// Seed the store with the rotation link that retires the pinned root's
/// half: the link sits at the half's own address, signed by the half it
/// retires, establishing the successor — every admission rule the chain
/// walk holds a link to, with the signature from the seed itself.
fn seed_retired_root() {
    let tenant = tenant();
    let previous_public =
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED));
    let previous_key_id = KeyId::from_public_key(&previous_public);
    let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&SUCCESSOR_SEED));
    let mut members = Object::new();
    members.set("schema", Value::Text("archivist.control/v1".to_owned()));
    members.set("record_type", Value::Text("authority-rotation".to_owned()));
    members.set("record_kind", Value::Text("immutable".to_owned()));
    members.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    members.set("previous_public_key", Value::Text(previous_public.to_hex()));
    members.set("previous_key_id", Value::Text(previous_key_id.to_hex()));
    members.set("key_algorithm", Value::Text("ed25519".to_owned()));
    members.set("public_key", Value::Text(public.to_hex()));
    members.set(
        "key_id",
        Value::Text(KeyId::from_public_key(&public).to_hex()),
    );
    members.set("signed_at", Value::Text(RETIRED_LINK_SIGNED_AT.to_owned()));
    members.set("authority_key_id", Value::Text(previous_key_id.to_hex()));
    let signature = ed25519::sign(
        &AUTHORITY_SEED,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    let key = ControlObjectKey::authority_rotation(&tenant, &previous_key_id);
    seam().objects.lock().expect("test backend lock").insert(
        key.as_str().to_owned(),
        Value::Object(members).canonical_bytes(),
    );
}

/// Seed the store the way a prior approval left it: the command's own
/// library entry over the same seam, before the router runs the second
/// approval the pointer family's monotonic rule must refuse.
fn seed_first_approval(argv: &[OsString]) {
    let invocation = match parse::parse(argv, Registry::pinned()).expect("the invocation parses") {
        Parsed::Command(invocation) => invocation,
        other => panic!("the parser returned {other:?} for a command invocation"),
    };
    if archivist_cli::approve::run(&invocation, seam()).is_err() {
        eprintln!("the first approval did not publish");
        std::process::exit(SETUP_FAULT);
    }
}

/// The golden and stale scenarios' shared postcondition: the object at
/// the derived pointer key re-reads through the seam and verifies from
/// the pinned root the way a reader would.
fn verify_published_record() {
    let stored = seam()
        .objects
        .lock()
        .expect("test backend lock")
        .get(&client_key())
        .cloned();
    let Some(stored) = stored else {
        eprintln!("no record landed at the derived pointer key");
        std::process::exit(SCENARIO_FAULT);
    };
    if let Err(error) = LinkedClientPointer::verify(&authority_root(), &stored, |_| None, &client())
    {
        eprintln!("the stored record does not verify: {error:?}");
        std::process::exit(SCENARIO_FAULT);
    }
}

// ---------------------------------------------------------------------------
// Shared fixture halves.
// ---------------------------------------------------------------------------

fn tenant() -> TenantId {
    TENANT.parse().expect("grammar")
}

fn client() -> ClientId {
    CLIENT.parse().expect("grammar")
}

fn authority_root() -> PinnedAuthorityRoot {
    PinnedAuthorityRoot::new(
        tenant(),
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&AUTHORITY_SEED)),
    )
}

/// The derived pointer key the record must land at.
fn client_key() -> String {
    ControlObjectKey::linked_client(&tenant(), &client())
        .as_str()
        .to_owned()
}

/// The deterministic installation identity and the draft document it
/// emits for this tenant: public identity and requested scope only.
fn link_draft(request_tenant: &TenantId) -> Vec<u8> {
    let public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&CLIENT_SEED));
    let identity = InstallationIdentity::from_seed(client(), CLIENT_SEED, public).expect("derives");
    let scopes = RequestedScopes::new(
        vec![HarnessId::parse("claude-code").expect("grammar")],
        vec![ScopeOperation::Ingest],
    )
    .expect("an in-bounds scope");
    LinkRequest::new(identity.public_identity(), request_tenant.clone(), scopes).canonical_bytes()
}
