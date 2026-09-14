// SPDX-License-Identifier: Apache-2.0

//! End-to-end identity discovery and private-material containment tests.
//!
//! The acceptance property for protected client identity is two-sided:
//! filesystem modes are restrictive, and no command, log, error, or test
//! output reveals the private key or an authorization value. These tests
//! pin both sides over the real generate → persist → discover cycle.

use std::path::PathBuf;

use archivist_auth::error::IdentityError;
use archivist_auth::identity::InstallationIdentity;
use archivist_auth::link::{LinkRequest, RequestedScopes, ScopeOperation};
use archivist_auth::reference::ProtectedReference;
use archivist_protocol::vocabulary::{Ed25519PublicKey, HarnessId, KeyId, TenantId};

/// A fixed synthetic seed so every serialization in this suite is scanned
/// against a known private half. Not a credential: it is test data, and it
/// never appears in any output this suite prints (pinned below).
const FIXED_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

fn fixed_identity() -> InstallationIdentity {
    let client_id =
        archivist_protocol::vocabulary::ClientId::parse("11111111-2222-4333-8444-555555555555")
            .expect("grammar");
    let public =
        Ed25519PublicKey::parse("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .expect("grammar");
    InstallationIdentity::from_seed(client_id, FIXED_SEED, public).expect("consistent parts")
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "archivist-identity-{tag}-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace('/', "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    // CFG-023 posture for a directory holding private material in these
    // tests: exactly `0700`, matching what `write_new` requires of a parent
    // it finds. Tests that pin the refusal of a looser parent deliberately
    // re-loosen their directory afterwards.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir mode");
    }
    dir
}

/// The full cycle: generate, persist at `0600`, discover through a
/// protected reference, and confirm the identity round-trips exactly.
#[test]
#[cfg(unix)]
fn generate_persist_discover_round_trip() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("round-trip");
    let path = dir.join("identity.json");

    let generated = InstallationIdentity::generate().expect("entropy available");
    generated.write_new(&path).expect("first write succeeds");

    let reference =
        ProtectedReference::parse(&format!("file:{}", path.display())).expect("generated path");
    let discovered = InstallationIdentity::discover(&reference).expect("discover succeeds");

    assert_eq!(discovered.client_id(), generated.client_id());
    assert_eq!(
        discovered.public_identity().public_key,
        generated.public_identity().public_key
    );
    assert_eq!(
        discovered.public_identity().key_id,
        generated.public_identity().key_id
    );

    // The persisted file is at mode 0600 or stricter — checked by property.
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(
        mode & 0o077,
        0,
        "no group or other permission bits: {mode:o}"
    );
    assert_eq!(mode & 0o700, 0o600, "owner read/write present: {mode:o}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// The key ID recorded anywhere is the SHA-256 of the encoded public key —
/// the pinned cross-field derivation (VAL-002).
#[test]
fn key_id_is_derived_from_public_key() {
    let identity = fixed_identity();
    let public = identity.public_identity();
    assert_eq!(public.key_id, KeyId::from_public_key(&public.public_key));
}

/// Generation refuses to overwrite an existing identity file.
#[test]
#[cfg(unix)]
fn write_new_refuses_overwrite() {
    let dir = temp_dir("refuse-overwrite");
    let path = dir.join("identity.json");
    let first = InstallationIdentity::generate().expect("entropy available");
    first.write_new(&path).expect("first write");
    let second = InstallationIdentity::generate().expect("entropy available");
    assert_eq!(second.write_new(&path), Err(IdentityError::IdentityExists));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Discovery refuses an identity file whose mode is looser than `0600`.
#[test]
#[cfg(unix)]
fn discover_refuses_loose_mode() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("refuse-loose-mode");
    let path = dir.join("identity.json");
    let identity = fixed_identity();
    std::fs::write(&path, persisted_document(&identity)).expect("write");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let reference = ProtectedReference::parse(&format!("file:{}", path.display())).expect("path");
    assert!(matches!(
        InstallationIdentity::discover(&reference),
        Err(IdentityError::ReferenceUnsafe)
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parent directory gets CFG-023's posture: `write_new` creates it at
/// mode `0700` when absent — pinned explicitly so a permissive umask cannot
/// widen it — and the document inside it stays free of group/other bits.
#[test]
#[cfg(unix)]
fn write_new_creates_the_parent_directory_restrictively() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("create-parent");
    let nested = dir.join("state").join("archivist");
    let path = nested.join("identity.json");

    let identity = InstallationIdentity::generate().expect("entropy available");
    identity.write_new(&path).expect("write creates the parent");

    let parent_mode = std::fs::metadata(&nested)
        .expect("stat parent")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700, "created parent is exactly 0700");
    let document_mode = std::fs::metadata(&path)
        .expect("stat document")
        .permissions()
        .mode();
    assert_eq!(
        document_mode & 0o077,
        0,
        "no group or other permission bits: {document_mode:o}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A parent directory that pre-exists at any mode other than `0700` is
/// refused, and no document is created under it (CFG-023 refuses the unsafe
/// state rather than adopting it).
#[test]
#[cfg(unix)]
fn write_new_refuses_a_loose_parent_directory() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("refuse-loose-parent");
    let path = dir.join("identity.json");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    let identity = InstallationIdentity::generate().expect("entropy available");
    assert_eq!(
        identity.write_new(&path),
        Err(IdentityError::ReferenceUnsafe)
    );
    assert!(
        !path.exists(),
        "no document may be created under an unsafe parent"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The identity bytes of `identity`, for tests that plant a document on
/// disk directly.
fn persisted_document(identity: &InstallationIdentity) -> Vec<u8> {
    // Re-serialize through the same canonical document the store writes by
    // round-tripping: persist to a scratch file and read those bytes.
    let dir = temp_dir("helper");
    let path = dir.join("identity.json");
    identity.write_new(&path).expect("scratch write");
    let bytes = std::fs::read(&path).expect("scratch read");
    let _ = std::fs::remove_dir_all(&dir);
    bytes
}

/// Every malformed or self-inconsistent document is the same corrupt class:
/// wrong schema token, missing member, unknown member, non-lowercase seed,
/// seed not deriving the public key, key ID not deriving from the key.
#[test]
#[cfg(unix)]
fn discover_refuses_corrupt_documents() {
    let dir = temp_dir("corrupt");
    let cases: Vec<(&str, String)> = vec![
        (
            "wrong-schema",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"f73dbfbe94e80ac7c4fc866d17776620c44f45d8a91bb14b4ba47f96b78f7a61","private_seed":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v2"}"#.to_owned(),
        ),
        (
            "missing-member",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"f73dbfbe94e80ac7c4fc866d17776620c44f45d8a91bb14b4ba47f96b78f7a61","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v1"}"#.to_owned(),
        ),
        (
            "unknown-member",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"f73dbfbe94e80ac7c4fc866d17776620c44f45d8a91bb14b4ba47f96b78f7a61","private_seed":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v1","tenant_hint":"0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b"}"#.to_owned(),
        ),
        (
            "uppercase-seed",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"f73dbfbe94e80ac7c4fc866d17776620c44f45d8a91bb14b4ba47f96b78f7a61","private_seed":"9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v1"}"#.to_owned(),
        ),
        (
            "seed-not-deriving-key",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"f73dbfbe94e80ac7c4fc866d17776620c44f45d8a91bb14b4ba47f96b78f7a61","private_seed":"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v1"}"#.to_owned(),
        ),
        (
            "key-id-not-deriving-from-key",
            r#"{"client_id":"11111111-2222-4333-8444-555555555555","key_algorithm":"ed25519","key_id":"e48500b3a46a539f5662286364536e23e1168ba681e8d4b614355704ffbc6bf9","private_seed":"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60","public_key":"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a","schema":"archivist.client-identity/v1"}"#.to_owned(),
        ),
        (
            "not-an-object",
            "[1,2,3]".to_owned(),
        ),
        (
            "truncated-json",
            r#"{"client_id":"11111111""#.to_owned(),
        ),
    ];
    for (tag, document) in cases {
        let path = dir.join(format!("{tag}.json"));
        std::fs::write(&path, document).expect("plant document");
        // CFG-030: discovery checks the mode before it parses a byte, so a
        // planted document must carry a passing mode (0600) or every case
        // below would be refused as ReferenceUnsafe instead of reaching the
        // corrupt-content classes these cases exist to pin.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("set mode on planted document");
        }
        let reference =
            ProtectedReference::parse(&format!("file:{}", path.display())).expect("path");
        assert!(
            matches!(
                InstallationIdentity::discover(&reference),
                Err(IdentityError::IdentityCorrupt)
            ),
            "case {tag} must be refused"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The acceptance property: no serialization, diagnostic, or debug output
/// this crate produces contains the private seed — as hex, as bytes, or as
/// a fragment — while every public member does appear where it should.
#[test]
fn no_output_reveals_the_private_seed() {
    use std::fmt::Write as _;

    let identity = fixed_identity();
    let seed_hex = {
        let mut text = String::new();
        for byte in FIXED_SEED {
            let _ = write!(text, "{byte:02x}");
        }
        text
    };
    // Even fragments of the private half must not leak.
    let seed_fragments = [
        seed_hex.as_str(),
        &seed_hex[..16],
        &seed_hex[24..40],
        &seed_hex[48..],
    ];

    // 1. Debug and Display of every type that touches the seed.
    let debug_outputs = [
        format!("{identity:?}"),
        format!("{:?}", identity.signing_key()),
        format!("{:?}", identity.public_identity()),
    ];
    let reference_target = temp_dir("leak-scan");
    let path = reference_target.join("identity.json");
    identity.write_new(&path).expect("write for leak scan");
    // The document on disk is the one sanctioned home for the seed.
    let document = std::fs::read(&path).expect("read back");
    assert!(
        window_contains(&document, seed_hex.as_bytes()),
        "sanity: the document holds the seed"
    );

    // 2. Every error path: messages must not carry path or value.
    let error_outputs: Vec<String> = [
        IdentityError::ReferenceGrammar,
        IdentityError::ReferenceMissing,
        IdentityError::ReferenceUnsafe,
        IdentityError::ReferenceUnreadable,
        IdentityError::ReferenceUnsupportedPlatform,
        IdentityError::IdentityCorrupt,
        IdentityError::IdentityExists,
        IdentityError::Entropy,
    ]
    .iter()
    .map(|error| format!("{error}"))
    .collect();

    // 3. The link request document and its debug.
    let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").expect("grammar");
    let scopes = RequestedScopes::new(
        vec![HarnessId::parse("claude-code").expect("grammar")],
        vec![ScopeOperation::Ingest],
    )
    .expect("well-formed");
    let request = LinkRequest::new(identity.public_identity(), tenant, scopes);
    let mut link_bytes = request.canonical_bytes();
    link_bytes.extend_from_slice(format!("{request:?}").as_bytes());

    for output in debug_outputs
        .iter()
        .map(String::as_bytes)
        .chain(core::iter::once(link_bytes.as_slice()))
        .chain(error_outputs.iter().map(String::as_bytes))
    {
        for fragment in seed_fragments {
            assert!(
                !window_contains(output, fragment.as_bytes()),
                "private seed fragment leaked: output was {:?}",
                String::from_utf8_lossy(output)
            );
        }
        assert!(
            !window_contains(output, &FIXED_SEED),
            "raw seed bytes leaked into output"
        );
    }

    // And the public members do appear in the link request, proving the
    // absence above is not an absence of the identity itself.
    let link_text = String::from_utf8(request.canonical_bytes()).expect("utf-8");
    assert!(link_text.contains(&identity.public_identity().public_key.to_hex()));
    assert!(link_text.contains(&identity.public_identity().key_id.to_hex()));

    let _ = std::fs::remove_dir_all(&reference_target);
}

/// The link request is built from the identity document on disk: the
/// public key it carries is exactly the `public_key` member persisted in
/// that document, recovered through a protected reference — the request
/// advertises the persisted key, never a freshly minted one.
#[test]
#[cfg(unix)]
fn link_request_key_matches_the_persisted_document() {
    let dir = temp_dir("link-request-key");
    let path = dir.join("identity.json");

    let identity = fixed_identity();
    identity.write_new(&path).expect("persist identity");
    let document = std::fs::read(&path).expect("read persisted document");

    // The key as persisted, read straight out of the document bytes.
    let persisted = archivist_protocol::json::parse(&document).expect("canonical document");
    let archivist_protocol::json::Value::Object(members) = persisted else {
        panic!("identity document is an object");
    };
    let persisted_key = match members.get("public_key") {
        Some(archivist_protocol::json::Value::Text(hex)) => hex.clone(),
        other => panic!("public_key member: {other:?}"),
    };

    let reference = ProtectedReference::parse(&format!("file:{}", path.display())).expect("path");
    let discovered = InstallationIdentity::discover(&reference).expect("discover");

    let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").expect("grammar");
    let scopes = RequestedScopes::new(
        vec![HarnessId::parse("claude-code").expect("grammar")],
        vec![ScopeOperation::Ingest],
    )
    .expect("well-formed");
    let request = LinkRequest::new(discovered.public_identity(), tenant, scopes);

    // The request carries exactly the persisted key: same hex as the
    // document member, present in the serialized request, and equal to the
    // identity it was discovered from.
    assert_eq!(request.identity.public_key.to_hex(), persisted_key);
    let link_text = String::from_utf8(request.canonical_bytes()).expect("utf-8");
    assert!(
        link_text.contains(&persisted_key),
        "the request must carry the persisted public key"
    );
    assert_eq!(
        request.identity.public_key,
        identity.public_identity().public_key
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Substring containment over byte windows.
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
