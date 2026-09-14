// SPDX-License-Identifier: Apache-2.0

//! End-to-end secret-hygiene acceptance tests for the identity surface
//! (SEC-004, SEC-006), proving the two acceptance properties of protected
//! client identity over the real cycle a client runs.
//!
//! One: every code path that creates or rewrites the identity document
//! leaves the filesystem restrictive — the document at exactly `0600` and
//! every directory the write creates at exactly `0700` — including the
//! reload-and-save path (discover a persisted document, persist it again
//! elsewhere: the restore/migration cycle).
//!
//! Two: nothing the whole cycle *emits* contains the private seed or an
//! authorization value. The crate is log-free by construction (no logging
//! dependency; see the dependency boundary in `lib.rs`), so a command's
//! diagnostic surface is its process's own stdout and stderr — that output
//! is captured wholesale from a child process running the full cycle, after
//! the child has rendered every observable the surface can produce:
//! `Debug`/`Display` of every type that touches identity material, every
//! failure class, the protected-reference renderings, and the link-request
//! serialization. Scanning the captured bytes catches a leak from any layer,
//! including the test harness itself.

use std::path::PathBuf;
use std::process::Command;

use archivist_auth::identity::InstallationIdentity;
use archivist_auth::link::{LinkRequest, RequestedScopes, ScopeOperation};
use archivist_auth::reference::ProtectedReference;
use archivist_protocol::vocabulary::{Ed25519PublicKey, HarnessId, TenantId};

/// A fixed synthetic seed (the RFC 8032 §7.1 vector seed) so every byte the
/// child cycle emits is scannable against a known private half. Not a
/// credential: it is test data, and no output this suite prints may contain
/// it (pinned below).
const FIXED_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// Environment gate the parent test sets when it spawns the child cycle; a
/// normal suite run leaves it unset and the child test is a no-op.
const CHILD_GATE: &str = "ARCHIVE_SECRET_HYGIENE_CHILD";

/// Carries the child's scratch directory from the parent, so both sides
/// scan for exactly the same path string.
const CHILD_DIR_VAR: &str = "ARCHIVE_SECRET_HYGIENE_DIR";

/// Carries a distinctive synthetic authorization value the child resolves
/// through an `env:` reference — the crate's authorization-value channel —
/// and must never emit.
const AUTH_SAMPLE_VAR: &str = "ARCHIVE_SECRET_HYGIENE_AUTH_SAMPLE";

/// The synthetic authorization value itself.
const AUTH_SAMPLE: &str = "auth-sample-9e4adc51f07b42d6";

/// A well-formed `env:` name that is never set: the missing-authorization
/// failure path.
const AUTH_UNSET_VAR: &str = "ARCHIVE_SECRET_HYGIENE_UNSET_9E4ADC51";

fn fixed_identity() -> InstallationIdentity {
    let client_id =
        archivist_protocol::vocabulary::ClientId::parse("11111111-2222-4333-8444-555555555555")
            .expect("grammar");
    let public =
        Ed25519PublicKey::parse("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
            .expect("grammar");
    InstallationIdentity::from_seed(client_id, FIXED_SEED, public).expect("consistent parts")
}

fn seed_hex() -> String {
    use std::fmt::Write as _;

    let mut text = String::new();
    for byte in FIXED_SEED {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "archivist-hygiene-{tag}-{}-{}",
        std::process::id(),
        std::thread::current()
            .name()
            .unwrap_or("t")
            .replace('/', "-")
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir mode");
    }
    dir
}

/// Substring containment over byte windows.
fn window_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The reload-and-save path — discover a persisted document through a
/// protected reference and persist the identity again under a directory
/// that does not exist yet — leaves the filesystem exactly as restrictive
/// as the first write: every document at exactly `0600`, every directory
/// the writes created at exactly `0700`, and the round-tripped identity
/// bit-identical in its public members. The fresh-mint (OS entropy) write
/// is pinned by the same exact-mode assertion.
#[test]
#[cfg(unix)]
fn reload_and_save_keeps_every_mode_restrictive() {
    use std::os::unix::fs::PermissionsExt as _;

    let dir = temp_dir("reload-save");
    let initial = dir.join("identity.json");
    let identity = fixed_identity();
    identity.write_new(&initial).expect("initial write");

    // The fresh-mint path, from OS entropy, into a parent that does not
    // exist yet — the same exact posture.
    let minted = InstallationIdentity::generate().expect("entropy available");
    let minted_path = dir.join("minted").join("identity.json");
    minted.write_new(&minted_path).expect("fresh-mint write");

    // Discover the persisted document and save it again — the
    // restore/migration cycle — into a parent that does not exist yet.
    let reference =
        ProtectedReference::parse(&format!("file:{}", initial.display())).expect("path");
    let discovered = InstallationIdentity::discover(&reference).expect("discover");
    let nested = dir.join("state").join("archivist");
    let saved = nested.join("identity.json");
    discovered.write_new(&saved).expect("reload-and-save write");

    for (tag, path) in [
        ("initial", &initial),
        ("fresh-minted", &minted_path),
        ("reloaded-and-saved", &saved),
    ] {
        let mode = std::fs::metadata(path)
            .expect("stat document")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "{tag} document is exactly 0600: {mode:o}"
        );
    }
    for (tag, path) in [("minted", &dir.join("minted")), ("saved", &nested)] {
        let mode = std::fs::metadata(path)
            .expect("stat parent")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "{tag} parent directory is exactly 0700: {mode:o}"
        );
    }

    // The document at the new location discovers to the same identity.
    let saved_reference =
        ProtectedReference::parse(&format!("file:{}", saved.display())).expect("path");
    let reloaded = InstallationIdentity::discover(&saved_reference).expect("second discover");
    assert_eq!(reloaded.client_id(), identity.client_id());
    assert_eq!(reloaded.public_identity(), identity.public_identity());

    let _ = std::fs::remove_dir_all(&dir);
}

/// The child half of the process-output scan. With the gate unset — every
/// normal suite run — this returns immediately; with the gate set, the
/// parent test below runs the full identity cycle here and scans everything
/// this process emits.
#[test]
#[cfg(unix)]
fn process_output_hygiene_cycle_child() {
    let Some(dir) = std::env::var_os(CHILD_DIR_VAR).map(PathBuf::from) else {
        return; // gate not set: a no-op under a normal suite run
    };
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("child scratch dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("child scratch dir mode");
    }

    // -- the cycle ------------------------------------------------------
    let identity = fixed_identity();
    let path = dir.join("identity.json");
    identity.write_new(&path).expect("initial write");
    let reference = ProtectedReference::parse(&format!("file:{}", path.display())).expect("path");
    let discovered = InstallationIdentity::discover(&reference).expect("discover");

    // An authorization value enters only through a protected reference.
    // The parent set the variable in this process's environment; resolve it
    // for real and drop it — no output may ever carry it. (The environment
    // is only read; nothing here writes it.)
    let auth_sample = std::env::var(AUTH_SAMPLE_VAR).expect("authorization sample is set");
    let auth_reference =
        ProtectedReference::parse(&format!("env:{AUTH_SAMPLE_VAR}")).expect("env grammar");
    let resolved = auth_reference.resolve().expect("env target resolves");
    assert_eq!(
        resolved,
        auth_sample.as_bytes(),
        "sanity: the authorization value resolves"
    );
    drop(resolved);

    // The reload-and-save path, so every write of the cycle is exercised.
    let nested = dir.join("state").join("archivist");
    let saved = nested.join("identity.json");
    discovered.write_new(&saved).expect("reload-and-save write");
    let saved_reference =
        ProtectedReference::parse(&format!("file:{}", saved.display())).expect("path");
    let reloaded = InstallationIdentity::discover(&saved_reference).expect("second discover");

    let tenant = TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").expect("grammar");
    let scopes = RequestedScopes::new(
        vec![HarnessId::parse("claude-code").expect("grammar")],
        vec![ScopeOperation::Ingest],
    )
    .expect("well-formed scope");
    let request = LinkRequest::new(reloaded.public_identity(), tenant, scopes);

    // -- everything the surface can render, emitted for real -------------
    // Debug and Display of every type that touches identity material, the
    // protected-reference renderings, the scope, and the wire document,
    // printed the way a command would print them.
    for rendered in [
        format!("{identity:?}"),
        format!("{:?}", identity.signing_key()),
        format!("{:?}", identity.public_identity()),
        format!("{reference:?}"),
        format!("{reference}"),
        format!("{auth_reference:?}"),
        format!("{auth_reference}"),
        format!("{request:?}"),
        format!("{:?}", request.scopes),
        String::from_utf8(request.canonical_bytes()).expect("canonical JSON is utf-8"),
    ] {
        println!("{rendered}");
    }

    emit_failure_renderings(&dir, &path);

    let _ = std::fs::remove_dir_all(&dir);
}

/// Drive every failure class through a real refusal — grammar, missing
/// targets, loose mode, corrupt document, overwrite — and render each on
/// stderr, both `Display` and `Debug`, the way a command's error path
/// would print it.
#[cfg(unix)]
fn emit_failure_renderings(dir: &std::path::Path, identity_path: &std::path::Path) {
    let corrupt_path = dir.join("corrupt.json");
    std::fs::write(
        &corrupt_path,
        r#"{"schema":"archivist.client-identity/v2"}"#,
    )
    .expect("plant corrupt document");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&corrupt_path, std::fs::Permissions::from_mode(0o600))
            .expect("corrupt document mode");
    }
    let corrupt_reference =
        ProtectedReference::parse(&format!("file:{}", corrupt_path.display())).expect("path");
    let loose_path = dir.join("loose.json");
    std::fs::write(&loose_path, b"never read: the mode check fires first").expect("plant loose");
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&loose_path, std::fs::Permissions::from_mode(0o644))
            .expect("loose document mode");
    }
    let loose_reference =
        ProtectedReference::parse(&format!("file:{}", loose_path.display())).expect("path");
    let absent_reference =
        ProtectedReference::parse(&format!("file:{}", dir.join("absent.json").display()))
            .expect("path");
    let unset_reference =
        ProtectedReference::parse(&format!("env:{AUTH_UNSET_VAR}")).expect("env grammar");
    let generated = InstallationIdentity::generate().expect("entropy available");

    let failures: Vec<String> = [
        ProtectedReference::parse("not-a-reference").expect_err("outside the grammar"),
        ProtectedReference::parse("file:relative/segment").expect_err("relative path"),
        ProtectedReference::parse("env:lowercase_name").expect_err("outside the env grammar"),
        absent_reference
            .resolve()
            .map(|_| ())
            .expect_err("target is absent"),
        unset_reference
            .resolve()
            .map(|_| ())
            .expect_err("variable is unset"),
        loose_reference
            .resolve()
            .map(|_| ())
            .expect_err("loose mode is refused"),
        InstallationIdentity::discover(&corrupt_reference)
            .map(|_| ())
            .expect_err("corrupt document is refused"),
        generated
            .write_new(identity_path)
            .expect_err("overwrite is refused"),
    ]
    .into_iter()
    .flat_map(|error| [format!("{error}"), format!("{error:?}")])
    .collect();
    for rendered in &failures {
        eprintln!("{rendered}");
    }
}

/// The acceptance property at the only layer a leak is actually observable:
/// the process's own output. The full cycle — mint, persist, discover,
/// resolve an authorization reference, reload-and-save, link-request
/// serialization, and every rendered diagnostic — runs in a child process
/// whose complete stdout and stderr are captured and scanned for the
/// private seed (whole, as hex, and as fragments), the raw seed bytes, the
/// authorization value, and the scratch path. Zero hits, while the public
/// members must appear — proving the scan is not vacuous. On failure the
/// mismatch names the token class only; the output is never re-printed.
#[test]
#[cfg(unix)]
fn process_output_reveals_no_private_material() {
    let binary = std::env::current_exe().expect("test binary");
    let dir = temp_dir("process-output");

    let output = Command::new(&binary)
        .args([
            "--exact",
            "process_output_hygiene_cycle_child",
            "--nocapture",
        ])
        .env(CHILD_GATE, "1")
        .env(CHILD_DIR_VAR, &dir)
        .env(AUTH_SAMPLE_VAR, AUTH_SAMPLE)
        .output()
        .expect("spawn the child cycle");
    assert!(
        output.status.success(),
        "the child cycle failed; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut emitted = output.stdout.clone();
    emitted.extend_from_slice(&output.stderr);

    // The scan is not vacuous: the cycle really rendered the public
    // identity, and output really flowed.
    let public = fixed_identity().public_identity();
    let client_id = "11111111-2222-4333-8444-555555555555";
    for expected in [
        public.public_key.to_hex(),
        public.key_id.to_hex(),
        client_id.to_owned(),
    ] {
        assert!(
            window_contains(&emitted, expected.as_bytes()),
            "positive control missing from captured output: {expected}"
        );
    }
    assert!(
        window_contains(&emitted, b"archivist.link-request/v1"),
        "positive control missing: the link-request serialization"
    );

    // Forbidden material: the seed as hex, as fragments, as raw bytes, the
    // authorization value, and the scratch path a command must not name.
    let hex = seed_hex().into_bytes();
    let forbidden: [(&str, Vec<u8>); 7] = [
        ("seed hex", hex.clone()),
        ("seed hex head", hex[..16].to_vec()),
        ("seed hex middle", hex[24..40].to_vec()),
        ("seed hex tail", hex[48..].to_vec()),
        ("raw seed bytes", FIXED_SEED.to_vec()),
        ("authorization value", AUTH_SAMPLE.as_bytes().to_vec()),
        (
            "scratch path",
            dir.to_str().expect("utf-8 temp dir").as_bytes().to_vec(),
        ),
    ];
    for (what, token) in &forbidden {
        assert!(
            !window_contains(&emitted, token),
            "private material leaked into process output: {what} (output suppressed)"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
