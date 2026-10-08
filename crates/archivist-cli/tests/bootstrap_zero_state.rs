// SPDX-License-Identifier: Apache-2.0

//! Executable proof of the released zero-state entry commands.
//!
//! The child processes use an empty state directory and an empty authority
//! destination.  The test observes the same public envelopes an adopter gets
//! from the binary, checks the protected-file modes, and runs the link command
//! twice to prove that a restart reuses the installation identity rather than
//! minting a second client key.  Storage credentials are deliberately dummy
//! protected references: these two local commands do not open a backend.

use std::process::{Command, Output};

use archivist_protocol::json::{self, Value};

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

fn workspace_environment(command: &mut Command) {
    command
        .env_clear()
        .env("ARCHIVIST_INGEST_ENDPOINT_URL", "http://127.0.0.1:8080")
        .env("ARCHIVIST_STORAGE_ENDPOINT_URL", "http://127.0.0.1:9000")
        .env("ARCHIVIST_STORAGE_REGION", "us-east-1")
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "s3_sse")
        .env("ARCHIVIST_STORAGE_RAW_BUCKET", "empty-raw")
        .env("ARCHIVIST_STORAGE_CONTROL_BUCKET", "empty-control")
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            "env:BOOTSTRAP_RAW_CREDENTIAL",
        )
        .env(
            "ARCHIVIST_STORAGE_CONTROL_READ_CREDENTIALS_REF",
            "env:BOOTSTRAP_CONTROL_CREDENTIAL",
        )
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:0")
        .env("ARCHIVIST_ADMIN_TENANT", TENANT);
}

fn run(arguments: &[&str], state_dir: &std::path::Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_archivist"));
    workspace_environment(&mut command);
    command
        .env("ARCHIVIST_CLIENT_STATE_DIR", state_dir)
        .env("ARCHIVIST_CLIENT_TENANT", TENANT)
        .env("ARCHIVIST_CLIENT_HARNESS", "codex")
        .args(arguments)
        .output()
        .expect("archivist child process")
}

fn result(output: &Output) -> Value {
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let document = json::parse(&output.stdout).expect("canonical CLI envelope");
    let Value::Object(envelope) = document else {
        panic!("CLI output is not an object");
    };
    match envelope.get("result") {
        Some(value) => value.clone(),
        None => panic!("CLI envelope has no result"),
    }
}

fn member<'a>(value: &'a Value, name: &str) -> Option<&'a Value> {
    match value {
        Value::Object(object) => object.get(name),
        _ => None,
    }
}

#[test]
#[allow(clippy::too_many_lines)] // one adopter path, asserted in execution order
fn empty_state_can_mint_authority_and_reusable_public_link_request() {
    let root = std::env::temp_dir().join(format!(
        "archivist-bootstrap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    let state_dir = root.join("client-state");
    let authority_path = root.join("admin").join("authority-seed");

    let authority_output = run(
        &[
            "--non-interactive",
            "--json",
            "admin",
            "create-authority",
            authority_path.to_str().expect("authority path"),
        ],
        &state_dir,
    );
    let authority = result(&authority_output);
    assert_eq!(
        member(&authority, "schema"),
        Some(&Value::Text("archivist.cli-result/v1".to_owned()))
    );
    assert_eq!(
        member(&authority, "tenant_id"),
        Some(&Value::Text(TENANT.to_owned()))
    );
    assert!(member(&authority, "authority_key").is_some());
    assert!(member(&authority, "authority_key_id").is_some());
    assert!(
        String::from_utf8_lossy(&authority_output.stdout)
            .find("private_seed")
            .is_none()
    );
    assert!(
        String::from_utf8_lossy(&authority_output.stdout)
            .find("authority_seed")
            .is_none()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&authority_path)
                .expect("authority seed")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(authority_path.parent().expect("authority parent"))
                .expect("authority parent")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    let first_link_output = run(
        &["--non-interactive", "--json", "link", "request"],
        &state_dir,
    );
    let first_link = result(&first_link_output);
    assert_eq!(
        member(&first_link, "schema"),
        Some(&Value::Text("archivist.link-request/v1".to_owned()))
    );
    assert_eq!(
        member(&first_link, "requested_tenant_id"),
        Some(&Value::Text(TENANT.to_owned()))
    );
    assert!(member(&first_link, "client_id").is_some());
    assert!(member(&first_link, "public_key").is_some());
    assert!(member(&first_link, "private_seed").is_none());
    assert!(
        String::from_utf8_lossy(&first_link_output.stdout)
            .find("private_seed")
            .is_none()
    );

    let second_link_output = run(
        &["--non-interactive", "--json", "link", "request"],
        &state_dir,
    );
    let second_link = result(&second_link_output);
    assert_eq!(first_link, second_link);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let identity_path = state_dir.join("identity.json");
        assert_eq!(
            std::fs::metadata(identity_path)
                .expect("client identity")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(&state_dir)
                .expect("client state")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    std::fs::remove_dir_all(root).expect("remove bootstrap test state");
}
