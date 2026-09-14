// SPDX-License-Identifier: Apache-2.0

//! Tests for the client configuration loader: tier precedence, the
//! unknown-name and type-grammar refusals, XDG/TOML discovery, the
//! protected-secret resolution checks, and the rule that every
//! diagnostic stays content-free.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use archivist_protocol::json;
use archivist_protocol::vocabulary::RequestId;

use super::registry;
use super::{ConfigError, ConfigErrorCode, ConfigSources, Interactivity, ResolvedValue, SecretRef};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

/// A private directory removed on drop, so file-backed tests never share
/// state and never leave debris behind.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let n = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("archivist-config-{tag}-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The synthetic environment of a fully-declared host: `HOME` plus every
/// required key through the environment tier, so the defaults and the
/// required-resolution paths both run on every load. The two secret
/// references point at `env:` targets outside the reserved prefix and
/// are never resolved during load; only the raw-write target is actually
/// set, so the control-read one doubles as the refused-env fixture.
fn base_sources() -> ConfigSources {
    ConfigSources::non_interactive()
        .env("HOME", "/home/operator")
        .env("TEST_RAW_CREDENTIAL", "fixture-raw-credential")
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
}

fn write_config(dir: &TempDir, body: &str) -> std::path::PathBuf {
    let path = dir.path().join("archivist.toml");
    std::fs::write(&path, body).expect("write config file");
    path
}

fn assert_usage(error: &ConfigError, field: &str) {
    assert_eq!(error.code(), ConfigErrorCode::Usage, "{error}");
    assert_eq!(error.field(), Some(field), "{error}");
    assert_eq!(error.exit_code(), 64, "{error}");
}

/// Blank the 36-character correlation value so two bodies of the same
/// condition compare equal.
fn with_masked_correlation(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let marker = "\"correlation_id\":\"";
    let at = text.find(marker).expect("correlation member present") + marker.len();
    format!("{}{}", &text[..at], &text[at + 36..])
}

// --- resolution and precedence -------------------------------------------

#[test]
fn defaults_apply_and_typed_accessors_resolve() {
    let config = base_sources().load().expect("fully declared host loads");
    assert_eq!(
        config.state_dir(),
        Path::new("/home/operator/.local/state/archivist")
    );
    assert_eq!(config.spool_max_bytes(), 2_147_483_648);
    assert_eq!(config.spool_free_floor_bytes(), 5_368_709_120);
    assert_eq!(config.spool_resume_percent(), 80);
    assert_eq!(config.schedule_interval_seconds(), 900);
    assert_eq!(config.schedule_jitter_percent(), 10);
    assert_eq!(config.schedule_backfill_quantum_bytes(), 268_435_456);
    assert_eq!(
        config.ingest_endpoint_url(),
        "https://ingest.example.invalid"
    );
    // An enum default resolves through the same text grammar.
    assert_eq!(config.text("storage.path_style"), Some("path"));
    assert_eq!(config.text("storage.encryption"), Some("s3_sse"));
    // Every registered key with a defined resolution resolved exactly
    // once; the optional credential references are deliberately absent,
    // which is the empty resolution their optionality pins (CFG-019).
    let optional_count = registry::config_registry()
        .keys()
        .iter()
        .filter(|key| key.optional())
        .count();
    assert_eq!(
        config.iter().count(),
        registry::config_registry().keys().len() - optional_count,
        "one resolved value per non-optional registered key"
    );
    assert!(
        config.reference("storage.raw_read_credentials_ref").is_none(),
        "an optional reference absent from every tier resolves to nothing"
    );
    assert!(
        config
            .reference("storage.offline_restore_credentials_ref")
            .is_none()
    );
    assert_eq!(
        config
            .iter()
            .filter(|(_, value)| matches!(value, ResolvedValue::Reference(_)))
            .count(),
        2,
        "the two secret references resolved as references"
    );
}

#[test]
fn precedence_is_flag_then_env_then_file_then_default() {
    let dir = TempDir::new("precedence");
    let path = write_config(&dir, "[spool]\nmax_bytes = 111111111\n");
    let sources = |flag: bool, env: bool| {
        let mut sources = base_sources()
            .config_path(path.clone())
            .env("ARCHIVIST_SPOOL_MAX_BYTES", "222222222");
        if !env {
            sources.env.remove("ARCHIVIST_SPOOL_MAX_BYTES");
        }
        if flag {
            sources = sources.flag("--spool-max-bytes", "333333333");
        }
        sources
    };
    assert_eq!(
        sources(true, true).load().expect("load").spool_max_bytes(),
        333_333_333
    );
    assert_eq!(
        sources(false, true).load().expect("load").spool_max_bytes(),
        222_222_222
    );
    assert_eq!(
        sources(false, false)
            .load()
            .expect("load")
            .spool_max_bytes(),
        111_111_111
    );
    // No tier at all: the registry default (drop the file selection too).
    let mut bare = base_sources();
    bare.env.remove("ARCHIVIST_SPOOL_MAX_BYTES");
    let config = bare.load().expect("load");
    assert_eq!(config.spool_max_bytes(), 2_147_483_648);
}

#[test]
fn a_shadowed_malformed_tier_value_still_fails() {
    // The flag wins the tier, but the environment value under it must
    // still announce itself (CFG-010 strictness).
    let error = base_sources()
        .env("ARCHIVIST_SPOOL_MAX_BYTES", "not-a-number")
        .flag("--spool-max-bytes", "1073741824")
        .load()
        .expect_err("malformed losing tier");
    assert_usage(&error, "spool.max_bytes");
}

#[test]
fn each_tier_resolves_alone() {
    // Flag alone.
    let flag_only = base_sources().flag("spool-max-bytes", "1048576");
    assert_eq!(flag_only.load().expect("load").spool_max_bytes(), 1_048_576);
    // File alone.
    let dir = TempDir::new("file-alone");
    let path = write_config(&dir, "[spool]\nmax_bytes = 2097152\n");
    let config = base_sources().config_path(path).load().expect("load");
    assert_eq!(config.spool_max_bytes(), 2_097_152);
}

// --- unknown names and duplicate flags -----------------------------------

#[test]
fn unknown_file_key_is_a_usage_error() {
    let dir = TempDir::new("unknown-file-key");
    let path = write_config(&dir, "[client]\nbogus = true\n");
    let error = base_sources()
        .config_path(path)
        .load()
        .expect_err("unknown key");
    assert_usage(&error, "client.bogus");
}

#[test]
fn unknown_environment_name_is_a_usage_error() {
    let error = base_sources()
        .env("ARCHIVIST_NOT_A_KEY", "1")
        .load()
        .expect_err("unknown env name");
    assert_usage(&error, "not_a_key");
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let error = base_sources()
        .flag("--not-a-flag", "1")
        .load()
        .expect_err("unknown flag");
    assert_usage(&error, "not-a-flag");
}

#[test]
fn a_repeated_flag_is_refused() {
    let error = base_sources()
        .flag("--spool-max-bytes", "1048576")
        .flag("--spool-max-bytes", "2097152")
        .load()
        .expect_err("repeated flag");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
    assert_eq!(error.field(), Some("spool.max_bytes"));
}

#[test]
fn secret_keys_never_accept_a_flag() {
    // CFG-031/CLI-024: there is no spelling by which a secret lands in
    // argv, because the loader refuses the tier outright.
    for token in [
        "storage-raw-write-credentials-ref",
        "--storage-control-read-credentials-ref",
    ] {
        let error = base_sources()
            .flag(token, "file:/etc/archivist/credentials")
            .load()
            .expect_err("secret flag refused");
        assert_eq!(error.code(), ConfigErrorCode::Usage, "{error}");
        assert_eq!(
            error.field(),
            Some(token.trim_start_matches('-')),
            "{error}"
        );
    }
}

// --- type grammar ---------------------------------------------------------

#[test]
fn integer_bounds_hold_in_every_tier() {
    for (value, field) in [
        ("0", "spool.max_bytes"),               // _bytes minimum is 1
        ("281474976710657", "spool.max_bytes"), // 2^48 + 1
        ("-1", "spool.max_bytes"),
        ("not-a-number", "spool.max_bytes"),
        ("3.5", "spool.max_bytes"),
        ("101", "spool.resume_percent"), // _percent maximum is 100
        ("-1", "spool.resume_percent"),
    ] {
        let mut sources = base_sources()
            .env("ARCHIVIST_SPOOL_MAX_BYTES", "1048576")
            .env("ARCHIVIST_SPOOL_RESUME_PERCENT", "50");
        sources = sources
            .env(
                &format!("ARCHIVIST_{}", field.replace('.', "_").to_uppercase()),
                value,
            )
            .clone();
        let error = sources.load().unwrap_err();
        assert_usage(&error, field);
    }
    // The same refusals through the flag tier.
    for value in ["0", "281474976710657", "abc"] {
        let error = base_sources()
            .flag("--spool-max-bytes", value)
            .load()
            .expect_err("flag-tier bounds");
        assert_usage(&error, "spool.max_bytes");
    }
    // The boundaries themselves resolve.
    let config = base_sources()
        .env("ARCHIVIST_SPOOL_RESUME_PERCENT", "100")
        .load()
        .expect("boundary value");
    assert_eq!(config.spool_resume_percent(), 100);
}

#[test]
fn string_grammar_holds() {
    let long = "a".repeat(129);
    for value in [long.as_str(), "brace{s}", "grüße", ""] {
        let error = base_sources()
            .env("ARCHIVIST_INGEST_ENDPOINT_URL", value)
            .load()
            .expect_err("string grammar");
        assert_usage(&error, "ingest.endpoint_url");
    }
    let boundary = "a".repeat(128);
    let config = base_sources()
        .env("ARCHIVIST_INGEST_ENDPOINT_URL", &boundary)
        .load()
        .expect("128 characters is in grammar");
    assert_eq!(config.ingest_endpoint_url(), boundary);
}

#[test]
fn enum_values_fail_closed() {
    let error = base_sources()
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "rot13")
        .load()
        .expect_err("unknown enum token");
    assert_usage(&error, "storage.encryption");
    let config = base_sources()
        .env("ARCHIVIST_STORAGE_PATH_STYLE", "virtual_hosted")
        .load()
        .expect("registered enum token");
    assert_eq!(config.text("storage.path_style"), Some("virtual_hosted"));
}

#[test]
fn file_tier_typed_values_must_match_their_key() {
    let dir = TempDir::new("file-typed");
    // Keys validate in registry order (name-sorted by the table
    // storage), so ingest.endpoint_url reports before spool.max_bytes.
    let path = write_config(&dir, "[spool]\nmax_bytes = 0\n[ingest]\nendpoint_url = 5\n");
    let error = base_sources()
        .config_path(path)
        .load()
        .expect_err("typed file values");
    assert_usage(&error, "ingest.endpoint_url");
}

// --- path values and XDG expansion ---------------------------------------

#[test]
fn path_values_expand_templates_and_reject_shorthand() {
    let cases = [
        // (value, env additions, expected)
        ("/var/lib/archivist", vec![], Some("/var/lib/archivist")),
        (
            "${XDG_STATE_HOME}/archivist",
            vec![("XDG_STATE_HOME", "/var/lib")],
            Some("/var/lib/archivist"),
        ),
        (
            "${XDG_STATE_HOME}",
            vec![("XDG_STATE_HOME", "/var/lib")],
            Some("/var/lib"),
        ),
        (
            "${XDG_STATE_HOME}/archivist",
            vec![("XDG_STATE_HOME", "relative/ignored")],
            Some("/home/operator/.local/state/archivist"),
        ),
        ("${HOME}/spool", vec![], Some("/home/operator/spool")),
        ("${HOME}", vec![], Some("/home/operator")),
        ("relative/path", vec![], None),
        ("~/spool", vec![], None),
        ("/a/../b", vec![], None),
        ("/a/./b", vec![], None),
        ("/tmp/trailing/", vec![], None),
        ("/tmp//double", vec![], None),
        ("${NOT_A_VARIABLE}/x", vec![], None),
        ("mid/${HOME}/dle", vec![], None),
    ];
    for (value, additions, expected) in cases {
        let mut sources = base_sources().env("ARCHIVIST_CLIENT_STATE_DIR", value);
        for (name, env_value) in additions {
            sources = sources.env(name, env_value);
        }
        match (expected, sources.load()) {
            (Some(expected), Ok(config)) => {
                assert_eq!(config.state_dir(), Path::new(expected), "value: {value}");
            }
            (None, Err(error)) => {
                assert_usage(&error, "client.state_dir");
            }
            (Some(expected), Err(error)) => {
                panic!("value {value} should resolve to {expected}: {error}");
            }
            (None, Ok(config)) => {
                panic!(
                    "value {value} should be refused, resolved to {}",
                    config.state_dir().display()
                );
            }
        }
    }
}

#[test]
fn missing_home_fails_the_state_dir_default_by_name() {
    let declared = ConfigSources::non_interactive()
        // Deliberately no HOME: XDG_STATE_HOME alone carries the default.
        .env("XDG_STATE_HOME", "/var/lib/archivist")
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
        .env("ARCHIVIST_SERVER_LISTEN_ADDRESS", "127.0.0.1:8087");
    let config = declared.load().expect("XDG_STATE_HOME covers the default");
    assert_eq!(
        config.state_dir(),
        Path::new("/var/lib/archivist/archivist")
    );
    // With neither variable the default cannot expand, and the failure
    // names the key that needed it (CFG-013).
    let mut undeclared = declared.clone();
    undeclared.env.remove("XDG_STATE_HOME");
    let error = undeclared.load().expect_err("state dir default needs HOME");
    assert_usage(&error, "client.state_dir");
}

// --- the file tier --------------------------------------------------------

#[test]
fn default_config_file_is_discovered_under_home() {
    let home = TempDir::new("default-config");
    let config_dir = home.path().join(".config").join("archivist");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("archivist.toml"),
        b"[spool]\nmax_bytes = 5242880\n",
    )
    .expect("write default config");
    let config = base_sources()
        .load()
        .expect("synthetic home has no config file");
    assert_eq!(config.spool_max_bytes(), 2_147_483_648);
    let config = base_sources()
        .env("HOME", home.path().to_str().expect("utf-8 temp path"))
        .load()
        .expect("default config discovered");
    assert_eq!(config.spool_max_bytes(), 5_242_880);
}

#[test]
fn xdg_config_home_overrides_the_default_location() {
    let home = TempDir::new("xdg-home");
    let xdg = TempDir::new("xdg-config");
    let config_dir = xdg.path().join("archivist");
    std::fs::create_dir_all(&config_dir).expect("create config dir");
    std::fs::write(
        config_dir.join("archivist.toml"),
        b"[spool]\nmax_bytes = 6291456\n",
    )
    .expect("write xdg config");
    let config = base_sources()
        .env("HOME", home.path().to_str().expect("utf-8 temp path"))
        .env(
            "XDG_CONFIG_HOME",
            xdg.path().to_str().expect("utf-8 temp path"),
        )
        .load()
        .expect("xdg config discovered");
    assert_eq!(config.spool_max_bytes(), 6_291_456);
}

#[test]
fn an_absent_default_file_is_fine_and_an_absent_selection_is_not() {
    // The base environment has no config file anywhere: fine.
    base_sources()
        .load()
        .expect("absent default file is not an error");
    // An explicitly selected file must exist.
    let dir = TempDir::new("absent-selection");
    let error = base_sources()
        .config_path(dir.path().join("missing.toml"))
        .load()
        .expect_err("selected file must exist");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
    assert_eq!(error.exit_code(), 64);
    // And it must be absolute (after ~ expansion).
    let error = base_sources()
        .config_path("relative/archivist.toml")
        .load()
        .expect_err("selected file must be absolute");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
}

#[test]
fn tilde_in_a_selected_path_expands_home() {
    let home = TempDir::new("tilde-home");
    std::fs::write(
        home.path().join("archivist.toml"),
        b"[spool]\nmax_bytes = 7340032\n",
    )
    .expect("write home config");
    let config = base_sources()
        .env("HOME", home.path().to_str().expect("utf-8 temp path"))
        .config_path("~/archivist.toml")
        .load()
        .expect("tilde expands");
    assert_eq!(config.spool_max_bytes(), 7_340_032);
}

#[test]
fn a_malformed_config_file_reports_its_line() {
    let dir = TempDir::new("malformed");
    let path = write_config(&dir, "[spool]\nmax_bytes =\n");
    let error = base_sources()
        .config_path(path)
        .load()
        .expect_err("malformed file");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
    assert_eq!(error.line(), Some(2), "{error}");
}

#[test]
fn secrets_may_arrive_through_the_file_tier() {
    let dir = TempDir::new("secret-file-tier");
    let path = write_config(
        &dir,
        "[storage]\nraw_write_credentials_ref = \"env:TEST_RAW_CREDENTIAL\"\n",
    );
    let mut sources = base_sources();
    sources
        .env
        .remove("ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF");
    let config = sources
        .config_path(path)
        .load()
        .expect("file-tier reference");
    assert!(matches!(
        config.value("storage.raw_write_credentials_ref"),
        Some(ResolvedValue::Reference(_))
    ));
}

#[test]
fn an_optional_reference_resolves_when_supplied_and_nothing_when_absent() {
    // Supplied through the environment tier, an optional reference is an
    // ordinary resolved reference.
    let granted = base_sources().env(
        "ARCHIVIST_STORAGE_RAW_READ_CREDENTIALS_REF",
        "env:TEST_RAW_CREDENTIAL",
    );
    let config = granted.load().expect("supplied optional reference");
    assert!(matches!(
        config.value("storage.raw_read_credentials_ref"),
        Some(ResolvedValue::Reference(_))
    ));
    // Absent from every tier it resolves to nothing — never a
    // decision-missing failure, which is reserved for required keys.
    let omitted = base_sources();
    let config = omitted.load().expect("omitted optional reference");
    assert!(config.reference("storage.raw_read_credentials_ref").is_none());
}

// --- required keys and the stable error surface ---------------------------

#[test]
fn a_missing_required_key_is_a_decision_missing_usage_error() {
    let mut sources = base_sources();
    sources.env.remove("ARCHIVIST_INGEST_ENDPOINT_URL");
    let error = sources.load().expect_err("required key missing");
    assert_eq!(error.code(), ConfigErrorCode::DecisionMissing);
    assert_eq!(error.field(), Some("ingest.endpoint_url"));
    assert_eq!(error.exit_code(), 64);
    assert!(
        !format!("{error}").to_lowercase().contains("prompt"),
        "the diagnostic must not promise a prompt: {error}"
    );
}

#[test]
fn the_error_body_is_the_closed_archivist_error_shape() {
    let mut sources = base_sources();
    sources.env.remove("ARCHIVIST_SERVER_LISTEN_ADDRESS");
    let error = sources.load().expect_err("required key missing");
    let body = error.error_body();
    let json::Value::Object(object) = &body else {
        panic!("the body is an object");
    };
    // The body schema is closed with exactly six members.
    let mut names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "code",
            "correlation_id",
            "message",
            "request_id",
            "retryable",
            "schema"
        ]
    );
    assert_eq!(
        object.get("schema"),
        Some(&json::Value::Text("archivist.error/v1".to_owned()))
    );
    assert_eq!(
        object.get("code"),
        Some(&json::Value::Text("cli.decision_missing".to_owned()))
    );
    assert_eq!(object.get("retryable"), Some(&json::Value::Bool(false)));
    assert_eq!(object.get("request_id"), Some(&json::Value::Null));
    assert_eq!(
        object.get("message"),
        Some(&json::Value::Text(
            "Non-interactive mode requires the server.listen_address decision; provide it by flag or configuration."
                .to_owned()
        ))
    );
    let correlation = match object.get("correlation_id") {
        Some(json::Value::Text(text)) => text.as_str(),
        other => panic!("correlation_id is text: {other:?}"),
    };
    RequestId::parse(correlation).expect("correlation_id is a canonical uuid v7");
    // Canonical bytes round-trip: the emitted form is already canonical.
    let bytes = error.error_body_bytes();
    let reparsed = json::parse(&bytes).expect("body parses as canonical json");
    assert_eq!(reparsed.canonical_bytes(), bytes);
}

#[test]
fn the_error_body_is_stable_except_for_the_correlation_id() {
    let mut first = base_sources();
    first.env.remove("ARCHIVIST_INGEST_ENDPOINT_URL");
    let mut second = base_sources();
    second.env.remove("ARCHIVIST_INGEST_ENDPOINT_URL");
    let one = first.load().expect_err("same condition twice");
    let two = second.load().expect_err("same condition twice");
    // Same condition: identical bodies once the per-event correlation
    // id is masked out; and each body carries its own fresh id.
    let one_body = one.error_body_bytes();
    let two_body = two.error_body_bytes();
    assert_eq!(
        with_masked_correlation(&one_body),
        with_masked_correlation(&two_body)
    );
    assert_ne!(
        one_body, two_body,
        "each body carries its own correlation id"
    );
}

#[test]
fn interactive_and_non_interactive_fail_identically() {
    // v1 never prompts (CLI-023): the mode changes nothing here.
    let mut interactive = ConfigSources::interactive();
    interactive.env = base_sources().env.clone();
    interactive.env.remove("ARCHIVIST_INGEST_ENDPOINT_URL");
    let mut non_interactive = base_sources();
    non_interactive.env.remove("ARCHIVIST_INGEST_ENDPOINT_URL");
    let interactive_error = interactive.load().expect_err("no prompt in v1");
    let non_interactive_error = non_interactive.load().expect_err("no prompt in v1");
    assert_eq!(interactive_error, non_interactive_error);
    assert_eq!(
        interactive.interactivity(),
        Interactivity::Interactive,
        "the mode is recorded without changing behavior"
    );
}

#[test]
fn daemon_construction_is_non_interactive() {
    let daemon = ConfigSources::daemon().expect("environment is valid utf-8");
    assert!(daemon.interactivity().is_non_interactive());
    // Loading never blocks on a tty: with the ambient environment the
    // outcome terminates without reading stdin.
    let outcome = daemon.load();
    assert!(
        outcome.is_ok()
            || matches!(
                &outcome,
                Err(error) if matches!(
                    error.code(),
                    ConfigErrorCode::DecisionMissing | ConfigErrorCode::Usage
                )
            ),
        "daemon load terminates without prompting"
    );
}

#[test]
fn the_environment_snapshot_captures_names() {
    let mut sources = ConfigSources::non_interactive()
        .capture_environment()
        .expect("capture");
    assert!(
        sources.env.remove("HOME").is_some(),
        "HOME is part of the snapshot"
    );
}

#[test]
fn correlation_ids_are_distinct_uuid_v7() {
    let one = super::mint_correlation_id();
    let two = super::mint_correlation_id();
    assert_ne!(one.as_str(), two.as_str());
    RequestId::parse(one.as_str()).expect("first mint parses");
    RequestId::parse(two.as_str()).expect("second mint parses");
}

// --- secret resolution ----------------------------------------------------

/// A secret-file fixture under its own mode.
#[cfg(unix)]
fn secret_fixture(contents: &[u8]) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new("secret");
    let path = dir.path().join("credentials");
    std::fs::write(&path, contents).expect("write secret fixture");
    (dir, path)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set fixture mode");
}

#[test]
fn an_environment_reference_resolves_and_missing_ones_refuse() {
    let config = base_sources().load().expect("load");
    let value = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect("env target is set in the snapshot");
    // A test fixture, not a credential: asserting the round trip is the
    // point of the test.
    assert_eq!(value.as_bytes(), b"fixture-raw-credential");
    assert!(!value.is_empty());
    let refused = config
        .resolve_secret("storage.control_read_credentials_ref")
        .expect_err("env target is not set");
    assert_eq!(refused.code(), ConfigErrorCode::SecretRefRefused);
    assert_eq!(
        refused.field(),
        Some("storage.control_read_credentials_ref")
    );
    assert_eq!(refused.exit_code(), 64);
}

#[test]
fn an_empty_environment_target_is_refused() {
    let config = base_sources()
        .env("TEST_RAW_CREDENTIAL", "")
        .load()
        .expect("empty targets parse; resolution refuses them");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("empty env target");
    assert_eq!(error.code(), ConfigErrorCode::SecretRefRefused);
}

#[cfg(unix)]
#[test]
fn secret_file_modes_are_enforced() {
    let (dir, path) = secret_fixture(b"fixture-credential\n");
    let reference = format!("file:{}", path.display());
    let load = |mode: u32| {
        set_mode(&path, mode);
        let config = base_sources()
            .env("ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF", &reference)
            .load()
            .expect("references never resolve at load");
        config.resolve_secret("storage.raw_write_credentials_ref")
    };
    assert_eq!(
        load(0o600).expect("0600 resolves").as_bytes(),
        b"fixture-credential"
    );
    assert_eq!(
        load(0o400).expect("0400 resolves").as_bytes(),
        b"fixture-credential"
    );
    for mode in [0o644u32, 0o660, 0o664, 0o777, 0o000] {
        let error = load(mode).expect_err("unsafe or unreadable mode");
        assert_eq!(
            error.code(),
            ConfigErrorCode::SecretRefRefused,
            "mode {mode:o}"
        );
        assert_eq!(error.field(), Some("storage.raw_write_credentials_ref"));
    }
    drop(dir);
}

#[cfg(unix)]
#[test]
fn secret_file_targets_must_be_regular_files() {
    let dir = TempDir::new("secret-directory");
    let directory_reference = format!("file:{}", dir.path().display());
    let config = base_sources()
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            &directory_reference,
        )
        .load()
        .expect("parse-only");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("a directory is not a secret file");
    assert_eq!(error.code(), ConfigErrorCode::SecretRefRefused);

    let missing_reference = "file:/etc/archivist/does-not-exist-at-all";
    let config = base_sources()
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            missing_reference,
        )
        .load()
        .expect("parse-only");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("missing target");
    assert_eq!(error.code(), ConfigErrorCode::SecretRefRefused);
}

#[cfg(unix)]
#[test]
fn secret_values_trim_exactly_one_trailing_newline() {
    for (contents, expected) in [
        (&b"abc\n"[..], &b"abc"[..]),
        (&b"abc\n\n"[..], &b"abc\n"[..]),
        (&b"abc"[..], &b"abc"[..]),
    ] {
        let (dir, path) = secret_fixture(contents);
        set_mode(&path, 0o600);
        let config = base_sources()
            .env(
                "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
                format!("file:{}", path.display()),
            )
            .load()
            .expect("load");
        let value = config
            .resolve_secret("storage.raw_write_credentials_ref")
            .expect("resolves");
        assert_eq!(value.as_bytes(), expected, "contents: {contents:?}");
        drop(dir);
    }
}

#[cfg(unix)]
#[test]
fn empty_and_oversized_secret_files_are_refused() {
    let (dir, path) = secret_fixture(b"");
    set_mode(&path, 0o600);
    let config = base_sources()
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            format!("file:{}", path.display()),
        )
        .load()
        .expect("load");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("empty target");
    assert_eq!(error.code(), ConfigErrorCode::SecretRefRefused);
    drop(dir);

    let (dir, path) = secret_fixture(&vec![b'x'; 64 * 1024 + 1]);
    set_mode(&path, 0o600);
    let config = base_sources()
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            format!("file:{}", path.display()),
        )
        .load()
        .expect("load");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("oversized target");
    assert_eq!(error.code(), ConfigErrorCode::SecretRefRefused);
    drop(dir);
}

#[test]
fn resolving_a_non_secret_key_is_a_usage_error() {
    let config = base_sources().load().expect("load");
    let error = config
        .resolve_secret("ingest.endpoint_url")
        .expect_err("not a secret key");
    assert_eq!(error.code(), ConfigErrorCode::Usage);
    assert_eq!(error.field(), Some("ingest.endpoint_url"));
}

// --- diagnostics never carry values, paths, or references -----------------

#[test]
fn diagnostics_never_carry_values() {
    let error = base_sources()
        .env(
            "ARCHIVIST_INGEST_ENDPOINT_URL",
            "https://secret-value.example.invalid",
        )
        .env("ARCHIVIST_STORAGE_ENCRYPTION", "rot13")
        .load()
        .expect_err("failing value");
    assert!(!format!("{error}").contains("secret-value"), "{error}");
    assert!(!format!("{error:?}").contains("rot13"), "{error:?}");
    let body = String::from_utf8(error.error_body_bytes()).expect("utf-8 body");
    assert!(
        !body.contains("secret-value") && !body.contains("rot13"),
        "{body}"
    );
}

#[cfg(unix)]
#[test]
fn diagnostics_never_carry_paths_or_references() {
    // A failing secret target: neither the reference string nor the
    // target path appears anywhere.
    let (dir, path) = secret_fixture(b"fixture\n");
    set_mode(&path, 0o644);
    let config = base_sources()
        .env(
            "ARCHIVIST_STORAGE_RAW_WRITE_CREDENTIALS_REF",
            format!("file:{}", path.display()),
        )
        .load()
        .expect("load");
    let error = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect_err("unsafe mode");
    let target = path.to_string_lossy();
    for rendered in [
        format!("{error}"),
        format!("{error:?}"),
        error.field().unwrap_or_default().to_owned(),
    ] {
        // The field is the key name; the target path and the reference
        // spelling must not appear.
        assert!(!rendered.contains(target.as_ref()), "{rendered}");
        assert!(!rendered.contains("file:"), "{rendered}");
    }
    let body = String::from_utf8(error.error_body_bytes()).expect("utf-8 body");
    assert!(
        !body.contains("file:") && !body.contains(target.as_ref()),
        "{body}"
    );
    drop(dir);
}

#[test]
fn secret_types_render_without_their_targets_or_values() {
    let file_ref = SecretRef::parse("file:/etc/archivist/storage/raw-write-credentials")
        .expect("well-formed file reference");
    assert!(!format!("{file_ref:?}").contains("/etc"), "{file_ref:?}");
    assert!(!format!("{file_ref}").contains("/etc"), "{file_ref}");
    let env_ref = SecretRef::parse("env:TEST_RAW_CREDENTIAL").expect("well-formed env reference");
    // An env target name is the one nameable kind.
    assert!(format!("{env_ref:?}").contains("TEST_RAW_CREDENTIAL"));

    let config = base_sources().load().expect("load");
    let value = config
        .resolve_secret("storage.raw_write_credentials_ref")
        .expect("env target resolves");
    let debug = format!("{value:?}");
    assert!(
        debug.contains("bytes") && !debug.contains("fixture"),
        "{debug}"
    );
}

// --- reference grammar ----------------------------------------------------

#[test]
fn reference_grammar_accepts_and_refuses() {
    for text in [
        "file:/etc/archivist/identity.json",
        "file:/srv/a.b_c-d+e",
        "env:TEST_CREDENTIAL",
    ] {
        SecretRef::parse(text).unwrap_or_else(|error| panic!("{text} must parse: {error}"));
    }
    for text in [
        "",
        "file",
        "file:",
        "file:relative/path",
        "file:/has/tilde~",
        "file:/dot/../segment",
        "file:/trailing/slash/",
        "file:/space segment",
        "env:",
        "env:lowercase",
        "env:1STARTS_WITH_DIGIT",
        "env:ARCHIVIST_CONFIG",
        "vault:/secret",
    ] {
        let error = SecretRef::parse(text).expect_err("outside the grammar");
        assert_eq!(error.code(), ConfigErrorCode::Usage);
    }
}
