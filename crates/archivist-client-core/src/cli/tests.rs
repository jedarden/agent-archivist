// SPDX-License-Identifier: Apache-2.0

//! CLI parser and output-surface tests.

use std::ffi::OsString;

use archivist_protocol::json;

use super::error::CliError;
use super::output::OutputEnvelope;
use super::parse::{self, ParseErrorKind, Parsed};
use super::registry::Registry;
use super::router::Router;

fn args(items: &[&str]) -> Vec<OsString> {
    items.iter().map(OsString::from).collect()
}

#[test]
fn registry_contains_the_pinned_paths_and_help_cites_it() {
    let registry = Registry::pinned();
    assert!(
        registry
            .command(&["catalog".into(), "rebuild".into()])
            .is_some()
    );
    let help = registry.help(None);
    assert!(help.contains("tools/cli-commands.toml"));
    assert!(help.contains("catalog rebuild"));
}

#[test]
fn strict_parser_rejects_unknown_repeated_and_extra_operands() {
    let registry = Registry::pinned();
    for (argv, kind) in [
        (&["status", "--unknown"][..], ParseErrorKind::UnknownFlag),
        (
            &["status", "--json", "--json"][..],
            ParseErrorKind::RepeatedFlag,
        ),
        (&["status", "one"][..], ParseErrorKind::OperandViolation),
        (
            &["admin", "approve", "one", "two"][..],
            ParseErrorKind::OperandViolation,
        ),
    ] {
        let error = parse::parse(&args(argv), registry).expect_err("must reject");
        assert_eq!(error.kind(), kind);
    }
}

#[test]
fn double_dash_stops_flag_parsing() {
    let registry = Registry::pinned();
    let error = parse::parse(&args(&["status", "--", "--json"]), registry)
        .expect_err("status has no operand");
    assert_eq!(error.kind(), ParseErrorKind::OperandViolation);
    let invocation = parse::parse(&args(&["admin", "approve", "--", "draft.json"]), registry)
        .expect("path operand is accepted after the terminator");
    assert!(matches!(invocation, Parsed::Command(_)));
}

#[test]
fn output_envelope_is_closed_and_contains_no_float_domain() {
    let mut result = json::Object::new();
    result.set("count", json::Value::Int(2));
    let envelope = OutputEnvelope::with_timestamp(
        "catalog-rebuild",
        "2026-09-20T22:00:00Z",
        json::Value::Object(result),
    )
    .expect("valid envelope");
    let bytes = envelope.canonical_bytes();
    assert_eq!(
        bytes,
        br#"{"command":"catalog-rebuild","generated_at":"2026-09-20T22:00:00Z","result":{"count":2},"schema":"archivist.cli-output/v1"}"#
    );
    let parsed = archivist_protocol::json::parse(&bytes).expect("JSON parses");
    let json::Value::Object(object) = parsed else {
        panic!("envelope is not an object")
    };
    assert_eq!(object.len(), 4);
    assert!(object.get("schema").is_some());
    assert!(object.get("command").is_some());
    assert!(object.get("generated_at").is_some());
    assert!(object.get("result").is_some());
}

#[test]
fn router_refuses_registered_commands_without_result_schemas() {
    let mut router = Router::new();
    assert!(
        router
            .register_handler("status", |_invocation| {
                Ok(json::Value::Object(json::Object::new()))
            })
            .is_err()
    );
    let _ = CliError::usage();
}
