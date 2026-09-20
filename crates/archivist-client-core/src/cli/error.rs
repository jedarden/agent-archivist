// SPDX-License-Identifier: Apache-2.0

//! CLI diagnostics and registered error-class exit mapping.

use std::io::{self, Write};

use archivist_protocol::json;

use crate::config::{self, registry};

const USAGE_CODE: &str = "cli.usage_error";
const INTERNAL_CODE: &str = "client.internal_error";

/// A content-free diagnostic whose code and exit behavior come from the
/// committed error registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CliError {
    code: &'static str,
}

impl CliError {
    /// Construct the registered usage error used by strict parsing and by an
    /// unshipped command.
    #[must_use]
    pub const fn usage() -> Self {
        Self { code: USAGE_CODE }
    }

    /// Construct the registered internal error used when a delegated handler
    /// violates the output boundary.
    #[must_use]
    pub const fn internal() -> Self {
        Self {
            code: INTERNAL_CODE,
        }
    }

    /// Construct a diagnostic for another statically registered code.
    ///
    /// Handlers use this when their library-owned condition is already in
    /// `tools/error-codes.toml`.
    #[must_use]
    pub const fn registered(code: &'static str) -> Self {
        Self { code }
    }

    /// The registered error-code token.
    #[must_use]
    pub const fn code(self) -> &'static str {
        self.code
    }

    /// The exit code allocated by the error class.
    #[must_use]
    pub fn exit_code(self) -> i32 {
        registry::error_registry()
            .code(self.code)
            .and_then(|definition| registry::error_registry().class(definition.class()))
            .map_or(70, registry::ErrorClass::exit_code)
    }

    /// The canonical `archivist.error/v1` body.
    #[must_use]
    pub fn body_bytes(self) -> Vec<u8> {
        let errors = registry::error_registry();
        let definition = errors.code(self.code);
        let retryable = definition
            .and_then(|definition| errors.class(definition.class()))
            .is_some_and(registry::ErrorClass::retryable);
        let message = definition.map_or_else(
            || "The command failed; consult the registered error condition.".to_owned(),
            |definition| config::render_message(definition.message(), None),
        );
        let mut object = json::Object::new();
        object.set("schema", json::Value::Text("archivist.error/v1".to_owned()));
        object.set("code", json::Value::Text(self.code.to_owned()));
        object.set("retryable", json::Value::Bool(retryable));
        object.set("message", json::Value::Text(message));
        object.set("request_id", json::Value::Null);
        object.set(
            "correlation_id",
            json::Value::Text(config::mint_correlation_id().as_str().to_owned()),
        );
        json::Value::Object(object).canonical_bytes()
    }

    /// Write one diagnostic to stderr in the requested stream format.
    ///
    /// # Errors
    /// Returns the underlying writer error.
    pub fn write_to<W: Write>(self, writer: &mut W, json_mode: bool) -> io::Result<()> {
        if json_mode {
            writer.write_all(&self.body_bytes())?;
            writer.write_all(b"\n")
        } else {
            let errors = registry::error_registry();
            let message = errors.code(self.code).map_or_else(
                || "The command failed; consult the registered error condition.".to_owned(),
                |definition| config::render_message(definition.message(), None),
            );
            writeln!(writer, "archivist {}: {message}", self.code)
        }
    }
}
