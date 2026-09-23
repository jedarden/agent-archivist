// SPDX-License-Identifier: Apache-2.0

//! Composition and stream routing for parsed CLI invocations.

use std::ffi::OsString;
use std::io::{self, IsTerminal, Write};

use archivist_protocol::json;

use super::error::CliError;
use super::output::{OutputEnvelope, write_human};
use super::parse::{self, Invocation, Parsed};
use super::registry::{Command, Registry};

/// A library-owned command implementation attached by a later phase.
pub type CommandHandler = fn(&Invocation) -> Result<json::Value, CliError>;

/// The single command router used by the `archivist` binary.
pub struct Router {
    registry: &'static Registry,
    handlers: Vec<(Box<str>, CommandHandler)>,
}

impl Router {
    /// Create a router over the pinned registry with no unshipped handlers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: Registry::pinned(),
            handlers: Vec::new(),
        }
    }

    /// Attach a handler for a command whose registry entry has a result
    /// schema. This is the composition point for implementing phases.
    ///
    /// # Errors
    /// Returns [`CliError::usage`] when the path is not registered, or the
    /// command neither emits a pinned result document nor the none-stdout
    /// kind a long-running command ships as behavior instead.
    pub fn register_handler(
        &mut self,
        path: &str,
        handler: CommandHandler,
    ) -> Result<(), CliError> {
        let segments = path.split(' ').map(str::to_owned).collect::<Vec<_>>();
        let Some(command) = self.registry.command(&segments) else {
            return Err(CliError::usage());
        };
        // A document command pins its result to a wire schema (CLI-015); a
        // none-stdout command (CLI-016) emits nothing to attach one to, and
        // its handler *is* the registered surface. Anything else has no
        // defined output and is refused.
        if command.stdout_kind() != "none" && command.result_schema().is_none() {
            return Err(CliError::usage());
        }
        if self
            .handlers
            .iter()
            .any(|(registered, _)| registered.as_ref() == path)
        {
            return Err(CliError::usage());
        }
        self.handlers
            .push((path.to_owned().into_boxed_str(), handler));
        Ok(())
    }

    /// Run one invocation and return its registered process exit code.
    #[must_use]
    pub fn run(&self, args: &[OsString]) -> i32 {
        match parse::parse(args, self.registry) {
            Ok(Parsed::Version) => {
                println!("archivist {}", env!("CARGO_PKG_VERSION"));
                0
            }
            Ok(Parsed::Help(path)) => {
                let command = path.as_deref().and_then(|path| self.registry.command(path));
                print!("{}", self.registry.help(command));
                0
            }
            Ok(Parsed::Command(invocation)) => self.run_command(&invocation),
            Err(error) => {
                let diagnostic = CliError::usage();
                let _ = diagnostic.write_to(&mut io::stderr().lock(), error.json());
                diagnostic.exit_code()
            }
        }
    }

    fn run_command(&self, invocation: &Invocation) -> i32 {
        let command = self
            .registry
            .command(invocation.command_path())
            .expect("the parser returns only a registered command");
        let Some((_, handler)) = self
            .handlers
            .iter()
            .find(|(path, _)| path.as_ref() == command.path_text())
        else {
            let diagnostic = CliError::usage();
            let _ = diagnostic.write_to(&mut io::stderr().lock(), invocation.modes().json());
            return diagnostic.exit_code();
        };
        let result = match handler(invocation) {
            Ok(result) => result,
            Err(diagnostic) => {
                let _ = diagnostic.write_to(&mut io::stderr().lock(), invocation.modes().json());
                return diagnostic.exit_code();
            }
        };
        if command.stdout_kind() == "none" {
            return 0;
        }
        if !matches!(&result, json::Value::Object(_)) {
            let diagnostic = CliError::internal();
            let _ = diagnostic.write_to(&mut io::stderr().lock(), invocation.modes().json());
            return diagnostic.exit_code();
        }
        let write_result = if invocation.modes().json() {
            let Ok(output) = OutputEnvelope::new(&command.joined(), result) else {
                let diagnostic = CliError::internal();
                let _ = diagnostic.write_to(&mut io::stderr().lock(), invocation.modes().json());
                return diagnostic.exit_code();
            };
            output.write_to(&mut io::stdout().lock())
        } else if io::stdout().is_terminal() {
            write_human(&result, &mut io::stdout().lock())
        } else {
            let mut stdout = io::stdout().lock();
            stdout
                .write_all(&result.canonical_bytes())
                .and_then(|()| stdout.write_all(b"\n"))
        };
        if write_result.is_ok() {
            0
        } else {
            let diagnostic = CliError::internal();
            let _ = diagnostic.write_to(&mut io::stderr().lock(), invocation.modes().json());
            diagnostic.exit_code()
        }
    }

    /// The registry entry for one command path, useful to composition code.
    #[must_use]
    pub fn command(&self, path: &[String]) -> Option<&Command> {
        self.registry.command(path)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}
