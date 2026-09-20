// SPDX-License-Identifier: Apache-2.0

//! The registry-driven command surface for the `archivist` binary.
//!
//! This module owns argument grammar, stream framing, and routing mechanics.
//! It intentionally does not own command behavior: a later phase registers a
//! library-owned handler for a command whose registry entry has a result
//! schema. Until then, that command is refused as not shipped (CLI-015).

pub mod error;
pub mod output;
pub mod parse;
pub mod registry;
pub mod router;

pub use error::CliError;
pub use output::OutputEnvelope;
pub use parse::{Invocation, ModeFlags, ParseError};
pub use router::{CommandHandler, Router};

#[cfg(test)]
mod tests;
