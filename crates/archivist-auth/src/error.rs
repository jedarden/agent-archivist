// SPDX-License-Identifier: Apache-2.0

//! Failure taxonomy for identity generation, protected-reference discovery,
//! and link-request construction.
//!
//! Every variant is a unit: diagnostics name the failure class and never
//! carry a path, a reference string, a key value, or any other dynamic
//! material (SEC-004, CFG-027). A `file:` reference's target path is
//! operator-supplied configuration and appears in no message, and private
//! halves never enter this type at all. The set is closed: callers match
//! exhaustively (the tests do), so a new failure class has to be added here
//! first and reviewed against the no-echo rules before any caller can
//! produce it.

use std::fmt;

/// An identity or trust operation failed.
///
/// The [`Display`](std::fmt::Display) text names the failure class only; the
/// concrete remediation is always "check the deployment configuration", never
/// echoed input. Nothing in this type can carry private key or authorization
/// material by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentityError {
    /// The OS entropy source could not be read. Generation fails closed
    /// rather than falling back to a weaker source.
    Entropy,
    /// A protected reference does not follow the pinned `file:`/`env:` grammar
    /// (CFG-029). No part of the malformed input is echoed.
    ReferenceGrammar,
    /// The reference's target does not exist: a missing file or an unset
    /// environment variable. Missing and unreadable are the same failure
    /// class to a caller that must not learn which paths exist.
    ReferenceMissing,
    /// The reference's target exists but is not secret-safe: a `file:` target
    /// that is not a regular file, or whose mode grants group or other access
    /// (CFG-030 refuses anything looser than `0600`).
    ReferenceUnsafe,
    /// The reference target was readable but the read failed (permissions
    /// changed mid-read, I/O error). The OS error detail is dropped on
    /// purpose: it can embed a path.
    ReferenceUnreadable,
    /// The platform cannot express the guarantee the reference kind requires
    /// (POSIX file modes). Fails closed rather than reading without the mode
    /// check.
    ReferenceUnsupportedPlatform,
    /// Discovered identity material is malformed: not valid JSON, a member
    /// outside the closed shape, a value failing its grammar, a public key
    /// not matching its recorded key ID, or a seed not deriving the recorded
    /// public key. Every one of these is the same "corrupt identity" class,
    /// and none echoes the offending value.
    IdentityCorrupt,
    /// The identity store already exists; generation refuses to overwrite an
    /// installation identity in place (a re-generation would silently
    /// orphan the linked record on the control plane).
    IdentityExists,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Entropy => {
                "entropy source unavailable; refusing to generate weaker identity material"
            }
            Self::ReferenceGrammar => {
                "protected reference is not a well-formed file: or env: reference"
            }
            Self::ReferenceMissing => "protected reference target not found",
            Self::ReferenceUnsafe => {
                "protected reference target is not a regular file readable only by the running user"
            }
            Self::ReferenceUnreadable => "protected reference target could not be read",
            Self::ReferenceUnsupportedPlatform => {
                "file: references require POSIX file permissions; refusing to read without the mode check"
            }
            Self::IdentityCorrupt => "identity material is corrupt or internally inconsistent",
            Self::IdentityExists => "identity already exists; refusing to overwrite",
        };
        f.write_str(text)
    }
}

impl std::error::Error for IdentityError {}
