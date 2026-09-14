// SPDX-License-Identifier: Apache-2.0

//! Protected references: the only channel private key material may enter
//! through.
//!
//! A protected reference is the configuration grammar's secret reference
//! (CFG-028/CFG-029): the conjunction of a `file:` or `env:` kind, a
//! validated target, and the promise that the target holds a secret value.
//! The value itself never appears in the reference, in an argument, or in
//! any diagnostic — a caller holds the *pointer*, and this module resolves
//! it while enforcing the safety properties (CFG-030): a `file:` target
//! must be a regular file readable by the running user only, and an `env:`
//! name can never collide with the `ARCHIVIST_` configuration tier.

use std::fmt;
use std::fs::File;
use std::io::Read;

use crate::error::IdentityError;

/// The environment-variable prefix reserved for the configuration tier
/// itself (CFG-006). A secret channel named with it could be confused with
/// a configuration key, so the grammar refuses it.
const RESERVED_ENV_PREFIX: &str = "ARCHIVIST_";

/// A parsed, validated secret reference: `file:` with an absolute path or
/// `env:` with an environment-variable name (CFG-029).
///
/// The type holds only the *reference* — the pointer — never the value it
/// names. Its [`Debug`](std::fmt::Debug) and [`Display`](std::fmt::Display)
/// implementations show the kind and, for `env:`, the variable name; a
/// `file:` target path is operator-supplied configuration that appears in
/// no output (CFG-027, CFG-030), so the display is redacted to the kind.
#[derive(Clone, PartialEq, Eq, Hash)]
pub enum ProtectedReference {
    /// `file:` — the target is a mode-restricted regular file on this host.
    File {
        /// The absolute target path. Never rendered by this type.
        path: Box<std::path::Path>,
    },
    /// `env:` — the target is an environment variable on this host, whose
    /// name is not itself secret and is safe to name in diagnostics.
    Env {
        /// The variable name, matching the pinned grammar.
        name: Box<str>,
    },
}

impl ProtectedReference {
    /// Parse a reference string, failing closed on anything outside the
    /// pinned grammar (CFG-029):
    ///
    /// - `file:` plus an absolute path whose segments use only
    ///   `[A-Za-z0-9._+-]`, with no `.` or `..` segment and no tilde;
    /// - `env:` plus a name matching `[A-Z][A-Z0-9_]{0,63}` that does not
    ///   start with the reserved `ARCHIVIST_` prefix.
    ///
    /// # Errors
    /// [`IdentityError::ReferenceGrammar`] for anything else. The malformed
    /// input is not echoed.
    pub fn parse(text: &str) -> Result<Self, IdentityError> {
        if let Some(path_text) = text.strip_prefix("file:") {
            return Self::parse_file(path_text);
        }
        if let Some(name) = text.strip_prefix("env:") {
            return Self::parse_env(name);
        }
        Err(IdentityError::ReferenceGrammar)
    }

    /// Validate and adopt a `file:` target.
    fn parse_file(path_text: &str) -> Result<Self, IdentityError> {
        // Absolute, no tilde, every segment in the pinned class, no dot
        // segments. A relative path cannot be validated against host state
        // the way CFG-030's mode check requires, so it is refused outright.
        if path_text.is_empty()
            || !path_text.starts_with('/')
            || path_text.contains('~')
            || !path_text
                .split('/')
                .skip(1)
                .all(|segment| is_path_segment(segment) && segment != "." && segment != "..")
        {
            return Err(IdentityError::ReferenceGrammar);
        }
        Ok(Self::File {
            path: std::path::PathBuf::from(path_text).into_boxed_path(),
        })
    }

    /// Validate and adopt an `env:` target.
    fn parse_env(name: &str) -> Result<Self, IdentityError> {
        let well_formed = (1..=64).contains(&name.len())
            && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            && name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && !name.starts_with(RESERVED_ENV_PREFIX);
        if !well_formed {
            return Err(IdentityError::ReferenceGrammar);
        }
        Ok(Self::Env { name: name.into() })
    }

    /// Resolve the reference to the secret value it names, enforcing the
    /// safety properties on the way (CFG-030).
    ///
    /// For `file:`, the mode check runs against the opened file itself (not
    /// a path probed beforehand), so the bytes read are the bytes checked;
    /// at most one trailing newline is trimmed, per the configuration
    /// convention. For `env:`, the variable is read at call time.
    ///
    /// # Errors
    /// [`IdentityError::ReferenceGrammar`] cannot escape here (parse
    /// already ran); [`IdentityError::ReferenceMissing`],
    /// [`IdentityError::ReferenceUnsafe`],
    /// [`IdentityError::ReferenceUnreadable`], and, on platforms without
    /// POSIX permissions, [`IdentityError::ReferenceUnsupportedPlatform`].
    /// No error carries the target path or the value.
    pub fn resolve(&self) -> Result<Vec<u8>, IdentityError> {
        match self {
            Self::File { path } => resolve_file(path),
            Self::Env { name } => std::env::var(name.as_ref())
                .map(String::into_bytes)
                .map_err(|error| match error {
                    std::env::VarError::NotPresent => IdentityError::ReferenceMissing,
                    // A non-UTF-8 value is an unreadable target, not a
                    // grammar failure — and its bytes are never echoed.
                    std::env::VarError::NotUnicode(_) => IdentityError::ReferenceUnreadable,
                }),
        }
    }
}

/// One path segment: `[A-Za-z0-9._+-]+`.
fn is_path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
}

/// Read a `file:` target with the mode check against the opened file.
fn resolve_file(path: &std::path::Path) -> Result<Vec<u8>, IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut file = File::open(path).map_err(|error| missing_or_unreadable(&error))?;
        let metadata = file
            .metadata()
            .map_err(|_io_error| IdentityError::ReferenceUnreadable)?;
        if !metadata.is_file() {
            return Err(IdentityError::ReferenceUnsafe);
        }
        // 0600 or stricter: any group or other permission bit is a refusal,
        // reported by property (CFG-030), never by path.
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::ReferenceUnsafe);
        }
        let mut value = Vec::new();
        file.read_to_end(&mut value)
            .map_err(|_io_error| IdentityError::ReferenceUnreadable)?;
        trim_one_trailing_newline(&mut value);
        Ok(value)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(IdentityError::ReferenceUnsupportedPlatform)
    }
}

/// Trim at most one trailing newline (CFG-030's value normalization).
fn trim_one_trailing_newline(value: &mut Vec<u8>) {
    if value.last() == Some(&b'\n') {
        value.pop();
    }
}

/// Collapse the two open failure modes into their two classes: a missing
/// target is `ReferenceMissing`, everything else is `ReferenceUnreadable`.
/// The OS message itself is dropped — it embeds the path.
fn missing_or_unreadable(error: &std::io::Error) -> IdentityError {
    if error.kind() == std::io::ErrorKind::NotFound {
        IdentityError::ReferenceMissing
    } else {
        IdentityError::ReferenceUnreadable
    }
}

impl fmt::Debug for ProtectedReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // The path is configuration; naming it in output is forbidden
            // (CFG-027), and Debug output is output.
            Self::File { .. } => f.write_str("ProtectedReference::file:<redacted>"),
            // An environment variable name is not secret and is the one
            // target a diagnostic may name.
            Self::Env { name } => write!(f, "ProtectedReference::env:{name}"),
        }
    }
}

impl fmt::Display for ProtectedReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { .. } => f.write_str("file:<redacted>"),
            Self::Env { name } => write!(f, "env:{name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The accepted grammar, one row per kind.
    #[test]
    fn accepts_well_formed_references() {
        assert!(matches!(
            ProtectedReference::parse("file:/etc/archivist/identity.json"),
            Ok(ProtectedReference::File { .. })
        ));
        assert!(matches!(
            ProtectedReference::parse("file:/srv/arc/state/a.b_c-d+e"),
            Ok(ProtectedReference::File { .. })
        ));
        // Segment character class is CFG-029's `[A-Za-z0-9._+-]`: uppercase
        // is in the grammar, shared with the config tier's own reference
        // parser.
        assert!(matches!(
            ProtectedReference::parse("file:/upper/Case"),
            Ok(ProtectedReference::File { .. })
        ));
        assert!(matches!(
            ProtectedReference::parse("env:ARCHIVE_IDENTITY_REF_WRL"),
            Ok(ProtectedReference::Env { .. })
        ));
    }

    /// Everything outside the grammar is refused with the same failure.
    #[test]
    fn refuses_malformed_references() {
        let malformed = [
            "",
            "file",
            "file:",
            "file:relative/path",
            "file:/has/tilde~",
            "file:/dot/segment/../..",
            "file:/dot/./segment",
            "file:/trailing/slash/",
            "file:/space seg/ment",
            "env:",
            "env:lowercase",
            "env:1STARTS_WITH_DIGIT",
            "env:HAS SPACE",
            "env:ARCHIVIST_LOG",
            "env:TOOLONGNAME_0123456789_0123456789_0123456789_0123456789_0123456789_0123456789",
            "secret:/etc/passwd",
        ];
        for text in malformed {
            assert_eq!(
                ProtectedReference::parse(text),
                Err(IdentityError::ReferenceGrammar),
                "expected refusal: {text}"
            );
        }
    }

    /// `env:` names resolve at call time; `PATH` exists on every host this
    /// suite runs on, so the success path is exercised without ever
    /// asserting on (or printing) the value.
    #[test]
    fn resolves_an_environment_reference() {
        let reference = ProtectedReference::parse("env:PATH").expect("PATH matches the grammar");
        let value = reference.resolve().expect("PATH is set");
        assert!(!value.is_empty());
    }

    /// A well-formed name naming an unset variable is a missing target.
    #[test]
    fn missing_environment_variable_fails_closed() {
        let reference = ProtectedReference::parse("env:ARCHIVE_DEFINITELY_UNSET_VAR_7F3A")
            .expect("name matches the grammar");
        assert_eq!(reference.resolve(), Err(IdentityError::ReferenceMissing));
    }

    /// A `file:` target with mode `0600` resolves, with one trailing
    /// newline trimmed; the same target at `0644` is refused by property.
    #[test]
    fn file_mode_is_enforced() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let dir =
                std::env::temp_dir().join(format!("archivist-ref-test-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir creation");
            let path = dir.join("identity.json");

            std::fs::write(&path, b"value\n").expect("write target");
            for (mode, expected) in [
                (0o600, Ok(b"value".to_vec())),
                (0o644, Err(IdentityError::ReferenceUnsafe)),
                (0o400, Ok(b"value".to_vec())),
            ] {
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
                    .expect("set mode");
                let reference = ProtectedReference::parse(&format!("file:{}", path.display()))
                    .expect("generated path matches the grammar");
                // Compare by outcome, never by echoing the resolved value.
                assert_eq!(reference.resolve().map(|_| b"value".to_vec()), expected);
            }
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&dir);
        }
    }

    /// A directory target exists but is not a regular file: refused.
    #[test]
    fn non_regular_file_target_is_refused() {
        #[cfg(unix)]
        {
            let reference =
                ProtectedReference::parse("file:/tmp").expect("generated path matches grammar");
            assert_eq!(reference.resolve(), Err(IdentityError::ReferenceUnsafe));
        }
    }

    /// A missing file target is `ReferenceMissing`, and neither parse
    /// failures nor resolution failures ever render the target path.
    #[test]
    fn diagnostics_never_name_the_file_target() {
        let reference = ProtectedReference::parse("file:/etc/archivist/identity.json")
            .expect("well-formed reference");
        let debug = format!("{reference:?}");
        let display = format!("{reference}");
        assert!(!debug.contains("/etc/archivist"), "{debug}");
        assert!(!display.contains("/etc/archivist"), "{display}");
        assert!(debug.starts_with("ProtectedReference::file:"));
    }

    /// Every rendered error is context-free (CFG-027, SEC-004): driven
    /// through real host-state refusals — a missing target, a directory
    /// target, a loose-mode target, an unknown scheme, a malformed
    /// reference — the error's Display and Debug output carries neither the
    /// target path nor any bytes of the target's content. The `env:` mapping
    /// drops the value by the same rule (`NotUnicode` binds `_`); its static
    /// messages are pinned by the integration suite's exhaustive variant
    /// scan. The markers are distinctive so a leak cannot pass by
    /// coincidence.
    #[test]
    fn error_strings_never_carry_the_target_or_the_value() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            const MARKER_SEGMENT: &str = "no-echo-target-3f91c4a7";
            const MARKER_VALUE: &str = "resolved-value-bytes-8b2e55d0";

            let dir =
                std::env::temp_dir().join(format!("archivist-ref-noecho-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("temp dir creation");
            let target = dir.join(MARKER_SEGMENT);
            let reference = ProtectedReference::parse(&format!("file:{}", target.display()))
                .expect("generated path matches the grammar");

            // A missing target whose path is distinctive: the refusal must
            // not name it.
            let error = reference.resolve().expect_err("target is absent");
            assert_eq!(error, IdentityError::ReferenceMissing);
            for rendered in [format!("{error}"), format!("{error:?}")] {
                assert!(!rendered.contains(MARKER_SEGMENT), "{rendered}");
                assert!(
                    !rendered.contains(dir.to_str().expect("utf-8 temp dir")),
                    "{rendered}"
                );
            }

            // A directory target whose path is distinctive: refused as
            // unsafe, never named.
            std::fs::create_dir(&target).expect("plant directory target");
            let error = reference.resolve().expect_err("target is a directory");
            assert_eq!(error, IdentityError::ReferenceUnsafe);
            for rendered in [format!("{error}"), format!("{error:?}")] {
                assert!(!rendered.contains(MARKER_SEGMENT), "{rendered}");
            }

            // A loose-mode regular file whose content is distinctive: the
            // mode check refuses before a byte is read, and neither the
            // path nor the unread value may appear.
            std::fs::remove_dir(&target).expect("replace with a file");
            std::fs::write(&target, MARKER_VALUE).expect("plant loose target");
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
                .expect("loosen mode");
            let error = reference.resolve().expect_err("mode is 0644");
            assert_eq!(error, IdentityError::ReferenceUnsafe);
            for rendered in [format!("{error}"), format!("{error:?}")] {
                assert!(!rendered.contains(MARKER_SEGMENT), "{rendered}");
                assert!(!rendered.contains(MARKER_VALUE), "{rendered}");
            }

            // A reference outside the grammar: the refusal echoes nothing of
            // the rejected input, whatever it carried.
            for malformed in [
                format!("secret:{MARKER_VALUE}"),
                format!("file:relative/{MARKER_SEGMENT}"),
            ] {
                let error = ProtectedReference::parse(&malformed).expect_err("outside the grammar");
                assert_eq!(error, IdentityError::ReferenceGrammar);
                for rendered in [format!("{error}"), format!("{error:?}")] {
                    assert!(!rendered.contains(MARKER_SEGMENT), "{rendered}");
                    assert!(!rendered.contains(MARKER_VALUE), "{rendered}");
                }
            }

            let _ = std::fs::remove_file(&target);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
