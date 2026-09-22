// SPDX-License-Identifier: Apache-2.0

//! The file-source capture core's session-identity resolution (plan
//! Phase 6A, plan Section 7.4): turn what the harness expressed — its own
//! name, and whatever session identifier it put on the session — into
//! the one identity capture derives from, preserving opaque bytes exactly
//! and never inventing identity the harness did not state.
//!
//! Three rules do all the work:
//!
//! - **Opaque is opaque.** An upstream session ID is preserved
//!   byte-for-byte: never case-folded, never Unicode-normalized, never
//!   trimmed, never merged with a lookalike. `Session-ABC` and
//!   `session-abc` are distinct identities, and so are the NFC and NFD
//!   spellings of the same characters (plan Section 7.4). The identity
//!   derivations hash the exact bytes
//!   ([`SessionIdentity::session_hash`]), so what the harness wrote is
//!   what the archive namespaces by.
//! - **Absent is synthetic.** A harness that expresses no session ID —
//!   the identifier is missing, or it is the empty string, which
//!   expresses no bytes to preserve — gets an adapter-minted `UUIDv4`
//!   stand-in with [`IdSource::Synthetic`] recorded in the manifest
//!   (plan Section 7.4). The empty-versus-absent ambiguity is decided
//!   here, once: the empty string *is* absence, because a zero-byte
//!   identifier has nothing to preserve and preserving it would merge
//!   every empty-ID session into one shared identity input. The stand-in
//!   is minted from entropy and never inferred from a path name — a path
//!   is not an input to this module at all, so no naming convention can
//!   become identity.
//! - **Invalid fails closed, content-free.** A harness name outside the
//!   plan 7.4 grammar, or a stated session ID outside the 1–1,024-byte
//!   opaque bound, is rejected with an error that names the failure and
//!   carries nothing else ([`SessionIdentityError`] has no payload):
//!   identifiers are untrusted content, and echoing one would leak
//!   whatever the harness put there.

use archivist_protocol::correlation::mint_synthetic_session_id;
use archivist_protocol::derivation::session_hash as derive_session_hash;
use archivist_protocol::vocabulary::{
    ClientId, HarnessId, IdSource, OpaqueId, SessionHash, TenantId,
};

/// Why a session's identity could not be resolved. The variants carry no
/// payload on purpose: the rejected text is harness-controlled content,
/// and a content-free error cannot leak it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionIdentityError {
    /// The harness name is outside the plan 7.4 grammar
    /// (`[a-z0-9][a-z0-9._-]{0,63}`).
    HarnessIdInvalid,
    /// The stated session ID is not a valid opaque identity (1–1,024
    /// bytes of UTF-8). Never emitted for an empty string, which is
    /// absence, not a malformed identity.
    UpstreamSessionInvalid,
}

impl std::fmt::Display for SessionIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::HarnessIdInvalid => "session_identity_harness_id_invalid",
            Self::UpstreamSessionInvalid => "session_identity_upstream_session_invalid",
        };
        f.write_str(token)
    }
}

impl std::error::Error for SessionIdentityError {}

/// The resolved identity of one logical session (plan Section 7.4): the
/// harness it came from, the upstream session ID capture namespaces by,
/// and where that ID came from. Resolved once per session by
/// [`SessionIdentity::resolve`] and never re-derived from content or
/// paths afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionIdentity {
    harness: HarnessId,
    upstream_session_id: OpaqueId,
    id_source: IdSource,
}

impl SessionIdentity {
    /// Resolve one session's identity from the harness's name and the
    /// session ID it stated, if any.
    ///
    /// A stated ID is preserved byte-for-byte under
    /// [`IdSource::Upstream`]. A missing ID — [`Option::None`] or the
    /// empty string, which is absence — is replaced by an adapter-minted
    /// `UUIDv4` under [`IdSource::Synthetic`], a fresh value per
    /// resolution so unidentified sessions never merge. Anything else
    /// that fails its grammar fails closed, content-free.
    ///
    /// # Errors
    /// [`SessionIdentityError::HarnessIdInvalid`] when `harness` is
    /// outside the plan 7.4 grammar, or
    /// [`SessionIdentityError::UpstreamSessionInvalid`] when the stated
    /// session ID is outside the opaque bound.
    pub fn resolve(
        harness: &str,
        upstream_session_id: Option<&str>,
    ) -> Result<Self, SessionIdentityError> {
        let harness =
            HarnessId::parse(harness).map_err(|_| SessionIdentityError::HarnessIdInvalid)?;
        match upstream_session_id {
            // The empty string is absence: no bytes were stated, so
            // there is nothing to preserve and nothing to reject.
            None | Some("") => Ok(Self {
                harness,
                upstream_session_id: mint_synthetic_session_id(),
                id_source: IdSource::Synthetic,
            }),
            Some(stated) => {
                let upstream_session_id = OpaqueId::parse(stated)
                    .map_err(|_| SessionIdentityError::UpstreamSessionInvalid)?;
                Ok(Self {
                    harness,
                    upstream_session_id,
                    id_source: IdSource::Upstream,
                })
            }
        }
    }

    /// The harness this session came from.
    #[must_use]
    pub fn harness(&self) -> &HarnessId {
        &self.harness
    }

    /// The upstream session ID capture namespaces by — the harness's
    /// exact bytes when stated, the minted `UUIDv4` when synthetic.
    #[must_use]
    pub fn upstream_session_id(&self) -> &OpaqueId {
        &self.upstream_session_id
    }

    /// Where the upstream session ID came from: read from the harness,
    /// or an adapter-minted stand-in.
    #[must_use]
    pub fn id_source(&self) -> IdSource {
        self.id_source
    }

    /// Whether the upstream session ID is an adapter-minted stand-in.
    #[must_use]
    pub fn is_synthetic(&self) -> bool {
        self.id_source == IdSource::Synthetic
    }

    /// The logical-session namespace hash this identity names (SID-001,
    /// plan Section 7.4): `session_hash` over this tenant, origin client,
    /// harness, and the upstream session ID's exact bytes. Synthetic and
    /// upstream identities enter the same derivation — the manifest's
    /// `id_source` is what records the difference, never the hash input.
    #[must_use]
    pub fn session_hash(&self, tenant_id: &TenantId, origin_client_id: &ClientId) -> SessionHash {
        derive_session_hash(
            tenant_id,
            origin_client_id,
            &self.harness,
            self.upstream_session_id.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> TenantId {
        TenantId::parse("0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b").expect("valid tenant id")
    }

    fn origin() -> ClientId {
        ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f").expect("valid client id")
    }

    /// A canonical `UUIDv4` text: 8-4-4-4-12 lowercase hex with the
    /// version nibble at index 14 and the RFC 9562 variant at 19.
    fn is_canonical_uuid_v4(text: &str) -> bool {
        let raw = text.as_bytes();
        raw.len() == 36
            && matches!(raw[14], b'4')
            && matches!(raw[19], b'8' | b'9' | b'a' | b'b')
            && text.bytes().enumerate().all(|(index, byte)| {
                matches!(index, 8 | 13 | 18 | 23) && byte == b'-'
                    || byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
            })
    }

    #[test]
    fn stated_ids_round_trip_byte_for_byte_as_upstream() {
        const CASE_DIFFERING: [&str; 4] = [
            "Session-ABC",
            "session-abc",
            "SESSION-ABC",
            "sEsSiOn AbC with spaces and /slashes/",
        ];
        for stated in CASE_DIFFERING {
            let identity =
                SessionIdentity::resolve("claude-code", Some(stated)).expect("a stated identity");
            assert_eq!(identity.upstream_session_id().as_str(), stated);
            assert_eq!(identity.id_source(), IdSource::Upstream);
            assert!(!identity.is_synthetic());
        }
    }

    #[test]
    fn non_ascii_and_normalization_lookalikes_round_trip_as_distinct_identities() {
        // NFC and NFD spellings of "é", plus an emoji and CJK text: the
        // bytes are preserved exactly, and no spelling is normalized away.
        const COMPOSED: &str = "caf\u{00e9}-session";
        const DECOMPOSED: &str = "cafe\u{0301}-session";
        assert_ne!(COMPOSED, DECOMPOSED, "the test inputs must really differ");

        let composed =
            SessionIdentity::resolve("claude-code", Some(COMPOSED)).expect("NFC identity");
        let decomposed =
            SessionIdentity::resolve("claude-code", Some(DECOMPOSED)).expect("NFD identity");
        assert_eq!(composed.upstream_session_id().as_str(), COMPOSED);
        assert_eq!(decomposed.upstream_session_id().as_str(), DECOMPOSED);
        assert_ne!(
            composed.upstream_session_id(),
            decomposed.upstream_session_id()
        );
        // No fold, no normalization, no merge — the namespace hashes
        // differ too.
        assert_ne!(
            composed.session_hash(&tenant(), &origin()),
            decomposed.session_hash(&tenant(), &origin())
        );

        let emoji = SessionIdentity::resolve("claude-code", Some("\u{1f9ca}")).expect("emoji id");
        assert_eq!(emoji.upstream_session_id().as_str(), "\u{1f9ca}");
    }

    #[test]
    fn case_differing_ids_name_distinct_session_namespaces() {
        let upper = SessionIdentity::resolve("claude-code", Some("Session-ABC")).expect("upper");
        let lower = SessionIdentity::resolve("claude-code", Some("session-abc")).expect("lower");
        assert_ne!(
            upper.upstream_session_id(),
            lower.upstream_session_id(),
            "no case folding"
        );
        assert_ne!(
            upper.session_hash(&tenant(), &origin()),
            lower.session_hash(&tenant(), &origin()),
            "no merge on textual similarity"
        );
    }

    #[test]
    fn an_absent_session_id_mints_a_fresh_synthetic_uuidv4_each_time() {
        let first = SessionIdentity::resolve("claude-code", None).expect("absent is resolvable");
        let second = SessionIdentity::resolve("claude-code", None).expect("absent is resolvable");
        for identity in [&first, &second] {
            assert_eq!(identity.id_source(), IdSource::Synthetic);
            assert!(identity.is_synthetic());
            assert!(
                is_canonical_uuid_v4(identity.upstream_session_id().as_str()),
                "the stand-in is a canonical UUIDv4, not derived text"
            );
        }
        // Two unidentified sessions stay distinct identities.
        assert_ne!(first.upstream_session_id(), second.upstream_session_id());
        assert_ne!(
            first.session_hash(&tenant(), &origin()),
            second.session_hash(&tenant(), &origin())
        );
    }

    #[test]
    fn an_empty_session_id_is_absence_and_mints_synthetic() {
        // The empty-versus-absent decision, pinned: the empty string
        // states no bytes to preserve, so it is absence and the
        // synthetic stand-in fires — it never becomes an upstream ID,
        // and it never fails closed.
        let empty = SessionIdentity::resolve("claude-code", Some("")).expect("empty is absence");
        assert_eq!(empty.id_source(), IdSource::Synthetic);
        assert!(empty.is_synthetic());
        assert_ne!(empty.upstream_session_id().as_str(), "");
        assert!(is_canonical_uuid_v4(empty.upstream_session_id().as_str()));
    }

    #[test]
    fn a_session_at_the_opaque_bound_round_trips_and_one_byte_more_fails_closed() {
        let at_bound = "s".repeat(1024);
        let identity =
            SessionIdentity::resolve("claude-code", Some(&at_bound)).expect("1,024 bytes fit");
        assert_eq!(identity.upstream_session_id().as_str(), at_bound);

        let past_bound = "s".repeat(1025);
        let error =
            SessionIdentity::resolve("claude-code", Some(&past_bound)).expect_err("over the bound");
        assert_eq!(error, SessionIdentityError::UpstreamSessionInvalid);
    }

    #[test]
    fn failures_are_content_free() {
        // The Display text names the failure and never echoes the input
        // that caused it.
        for harness in ["", "Claude-Code", "-leading", "with space", &"a".repeat(65)] {
            let error = SessionIdentity::resolve(harness, Some("session"))
                .expect_err("an invalid harness name");
            assert_eq!(error, SessionIdentityError::HarnessIdInvalid);
            assert_eq!(
                error.to_string(),
                "session_identity_harness_id_invalid",
                "no echoed content"
            );
        }
        let overlong = "x".repeat(2_048);
        let error = SessionIdentity::resolve("claude-code", Some(&overlong))
            .expect_err("an over-long session id");
        assert_eq!(
            error.to_string(),
            "session_identity_upstream_session_invalid",
            "no echoed content"
        );
    }

    #[test]
    fn a_synthetic_stand_in_is_never_a_path_name() {
        // Absence resolves to a minted UUIDv4 — the one shape a path
        // name cannot have. The harness's file name is not an input to
        // resolution, so "session-82d6…jsonl"-style naming can never
        // become identity: this pins the plan 7.4 never-inferred rule
        // structurally, by the shape of what absence produces.
        for _ in 0..8 {
            let identity = SessionIdentity::resolve("claude-code", None).expect("absent");
            assert!(is_canonical_uuid_v4(
                identity.upstream_session_id().as_str()
            ));
        }
    }

    #[test]
    fn synthetic_and_upstream_identities_enter_the_same_derivation() {
        let stated = SessionIdentity::resolve("claude-code", Some("session-1")).expect("stated");
        let minted = SessionIdentity::resolve("claude-code", None).expect("absent");
        // The derivation is one shape whatever the id_source; the
        // manifest records the difference, the hash input does not
        // special-case it.
        let stated_hash = stated.session_hash(&tenant(), &origin());
        let minted_hash = minted.session_hash(&tenant(), &origin());
        assert_ne!(stated_hash, minted_hash);
        assert_eq!(
            stated_hash,
            stated.session_hash(&tenant(), &origin()),
            "resolution is stable within one identity"
        );
    }
}
