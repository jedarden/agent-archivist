// SPDX-License-Identifier: Apache-2.0

//! The tenant trust configuration of one ingestion replica: which tenants
//! the replica serves and the tenant-authority public key each tenant's
//! control records must verify against.
//!
//! Plan Section 5: "Trust registration MUST live in an external
//! identity/control plane" (ARCH-005) — a replica is never the authority
//! for trust, it only carries the pinned verification anchors for the
//! tenants it serves. This module is that pinned anchor set, validated
//! fail-closed before a replica can start:
//!
//! - the set is **non-empty** — a replica configured to serve no tenant
//!   would otherwise advertise a readiness that is vacuously true, and a
//!   vacuous readiness is a lie the readiness contract (plan Phase 4)
//!   does not permit;
//! - every tenant is a canonical [`TenantId`] and appears **once** — a
//!   duplicated tenant would make two roots race over one trust identity;
//! - every authority key matches the wire's `ed25519-public-key-hex`
//!   grammar (`schemas/v1/common.json`: 32 raw bytes, lowercase hex) —
//!   the same encoding every control record and receipt carries;
//! - two tenants never share one authority key — tenants are distinct
//!   authorities by construction, and one key verifying for two tenants
//!   collapses the tenant boundary the tenancy exists to hold.
//!
//! This is configuration, not verification: what a key *signs* and how a
//! record's signature is checked belong to `archivist-auth` (Phase 3).
//! What this module buys the bootstrap is the fail-safe half of the
//! acceptance — a malformed or contradictory trust configuration is a
//! construction failure, never a replica that starts half-trusting.
//!
//! Like the storage configuration, these anchors have no registry keys
//! yet: the registry format gains the tenant-trust section when the
//! Phase 4 trust slice loads it from tiers; until then the composition
//! root assembles [`TrustConfig`] directly, exactly as the offline
//! control-administration surface does in `archivist-storage-s3`.

use std::fmt;

use archivist_protocol::vocabulary::TenantId;

/// Why a trust configuration failed validation: a closed class of
/// failure carrying the decision the operator must make next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TrustConfigErrorKind {
    /// No tenant root arrived at all.
    EmptyTrustSet,
    /// A value arrived but is outside its closed grammar.
    MalformedValue,
    /// The same tenant appeared twice.
    DuplicateTenant,
    /// Two tenants were pinned to the same authority key.
    SharedAuthority,
}

impl TrustConfigErrorKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::EmptyTrustSet,
            Self::MalformedValue,
            Self::DuplicateTenant,
            Self::SharedAuthority,
        ]
    }

    /// The content-free default detail shipped with this kind. The
    /// literals are pinned by a unit test to stay inside the project's
    /// safe-message grammar.
    #[must_use]
    pub const fn default_detail(self) -> &'static str {
        match self {
            Self::EmptyTrustSet => "at least one tenant root is required",
            Self::MalformedValue => "value is outside its closed grammar",
            Self::DuplicateTenant => "the same tenant appeared twice",
            Self::SharedAuthority => "two tenants share one authority key",
        }
    }
}

impl fmt::Display for TrustConfigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::EmptyTrustSet => "empty-trust-set",
            Self::MalformedValue => "malformed-value",
            Self::DuplicateTenant => "duplicate-tenant",
            Self::SharedAuthority => "shared-authority",
        };
        f.write_str(text)
    }
}

/// Why a trust configuration failed validation: a closed kind plus one
/// content-safe detail. The detail is a static literal by construction —
/// the type cannot carry the offending tenant or key text — so a trust
/// error can never echo operator input (CFG-027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TrustConfigError {
    kind: TrustConfigErrorKind,
    detail: &'static str,
}

impl TrustConfigError {
    /// Build an error carrying the kind's default detail.
    #[must_use]
    pub const fn of_kind(kind: TrustConfigErrorKind) -> Self {
        Self {
            kind,
            detail: kind.default_detail(),
        }
    }

    /// Build an error from a kind and a static, content-safe detail.
    #[must_use]
    pub const fn new(kind: TrustConfigErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The failure class.
    #[must_use]
    pub const fn kind(&self) -> TrustConfigErrorKind {
        self.kind
    }

    /// The content-free detail text.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for TrustConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "trust config {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for TrustConfigError {}

/// A tenant-authority Ed25519 public key in the wire's
/// `ed25519-public-key-hex` encoding: exactly 64 lowercase hex
/// characters, 32 raw bytes (`schemas/v1/common.json`).
///
/// This is verification material, not a secret: public halves travel by
/// value in every control record and receipt, so [`AuthorityKey`]'s
/// `Debug` and `Display` render the key text without redaction — the
/// pinned grammar is what keeps that rendering bounded and canonical.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthorityKey {
    text: String,
}

impl AuthorityKey {
    /// Parse an authority key, failing closed on anything outside the
    /// pinned grammar.
    ///
    /// # Errors
    /// [`TrustConfigErrorKind::MalformedValue`] for anything that is not
    /// 64 lowercase hex characters. The malformed input is not echoed.
    pub fn parse(text: &str) -> Result<Self, TrustConfigError> {
        let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if text.len() == 64 && text.bytes().all(is_hex) {
            Ok(Self {
                text: text.to_owned(),
            })
        } else {
            Err(TrustConfigError::new(
                TrustConfigErrorKind::MalformedValue,
                "authority key is outside the ed25519-public-key-hex grammar",
            ))
        }
    }

    /// The canonical wire text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for AuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl AsRef<[u8]> for AuthorityKey {
    fn as_ref(&self) -> &[u8] {
        self.text.as_bytes()
    }
}

/// One tenant's pinned trust anchor: the tenant and the only authority
/// key whose signatures count as that tenant's control-plane voice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantTrustRoot {
    tenant: TenantId,
    authority: AuthorityKey,
}

impl TenantTrustRoot {
    /// Pin one tenant to one authority key.
    ///
    /// # Errors
    /// [`TrustConfigErrorKind::MalformedValue`] when the tenant is
    /// outside the canonical uuid-v4 grammar or the key is outside the
    /// `ed25519-public-key-hex` grammar. The offending text is not
    /// echoed.
    pub fn new(tenant: &str, authority: &str) -> Result<Self, TrustConfigError> {
        let tenant: TenantId = tenant.parse().map_err(|_| {
            TrustConfigError::new(
                TrustConfigErrorKind::MalformedValue,
                "tenant is outside the canonical uuid grammar",
            )
        })?;
        let authority = AuthorityKey::parse(authority)?;
        Ok(Self { tenant, authority })
    }

    /// The tenant this anchor serves.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The authority key whose signatures count for this tenant.
    #[must_use]
    pub const fn authority(&self) -> &AuthorityKey {
        &self.authority
    }
}

/// The validated trust anchor set of one ingestion replica: at least one
/// tenant, each tenant exactly once, each with its own authority key.
///
/// Construct only through [`TrustConfig::from_roots`]; the anchor order
/// is normalized to tenant order so two configurations for the same
/// deployment compare equal regardless of assembly order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustConfig {
    roots: Vec<TenantTrustRoot>,
}

impl TrustConfig {
    /// Validate and build the anchor set.
    ///
    /// # Errors
    /// [`TrustConfigErrorKind::EmptyTrustSet`] for an empty set,
    /// [`TrustConfigErrorKind::DuplicateTenant`] when one tenant appears
    /// twice, and [`TrustConfigErrorKind::SharedAuthority`] when two
    /// tenants pin the same authority key.
    pub fn from_roots(roots: Vec<TenantTrustRoot>) -> Result<Self, TrustConfigError> {
        if roots.is_empty() {
            return Err(TrustConfigError::of_kind(
                TrustConfigErrorKind::EmptyTrustSet,
            ));
        }
        for (index, root) in roots.iter().enumerate() {
            for earlier in roots.iter().take(index) {
                if earlier.tenant() == root.tenant() {
                    return Err(TrustConfigError::of_kind(
                        TrustConfigErrorKind::DuplicateTenant,
                    ));
                }
                if earlier.authority() == root.authority() {
                    return Err(TrustConfigError::of_kind(
                        TrustConfigErrorKind::SharedAuthority,
                    ));
                }
            }
        }
        let mut roots = roots;
        roots.sort_by(|a, b| a.tenant().as_str().cmp(b.tenant().as_str()));
        Ok(Self { roots })
    }

    /// The pinned anchors, in normalized tenant order.
    #[must_use]
    pub fn roots(&self) -> &[TenantTrustRoot] {
        &self.roots
    }

    /// The number of tenants this replica serves.
    #[must_use]
    pub fn tenant_count(&self) -> usize {
        self.roots.len()
    }

    /// The anchor for one tenant, if this replica serves it.
    ///
    /// A tenant outside the configuration has no anchor: the
    /// authorization path treats such a request as untrusted, not as an
    /// error to probe for (fail closed, never fail chatty).
    #[must_use]
    pub fn root_for(&self, tenant: &TenantId) -> Option<&TenantTrustRoot> {
        self.roots.iter().find(|root| root.tenant() == tenant)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityKey, TenantTrustRoot, TrustConfig, TrustConfigError, TrustConfigErrorKind,
    };

    const TENANT_A: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const TENANT_B: &str = "1a2b3c4d-5e6f-4a1b-8c2d-3e4f5a6b7c8d";
    const KEY_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const KEY_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

    fn root_a() -> TenantTrustRoot {
        TenantTrustRoot::new(TENANT_A, KEY_A).unwrap()
    }

    fn root_b() -> TenantTrustRoot {
        TenantTrustRoot::new(TENANT_B, KEY_B).unwrap()
    }

    #[test]
    fn a_valid_anchor_set_round_trips() {
        let config = TrustConfig::from_roots(vec![root_a(), root_b()]).unwrap();
        assert_eq!(config.tenant_count(), 2);
        // Normalized order, independent of assembly order.
        assert_eq!(config.roots()[0].tenant().as_str(), TENANT_A);
        assert_eq!(config.roots()[1].tenant().as_str(), TENANT_B);
        assert_eq!(
            config
                .root_for(&TENANT_A.parse().unwrap())
                .unwrap()
                .authority()
                .as_str(),
            KEY_A
        );
        assert!(
            config
                .root_for(&"99999999-9999-4999-8999-999999999999".parse().unwrap())
                .is_none()
        );
    }

    #[test]
    fn two_configurations_of_one_deployment_compare_equal() {
        let first = TrustConfig::from_roots(vec![root_a(), root_b()]).unwrap();
        let second = TrustConfig::from_roots(vec![root_b(), root_a()]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn an_empty_trust_set_is_a_construction_failure() {
        let error = TrustConfig::from_roots(vec![]).unwrap_err();
        assert_eq!(error.kind(), TrustConfigErrorKind::EmptyTrustSet);
        assert_eq!(error.detail(), "at least one tenant root is required");
    }

    #[test]
    fn a_duplicated_tenant_is_a_construction_failure() {
        let error = TrustConfig::from_roots(vec![root_a(), root_a()]).unwrap_err();
        assert_eq!(error.kind(), TrustConfigErrorKind::DuplicateTenant);
        assert_eq!(error.detail(), "the same tenant appeared twice");
    }

    #[test]
    fn a_shared_authority_key_is_a_construction_failure() {
        let shared = TenantTrustRoot::new(TENANT_B, KEY_A).unwrap();
        let error = TrustConfig::from_roots(vec![root_a(), shared]).unwrap_err();
        assert_eq!(error.kind(), TrustConfigErrorKind::SharedAuthority);
        assert_eq!(error.detail(), "two tenants share one authority key");
    }

    #[test]
    fn malformed_tenants_fail_closed_without_echo() {
        for tenant in [
            "",
            "not-a-uuid",
            "0F1E2D3C-4B5A-4978-8A9B-0C1D2E3F4A5B",
            "0f1e2d3c-4b5a-ca9b-8a9b-0c1d2e3f4a5b",
            "0f1e2d3c4b5a49788a9b0c1d2e3f4a5b",
        ] {
            let error = TenantTrustRoot::new(tenant, KEY_A).unwrap_err();
            assert_eq!(
                error.kind(),
                TrustConfigErrorKind::MalformedValue,
                "{tenant:?}"
            );
            assert_eq!(
                error.detail(),
                "tenant is outside the canonical uuid grammar"
            );
        }
    }

    #[test]
    fn malformed_authority_keys_fail_closed_without_echo() {
        for key in [
            "",
            "0123",
            KEY_A.to_uppercase().as_str(),
            &"g".repeat(64),
            &"0".repeat(63),
            &"0".repeat(65),
            &format!("{KEY_A}\n"),
        ] {
            let error = AuthorityKey::parse(key).unwrap_err();
            assert_eq!(
                error.kind(),
                TrustConfigErrorKind::MalformedValue,
                "{key:?}"
            );
            assert_eq!(
                error.detail(),
                "authority key is outside the ed25519-public-key-hex grammar"
            );
        }
    }

    #[test]
    fn authority_keys_render_canonically() {
        let key = AuthorityKey::parse(KEY_A).unwrap();
        assert_eq!(key.as_str(), KEY_A);
        assert_eq!(key.to_string(), KEY_A);
        assert_eq!(key.as_ref(), KEY_A.as_bytes());
    }

    #[test]
    fn error_kinds_and_details_stay_inside_the_safe_grammar() {
        for kind in TrustConfigErrorKind::all() {
            let detail = kind.default_detail();
            assert!(!detail.is_empty());
            assert!(
                detail.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                "{detail:?}"
            );
            assert!(!detail.contains('{') && !detail.contains('}'), "{detail:?}");
        }
        let rendered = TrustConfigError::of_kind(TrustConfigErrorKind::SharedAuthority).to_string();
        assert_eq!(
            rendered,
            "trust config shared-authority: two tenants share one authority key"
        );
    }
}
