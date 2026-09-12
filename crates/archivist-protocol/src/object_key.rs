// SPDX-License-Identifier: Apache-2.0

//! Server-derived object keys (plan Section 7.5; ID-008).
//!
//! Keys are assembled only from validated tenant UUIDs, the pinned storage
//! profile, and computed digests — raw upstream identifiers and hostnames
//! never become key components. Each newtype builds the key from its typed
//! inputs and re-parses arbitrary text against both the segment grammar and
//! the semantic coupling (a shard segment must equal the first two hex of
//! the digest it shards), so a client walking a receipt cannot be handed a
//! key that disagrees with the bound identifiers (CAP-006 re-derivation).

use std::fmt;
use std::str::FromStr;

use crate::vocabulary::{
    AttestationId, BlobDigest, ClientId, GrammarError, HarnessId, OccurrenceId, SessionHash,
    StorageProfile, TenantId,
};

macro_rules! object_key {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// The assembled key.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

object_key!(
    /// `tenants/<tenant>/v1/raw/blobs/<profile>/sha256/<dd>/<digest>.zst` —
    /// the stored blob, sharded by the first two hex of its digest.
    BlobObjectKey
);
object_key!(
    /// `tenants/<tenant>/v1/raw/occurrences/<origin>/<harness>/<ss>/<session
    /// _hash>/<occurrence>.json` — the occurrence manifest. Raw upstream
    /// identifiers appear only as the hashed session and occurrence values.
    OccurrenceObjectKey
);
object_key!(
    /// `tenants/<tenant>/v1/raw/attestations/<oo>/<occurrence>/<attestation>
    /// .json` — the upload attestation, sharded by its occurrence.
    AttestationObjectKey
);

/// A prefix of `text` split on `/`, requiring exactly `n` segments.
fn split_exact(text: &str, n: usize) -> Option<Vec<&str>> {
    let segments: Vec<&str> = text.split('/').collect();
    (segments.len() == n).then_some(segments)
}

/// Parse `member.len() == hex_len + suffix.len()` with a hex body ending in
/// `suffix`, returning the hex body.
fn hex_member<'a>(member: &'a str, hex_len: usize, suffix: &str) -> Option<&'a str> {
    if member.len() != hex_len + suffix.len() || !member.ends_with(suffix) {
        return None;
    }
    Some(&member[..hex_len])
}

impl BlobObjectKey {
    /// Assemble the blob key for `tenant` and `blob` under the pinned
    /// storage profile (`zstd-v1` in v1).
    #[must_use]
    pub fn new(tenant: &TenantId, profile: StorageProfile, blob: &BlobDigest) -> Self {
        Self(format!(
            "tenants/{tenant}/v1/raw/blobs/{profile}/sha256/{shard}/{blob}.zst",
            shard = &blob.to_hex()[..2],
        ))
    }

    /// Parse and cross-check: tenant grammar, pinned profile, `sha256`
    /// algorithm segment, 2-hex shard equal to the digest prefix, digest
    /// grammar.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for any disagreement.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        let bad = || GrammarError::NotCanonical;
        // tenants/<tenant>/v1/raw/blobs/<profile>/sha256/<dd>/<digest>.zst
        let s = split_exact(text, 9).ok_or_else(bad)?;
        if s[0] != "tenants" || s[2] != "v1" || s[3] != "raw" || s[4] != "blobs" {
            return Err(bad());
        }
        TenantId::parse(s[1])?;
        StorageProfile::parse(s[5])?;
        if s[6] != "sha256" {
            return Err(bad());
        }
        let blob = BlobDigest::parse(hex_member(s[8], 64, ".zst").ok_or_else(bad)?)?;
        if s[7] != &blob.to_hex()[..2] {
            return Err(bad());
        }
        Ok(Self(text.to_owned()))
    }
}

impl OccurrenceObjectKey {
    /// Assemble the occurrence-manifest key from validated components.
    #[must_use]
    pub fn new(
        tenant: &TenantId,
        origin: &ClientId,
        harness: &HarnessId,
        session: &SessionHash,
        occurrence: &OccurrenceId,
    ) -> Self {
        Self(format!(
            "tenants/{tenant}/v1/raw/occurrences/{origin}/{harness}/{shard}/{session}/{occurrence}.json",
            shard = &session.to_hex()[..2],
        ))
    }

    /// Parse and cross-check the nine-segment layout, including the
    /// session-shard coupling.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for any disagreement.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        let bad = || GrammarError::NotCanonical;
        // tenants/<tenant>/v1/raw/occurrences/<origin>/<harness>/<ss>/<session>/<occurrence>.json
        let s = split_exact(text, 10).ok_or_else(bad)?;
        if s[0] != "tenants" || s[2] != "v1" || s[3] != "raw" || s[4] != "occurrences" {
            return Err(bad());
        }
        TenantId::parse(s[1])?;
        ClientId::parse(s[5])?;
        HarnessId::parse(s[6])?;
        let session = SessionHash::parse(s[8])?;
        OccurrenceId::parse(hex_member(s[9], 64, ".json").ok_or_else(bad)?)?;
        if s[7] != &session.to_hex()[..2] {
            return Err(bad());
        }
        Ok(Self(text.to_owned()))
    }
}

impl AttestationObjectKey {
    /// Assemble the attestation key for `tenant` and the
    /// occurrence→attestation pair.
    #[must_use]
    pub fn new(tenant: &TenantId, occurrence: &OccurrenceId, attestation: &AttestationId) -> Self {
        Self(format!(
            "tenants/{tenant}/v1/raw/attestations/{shard}/{occurrence}/{attestation}.json",
            shard = &occurrence.to_hex()[..2],
        ))
    }

    /// Parse and cross-check the seven-segment layout, including the
    /// occurrence-shard coupling.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for any disagreement.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        let bad = || GrammarError::NotCanonical;
        // tenants/<tenant>/v1/raw/attestations/<oo>/<occurrence>/<attestation>.json
        let s = split_exact(text, 8).ok_or_else(bad)?;
        if s[0] != "tenants" || s[2] != "v1" || s[3] != "raw" || s[4] != "attestations" {
            return Err(bad());
        }
        TenantId::parse(s[1])?;
        let occurrence = OccurrenceId::parse(s[6])?;
        AttestationId::parse(hex_member(s[7], 64, ".json").ok_or_else(bad)?)?;
        if s[5] != &occurrence.to_hex()[..2] {
            return Err(bad());
        }
        Ok(Self(text.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn blob_key_assembly_and_round_trip() {
        let tenant = TenantId::parse(TENANT).unwrap();
        let blob = BlobDigest::parse(DIGEST).unwrap();
        let key = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob);
        assert_eq!(
            key.as_str(),
            format!("tenants/{TENANT}/v1/raw/blobs/zstd-v1/sha256/01/{DIGEST}.zst")
        );
        assert_eq!(BlobObjectKey::parse(key.as_str()).unwrap(), key);
    }

    #[test]
    fn blob_key_rejects_disagreement() {
        let tenant = TenantId::parse(TENANT).unwrap();
        let blob = BlobDigest::parse(DIGEST).unwrap();
        let good = BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &blob);
        // Shard disagrees with digest prefix.
        let swapped = good.as_str().replace("/01/", "/ff/");
        assert!(BlobObjectKey::parse(&swapped).is_err());
        // Unknown profile.
        let profiled = good.as_str().replace("zstd-v1", "gzip-v9");
        assert!(BlobObjectKey::parse(&profiled).is_err());
        // Tenant grammar broken.
        let tenanted = good.as_str().replace(TENANT, "not-a-uuid");
        assert!(BlobObjectKey::parse(&tenanted).is_err());
        // Wrong extension.
        let stripped = good.as_str().replace(".zst", ".gz");
        assert!(BlobObjectKey::parse(&stripped).is_err());
        // Extra trailing segment.
        assert!(BlobObjectKey::parse(&format!("{good}/x")).is_err());
    }

    #[test]
    fn occurrence_key_assembly_and_shard_check() {
        let tenant = TenantId::parse(TENANT).unwrap();
        let origin = ClientId::parse("aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f").unwrap();
        let harness = HarnessId::parse("claude-code").unwrap();
        let session = SessionHash::parse(DIGEST).unwrap();
        let occurrence = OccurrenceId::parse(&"ab".repeat(32)).unwrap();
        let key = OccurrenceObjectKey::new(&tenant, &origin, &harness, &session, &occurrence);
        let occ_hex = "ab".repeat(32);
        assert_eq!(
            key.as_str(),
            format!(
                "tenants/{TENANT}/v1/raw/occurrences/aaaaaaaa-bbbb-4ccc-8ddd-1e2f3f4f5f6f/claude-code/01/{DIGEST}/{occ_hex}.json"
            )
        );
        assert_eq!(OccurrenceObjectKey::parse(key.as_str()).unwrap(), key);
        let swapped = key.as_str().replace("/01/", "/ff/");
        assert!(OccurrenceObjectKey::parse(&swapped).is_err());
        // Upstream identifiers can never be key components: a harness with a
        // slash is not a harness (split_exact sees ten segments).
        let bad_harness = key.as_str().replace("claude-code", "a/b");
        assert!(OccurrenceObjectKey::parse(&bad_harness).is_err());
    }

    #[test]
    fn attestation_key_assembly_and_shard_check() {
        let tenant = TenantId::parse(TENANT).unwrap();
        let occurrence = OccurrenceId::parse(DIGEST).unwrap();
        let attestation = AttestationId::parse(&"cd".repeat(32)).unwrap();
        let key = AttestationObjectKey::new(&tenant, &occurrence, &attestation);
        let att_hex = "cd".repeat(32);
        assert_eq!(
            key.as_str(),
            format!("tenants/{TENANT}/v1/raw/attestations/01/{DIGEST}/{att_hex}.json")
        );
        assert_eq!(AttestationObjectKey::parse(key.as_str()).unwrap(), key);
        let swapped = key.as_str().replace("/01/", "/99/");
        assert!(AttestationObjectKey::parse(&swapped).is_err());
    }
}
