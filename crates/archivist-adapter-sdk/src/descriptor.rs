// SPDX-License-Identifier: Apache-2.0

//! The adapter descriptor: requirement CAP-002's documented plugin
//! interface, published as data. One [`AdapterDescriptor`] is everything
//! the client engine — and the compatibility matrix — knows about an
//! adapter before any source is read: who it is, what it supports, which
//! fingerprints it admits, and which projection version it speaks.
//!
//! The descriptor is **content-free by construction**: every field is a
//! parsed project-owned or closed-vocabulary token, so a descriptor can
//! be embedded in a released adapter, printed in status, committed to
//! the compatibility matrix, and compared across hosts without ever
//! carrying a path, a hostname, or an upstream account value.

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{AdapterId, VersionToken};

use crate::capability::CapabilitySet;
use crate::fingerprint::FingerprintAllowlist;

/// Why a descriptor could not be published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DescriptorError {
    /// An adapter must declare at least one capability: an adapter that
    /// supports nothing is a configuration error, not an adapter.
    NoCapabilities,
}

impl std::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::NoCapabilities => "adapter_descriptor_no_capabilities",
        };
        f.write_str(token)
    }
}

impl std::error::Error for DescriptorError {}

/// The published self-description of one source adapter (CAP-002). Built
/// once at adapter construction from compile-time-constant parts;
/// everything it names is already validated by its own module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterDescriptor {
    /// The adapter's identity (protocol `AdapterId`).
    pub adapter: AdapterId,
    /// The projection version this adapter speaks (CAP-004): the same
    /// token that stamps every chunk and enters the artifact identity,
    /// so a projection change is visible here first.
    pub projection: VersionToken,
    /// The capabilities this adapter declares (CAP-002, CAP-008).
    pub capabilities: CapabilitySet,
    /// The exact supported-fingerprint allowlist this adapter embeds:
    /// every fingerprint it can detect, fail-closed against everything
    /// else (plan `EC-08`).
    pub fingerprints: FingerprintAllowlist,
}

impl AdapterDescriptor {
    /// Publish a descriptor.
    ///
    /// # Errors
    /// [`DescriptorError::NoCapabilities`] when `capabilities` is empty.
    pub fn publish(
        adapter: AdapterId,
        projection: VersionToken,
        capabilities: CapabilitySet,
        fingerprints: FingerprintAllowlist,
    ) -> Result<Self, DescriptorError> {
        if capabilities.is_empty() {
            return Err(DescriptorError::NoCapabilities);
        }
        Ok(Self {
            adapter,
            projection,
            capabilities,
            fingerprints,
        })
    }

    /// Whether this adapter can read a source showing `fingerprint`:
    /// the fail-closed admission decision, delegated to the allowlist.
    #[must_use]
    pub fn supports_fingerprint(
        &self,
        fingerprint: &crate::fingerprint::SourceFingerprint,
    ) -> bool {
        self.fingerprints.contains(fingerprint)
    }

    /// The compatibility-matrix row for this adapter: a fixed key set —
    /// identity, projection version, declared capability tokens, and
    /// supported fingerprint tokens — byte-stable across hosts because
    /// every collection is canonically ordered at construction.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("adapter", Value::Text(self.adapter.as_str().to_owned()));
        object.set("capabilities", self.capabilities.to_json());
        object.set("fingerprints", self.fingerprints.to_json());
        object.set(
            "projection",
            Value::Text(self.projection.as_str().to_owned()),
        );
        Value::Object(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::AdapterCapability;

    fn descriptor() -> AdapterDescriptor {
        AdapterDescriptor::publish(
            AdapterId::parse("claude-code").expect("valid adapter id"),
            VersionToken::parse("1.0.0").expect("valid version token"),
            CapabilitySet::parse(["file-slice-capture", "generation-detection"])
                .expect("valid capabilities"),
            FingerprintAllowlist::parse(["claude-jsonl-v1", "claude-jsonl-v2"])
                .expect("valid allowlist"),
        )
        .expect("non-empty capabilities")
    }

    #[test]
    fn descriptors_publish_only_with_capabilities() {
        assert_eq!(descriptor().capabilities.len(), 2);
        let empty = AdapterDescriptor::publish(
            AdapterId::parse("pi").expect("valid adapter id"),
            VersionToken::parse("0.1.0").expect("valid version token"),
            CapabilitySet::new(),
            FingerprintAllowlist::parse(["pi-jsonl-v1"]).expect("valid allowlist"),
        );
        assert_eq!(empty, Err(DescriptorError::NoCapabilities));
    }

    #[test]
    fn fingerprint_support_is_exact_and_fail_closed() {
        let descriptor = descriptor();
        let v1 = crate::fingerprint::SourceFingerprint::parse("claude-jsonl-v1")
            .expect("valid fingerprint");
        let v9 = crate::fingerprint::SourceFingerprint::parse("claude-jsonl-v9")
            .expect("parses, unsupported");
        assert!(descriptor.supports_fingerprint(&v1));
        assert!(!descriptor.supports_fingerprint(&v9));
        assert_eq!(
            descriptor
                .fingerprints
                .admit(&v9)
                .expect_err("fails closed")
                .classification(),
            crate::status::ScanClassification::FingerprintUnsupported
        );
        assert!(
            descriptor
                .capabilities
                .supports(AdapterCapability::FileSliceCapture)
        );
    }

    #[test]
    fn the_matrix_row_is_byte_stable_across_declaration_order() {
        let first = descriptor();
        // The same adapter, with the same members declared in a
        // different order, publishes the identical row.
        let second = AdapterDescriptor::publish(
            AdapterId::parse("claude-code").expect("valid adapter id"),
            VersionToken::parse("1.0.0").expect("valid version token"),
            CapabilitySet::parse(["generation-detection", "file-slice-capture"])
                .expect("valid capabilities"),
            FingerprintAllowlist::parse(["claude-jsonl-v2", "claude-jsonl-v1"])
                .expect("valid allowlist"),
        )
        .expect("non-empty capabilities");
        assert_eq!(
            first.to_json().canonical_bytes(),
            second.to_json().canonical_bytes()
        );
        let text = String::from_utf8(first.to_json().canonical_bytes()).expect("utf8");
        assert!(text.contains(r#""adapter":"claude-code""#));
        assert!(text.contains(r#""projection":"1.0.0""#));
        assert!(text.contains(r#""file-slice-capture""#));
        assert!(text.contains(r#""claude-jsonl-v1""#));
    }
}
