// SPDX-License-Identifier: Apache-2.0

//! The control-plane boundary (plan Section 5, [control trust]):
//! two disjoint authorities over the signed records below
//! `tenants/<tenant>/v1/control/`.
//!
//! - [`ControlReadStore`] — the ingestion replica's view: read-only access
//!   to the five record families, one method per family, each key derived
//!   from validated identifiers. It has no write method of any kind.
//! - [`ControlAdminStore`] — the offline administrator's write authority:
//!   complete, tenant-authority-signed records only, never arbitrary keys
//!   or payload bytes. Ingest replicas never receive this credential.
//!
//! Neither trait touches raw, catalog, derived, tombstone, or legal-hold
//! data, and the record *semantics* — signature verification, epochs as
//! trust, the 60-second cache policy — live in `archivist-auth` and the
//! server, not here. This module owns only the storage boundary: the
//! record-kind vocabulary keys are derived from, the two write classes with
//! their overwrite rules, and the byte-exact records as observed.
//!
//! [control trust]: ../../../docs/notes/control-trust.md

use std::fmt;
use std::future::Future;
use std::str::FromStr;

use archivist_protocol::vocabulary::{ClientId, GrammarError, KeyId, TenantId};

use crate::error::StorageError;
use crate::metadata::Observation;

/// Why a candidate control-vocabulary value is not valid.
pub type ControlVocabularyError = GrammarError;

/// The closed set of signed record families the control prefix carries
/// (`archivist.control-registry/v1`; the set is append-only within v1 —
/// a new record type lands here as a new variant in the same change that
/// extends the registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlRecordKind {
    /// One installation's identity in one tenant; current-pointer write
    /// class.
    LinkedClient,
    /// One relay's authority to present one origin client's occurrences;
    /// current-pointer write class.
    Delegation,
    /// A client's revocation at one authorization epoch; immutable write
    /// class.
    Revocation,
    /// A client's key rotation at one authorization epoch; immutable write
    /// class.
    Rotation,
    /// A tenant-scoped receipt-verification key; immutable write class.
    ReceiptKey,
}

impl ControlRecordKind {
    /// Every record family, in registry order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::LinkedClient,
            Self::Delegation,
            Self::Revocation,
            Self::Rotation,
            Self::ReceiptKey,
        ]
    }

    /// The registry token.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::LinkedClient => "linked-client",
            Self::Delegation => "delegation",
            Self::Revocation => "revocation",
            Self::Rotation => "rotation",
            Self::ReceiptKey => "receipt-key",
        }
    }

    /// Parse one registry token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`ControlVocabularyError::NotCanonical`] for a token outside the
    /// closed v1 registry.
    pub fn parse(text: &str) -> Result<Self, ControlVocabularyError> {
        match text {
            "linked-client" => Ok(Self::LinkedClient),
            "delegation" => Ok(Self::Delegation),
            "revocation" => Ok(Self::Revocation),
            "rotation" => Ok(Self::Rotation),
            "receipt-key" => Ok(Self::ReceiptKey),
            _ => Err(ControlVocabularyError::NotCanonical),
        }
    }

    /// The write class governing overwrites of this family.
    ///
    /// The class is a property of the record family, not of the caller:
    /// immutable families (`revocation`, `rotation`, `receipt-key`) are
    /// addressed by their own epoch or key, so a conflicting object at the
    /// same key is an integrity conflict, never a rewrite; current-pointer
    /// families (`linked-client`, `delegation`) live at one key per client
    /// pair and advance only by a strictly increasing signed epoch.
    #[must_use]
    pub fn write_class(self) -> ControlWriteClass {
        match self {
            Self::LinkedClient | Self::Delegation => ControlWriteClass::CurrentPointer,
            Self::Revocation | Self::Rotation | Self::ReceiptKey => ControlWriteClass::Immutable,
        }
    }
}

impl fmt::Display for ControlRecordKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.token())
    }
}

impl FromStr for ControlRecordKind {
    type Err = ControlVocabularyError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::parse(text)
    }
}

/// The overwrite rule for one control record family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ControlWriteClass {
    /// One key names the current record; a replacement is accepted only
    /// when its signed authorization epoch strictly increases over the
    /// stored pointer (plan Section 5).
    CurrentPointer,
    /// The key is addressed by the record's own epoch or key ID; an
    /// incompatible object at an occupied key is rejected as an integrity
    /// conflict, and an identical record re-put is idempotent success.
    Immutable,
}

/// A monotonic authorization epoch (`>= 1`; the link is epoch 1, and every
/// administrative act on a client publishes the next epoch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationEpoch(u64);

impl AuthorizationEpoch {
    /// Adopt `n` as an authorization epoch.
    ///
    /// # Errors
    /// [`ControlVocabularyError::NotCanonical`] for 0 — epochs are
    /// one-based by construction, so no stored record can carry a 0 epoch.
    pub fn new(n: u64) -> Result<Self, ControlVocabularyError> {
        if n == 0 {
            return Err(ControlVocabularyError::NotCanonical);
        }
        Ok(Self(n))
    }

    /// The epoch value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for AuthorizationEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for AuthorizationEpoch {
    type Err = ControlVocabularyError;
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .map(Self)
            .ok_or(ControlVocabularyError::NotCanonical)
    }
}

/// One signed control record exactly as the store observed it.
///
/// `envelope` is the byte-exact stored object — the complete record with its
/// tenant-authority signature, unaltered. Verification is `archivist-auth`'s
/// job; this type guarantees only that these are the bytes at the derived
/// key as of [`Observation::observed_at`], which is what bounds the
/// consumer's 60-second trust cache (`EC-09`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlRecord {
    envelope: Vec<u8>,
    observation: Observation,
}

impl ControlRecord {
    /// Pair the stored bytes with how they were observed.
    #[must_use]
    pub const fn new(envelope: Vec<u8>, observation: Observation) -> Self {
        Self {
            envelope,
            observation,
        }
    }

    /// The byte-exact stored envelope.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }

    /// How and when the store observed the envelope.
    #[must_use]
    pub const fn observation(&self) -> &Observation {
        &self.observation
    }
}

/// A complete, tenant-authority-signed control record handed to
/// [`ControlAdminStore`].
///
/// The key is deliberately absent: the implementation derives it from the
/// validated record family and the members inside the signed envelope
/// (plan Section 5: "The S3 adapter derives each key from the validated
/// record type"). Accepting a caller-chosen key would make the offline
/// store a general-purpose object writer, which is exactly the authority
/// this boundary withholds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminControlRecord {
    kind: ControlRecordKind,
    envelope: Vec<u8>,
}

impl AdminControlRecord {
    /// Present a complete signed record of `kind`.
    ///
    /// `envelope` must be the complete record object — every field the
    /// family's schema requires, including the tenant-authority signature
    /// and the key members the implementation derives the object key from.
    #[must_use]
    pub const fn new(kind: ControlRecordKind, envelope: Vec<u8>) -> Self {
        Self { kind, envelope }
    }

    /// The record family.
    #[must_use]
    pub const fn kind(&self) -> ControlRecordKind {
        self.kind
    }

    /// The complete signed record bytes.
    #[must_use]
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
}

/// The ingestion replica's control-prefix authority: read the five signed
/// record families, nothing else.
///
/// One method per family, each key derived from validated identifiers —
/// there is no `read(key)` on this trait, so the read authority cannot be
/// pointed at an arbitrary object. The trait has no write, delete, or list
/// method: an ingestion replica cannot publish, retract, or enumerate
/// control records through its storage configuration, and it has no path to
/// the raw, catalog, or derived prefixes at all (plan Section 5).
///
/// Reads return `Ok(None)` for an absent record — an unlinked client and a
/// client with no delegation at a key are ordinary states, not errors.
/// `Ok(Some(record))` hands over unverified bytes; failing closed on a bad
/// signature, a stale epoch, or an expired cache entry is the consumer's
/// contract (`EC-09`), not the store's.
pub trait ControlReadStore {
    /// Read the linked-client record for one installation.
    ///
    /// # Errors
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down,
    /// [`StorageError::ScopeViolation`](crate::error::StorageError) when the
    /// tenant is outside this identity's provisioning.
    fn read_linked_client(
        &self,
        tenant: &TenantId,
        client: &ClientId,
    ) -> impl Future<Output = Result<Option<ControlRecord>, StorageError>> + Send;

    /// Read the delegation record granting `relay` authority over `origin`.
    ///
    /// # Errors
    /// As [`ControlReadStore::read_linked_client`].
    fn read_delegation(
        &self,
        tenant: &TenantId,
        relay: &ClientId,
        origin: &ClientId,
    ) -> impl Future<Output = Result<Option<ControlRecord>, StorageError>> + Send;

    /// Read one revocation record at an exact authorization epoch.
    ///
    /// # Errors
    /// As [`ControlReadStore::read_linked_client`].
    fn read_revocation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> impl Future<Output = Result<Option<ControlRecord>, StorageError>> + Send;

    /// Read one rotation record at an exact authorization epoch.
    ///
    /// # Errors
    /// As [`ControlReadStore::read_linked_client`].
    fn read_rotation(
        &self,
        tenant: &TenantId,
        client: &ClientId,
        epoch: AuthorizationEpoch,
    ) -> impl Future<Output = Result<Option<ControlRecord>, StorageError>> + Send;

    /// Read the receipt-key record for one verification key.
    ///
    /// # Errors
    /// As [`ControlReadStore::read_linked_client`].
    fn read_receipt_key(
        &self,
        tenant: &TenantId,
        key: &KeyId,
    ) -> impl Future<Output = Result<Option<ControlRecord>, StorageError>> + Send;
}

/// The offline administrator's control-prefix write authority.
///
/// Separate credential, separate trait, never configured on an ingest
/// replica (plan Section 5). It accepts complete signed records — never
/// arbitrary keys or payload bytes — and enforces the two write classes:
/// an immutable family rejects an incompatible object at an occupied key,
/// and a current-pointer family accepts a replacement only when its signed
/// epoch strictly increases.
///
/// The trait has no read, delete, or list method. Removal is not a store
/// operation: revocations are never removed, immutable records stay for
/// retained receipts, and superseded pointers are replaced by higher epochs,
/// not deleted — an offline administrator who needs to correct a record
/// publishes the next epoch.
pub trait ControlAdminStore {
    /// Put one record of an immutable family (`revocation`, `rotation`,
    /// `receipt-key`).
    ///
    /// Re-putting the byte-identical record is idempotent success. An
    /// incompatible object at the same derived key is
    /// [`StorageError::IntegrityConflict`](crate::error::StorageError) —
    /// retrying it is an overwrite loop, not a repair (`EC-06`).
    ///
    /// # Errors
    /// [`StorageError::IntegrityConflict`](crate::error::StorageError) on an
    /// incompatible overwrite,
    /// [`StorageError::MalformedInput`](crate::error::StorageError) when the
    /// envelope does not validate as a complete signed record of `kind`,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn put_immutable_record(
        &self,
        record: &AdminControlRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Replace one current-pointer record (`linked-client`, `delegation`)
    /// with a higher signed epoch.
    ///
    /// # Errors
    /// [`StorageError::StaleEpoch`](crate::error::StorageError) when the
    /// presented epoch does not strictly increase over the stored pointer,
    /// [`StorageError::MalformedInput`](crate::error::StorageError) when the
    /// envelope does not validate as a complete signed record of `kind`,
    /// [`StorageError::Unavailable`](crate::error::StorageError) when the
    /// backend or network is down.
    fn put_current_pointer(
        &self,
        record: &AdminControlRecord,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::{
        AdminControlRecord, AuthorizationEpoch, ControlRecord, ControlRecordKind, ControlWriteClass,
    };
    use crate::metadata::Observation;

    #[test]
    fn record_kinds_round_trip_and_fail_closed() {
        for kind in ControlRecordKind::all() {
            assert_eq!(ControlRecordKind::parse(kind.token()).unwrap(), *kind);
        }
        assert_eq!(ControlRecordKind::all().len(), 5);
        assert!(ControlRecordKind::parse("linked_client").is_err());
        assert!(ControlRecordKind::parse("tombstone").is_err());
        assert!(ControlRecordKind::parse("").is_err());
    }

    #[test]
    fn write_classes_match_the_registry() {
        assert_eq!(
            ControlRecordKind::LinkedClient.write_class(),
            ControlWriteClass::CurrentPointer
        );
        assert_eq!(
            ControlRecordKind::Delegation.write_class(),
            ControlWriteClass::CurrentPointer
        );
        for kind in [
            ControlRecordKind::Revocation,
            ControlRecordKind::Rotation,
            ControlRecordKind::ReceiptKey,
        ] {
            assert_eq!(kind.write_class(), ControlWriteClass::Immutable);
        }
    }

    #[test]
    fn epochs_are_one_based() {
        assert!(AuthorizationEpoch::new(1).is_ok());
        assert!(AuthorizationEpoch::new(0).is_err());
        assert!(AuthorizationEpoch::new(u64::MAX).is_ok());
        assert_eq!(AuthorizationEpoch::new(41).unwrap().get(), 41);
        assert!("1".parse::<AuthorizationEpoch>().is_ok());
        assert!("0".parse::<AuthorizationEpoch>().is_err());
        assert!("-1".parse::<AuthorizationEpoch>().is_err());
        assert!("x".parse::<AuthorizationEpoch>().is_err());
    }

    #[test]
    fn epochs_order_monotonically() {
        let first = AuthorizationEpoch::new(1).unwrap();
        let second = AuthorizationEpoch::new(2).unwrap();
        assert!(first < second);
    }

    #[test]
    fn records_carry_exact_bytes_and_observation() {
        let stamp =
            archivist_protocol::vocabulary::Timestamp::parse("2026-09-13T12:00:00Z").unwrap();
        let observation = Observation::new(None, None, stamp);
        let record = ControlRecord::new(b"envelope-bytes".to_vec(), observation);
        assert_eq!(record.envelope(), b"envelope-bytes");
        assert_eq!(
            record.observation().observed_at().as_str(),
            "2026-09-13T12:00:00Z"
        );

        let admin = AdminControlRecord::new(
            ControlRecordKind::Revocation,
            b"complete-signed-record".to_vec(),
        );
        assert_eq!(admin.kind(), ControlRecordKind::Revocation);
        assert_eq!(admin.envelope(), b"complete-signed-record");
    }
}
