// SPDX-License-Identifier: Apache-2.0

//! Tenant-scoped receipt signing and offline receipt verification.
//!
//! A receipt has two independently authenticated links.  The tenant
//! authority signs a public receipt-key certificate and the certified key
//! signs the receipt.  The certificate is embedded in the receipt, so a
//! client can verify the complete chain from its pinned authority root
//! without contacting the server or a current control-plane replica.
//!
//! Receipt keys are deliberately loaded only through [`ProtectedReference`].
//! There is no public constructor accepting a seed or private key.  The
//! resulting private half is held only by [`CertifiedReceiptKey`] while the
//! public certificate and immutable control record are the only values a
//! publication or receipt may expose.

use std::collections::BTreeMap;
use std::fmt;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{
    Ed25519PublicKey, Ed25519Signature, KeyId, SignatureAlgorithm, TenantId, Timestamp,
};

use crate::authority::{
    AuthorityChainError, PinnedAuthorityRoot, ResolvedAuthority, verify_signing_authority,
};
use crate::ed25519;
use crate::error::IdentityError;
use crate::identity::SigningKey;
use crate::reference::ProtectedReference;

/// How often a new tenant-scoped receipt key is certified.
pub const RECEIPT_KEY_ROTATION_DAYS: i64 = 30;

/// How long the previous receipt key remains allowed to sign after its
/// successor starts signing.
pub const RECEIPT_KEY_SIGNING_OVERLAP_DAYS: i64 = 7;

/// The complete signing lifetime of a receipt key.
pub const RECEIPT_KEY_VALIDITY_DAYS: i64 =
    RECEIPT_KEY_ROTATION_DAYS + RECEIPT_KEY_SIGNING_OVERLAP_DAYS;

const CERTIFICATE_VERSION: i64 = 1;
const CONTROL_NAMESPACE: &str = "archivist.control/v1";
const CONTROL_RECORD_TYPE: &str = "receipt-key";
const CONTROL_RECORD_KIND: &str = "immutable";
const RECEIPT_VERSION: i64 = 1;
const ALGORITHM: SignatureAlgorithm = SignatureAlgorithm::Ed25519;

const CERTIFICATE_MEMBERS: [&str; 9] = [
    "authority_key_id",
    "authority_signature",
    "certificate_version",
    "key_algorithm",
    "key_id",
    "public_key",
    "tenant_id",
    "valid_from",
    "valid_until",
];

const CONTROL_MEMBERS: [&str; 12] = [
    "authority_key_id",
    "authority_signature",
    "key_algorithm",
    "key_id",
    "public_key",
    "record_kind",
    "record_type",
    "schema",
    "signed_at",
    "tenant_id",
    "valid_from",
    "valid_until",
];

const RECEIPT_PROTECTED_MEMBERS: [&str; 5] = [
    "certificate",
    "receipt_key_id",
    "receipt_version",
    "signature",
    "signature_algorithm",
];

/// Why receipt trust or receipt signing failed.
///
/// Variants intentionally carry no input, path, key, signature, or secret
/// material.  This keeps errors safe for logs and wire-level diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiptKeyError {
    /// A record or receipt does not have the closed shape or a valid value.
    MalformedRecord,
    /// A record belongs to a different tenant or a certificate disagrees
    /// with the receipt that carries it.
    TenantMismatch,
    /// A key ID is not the SHA-256 derivation of its public key.
    KeyDerivation,
    /// A timestamp or signing-window relationship is invalid.
    InvalidWindow,
    /// A receipt contains a protected field supplied by its caller.
    ProtectedField,
    /// The requested commit instant is outside the certified key window.
    OutsideSigningWindow,
    /// A signature did not verify under the authenticated public half.
    Signature,
    /// A receipt-key record at an immutable address conflicts with the
    /// record already retained there.
    ConflictingRecord,
    /// A rotation is not exactly the next 30-day cadence.
    RotationCadence,
    /// The private half could not be obtained through a safe reference.
    SecretReference(IdentityError),
    /// The authority chain could not authenticate the certificate signer.
    Authority(AuthorityChainError),
}

impl fmt::Display for ReceiptKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::MalformedRecord => "receipt trust record is malformed",
            Self::TenantMismatch => "receipt trust record belongs to another tenant",
            Self::KeyDerivation => "receipt key identifier does not derive from its public key",
            Self::InvalidWindow => "receipt trust signing window is invalid",
            Self::ProtectedField => "receipt contains a signer-controlled field",
            Self::OutsideSigningWindow => "receipt commit time is outside the signing window",
            Self::Signature => "receipt trust signature failed verification",
            Self::ConflictingRecord => "retained receipt trust record conflicts at its key",
            Self::RotationCadence => "receipt key is not the next 30-day rotation",
            Self::SecretReference(_) => "receipt private key reference could not be resolved",
            Self::Authority(_) => "receipt certificate authority chain could not be verified",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ReceiptKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SecretReference(error) => Some(error),
            Self::Authority(error) => Some(error),
            _ => None,
        }
    }
}

impl From<AuthorityChainError> for ReceiptKeyError {
    fn from(error: AuthorityChainError) -> Self {
        Self::Authority(error)
    }
}

/// A private receipt-signing half loaded through a protected secret
/// reference.  Its debug representation is always redacted.
pub struct ReceiptSigningKey {
    tenant_id: TenantId,
    signing_key: SigningKey,
}

impl fmt::Debug for ReceiptSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiptSigningKey(<redacted>)")
    }
}

impl ReceiptSigningKey {
    /// Load a tenant-scoped receipt key from a `file:` or `env:` protected
    /// reference.  The reference resolver enforces the configured secret
    /// channel and, for files, restrictive permissions.
    ///
    /// # Errors
    /// [`ReceiptKeyError::SecretReference`] when the reference is missing,
    /// unsafe, unreadable, or does not contain exactly one Ed25519 seed.
    pub fn from_secret_reference(
        tenant_id: TenantId,
        reference: &ProtectedReference,
    ) -> Result<Self, ReceiptKeyError> {
        let bytes = reference
            .resolve()
            .map_err(ReceiptKeyError::SecretReference)?;
        let seed = decode_seed(&bytes).ok_or(ReceiptKeyError::SecretReference(
            IdentityError::IdentityCorrupt,
        ))?;
        Ok(Self {
            tenant_id,
            signing_key: SigningKey::from_seed(seed),
        })
    }

    /// The tenant this private key is scoped to.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The public half corresponding to this private key.
    #[must_use]
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey::from_raw(self.signing_key.public_key())
    }

    /// The derived public key identifier.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_key(&self.public_key())
    }

    fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature::from_raw(*self.signing_key.sign(message).as_bytes())
    }
}

/// A tenant authority private signer loaded through a protected reference.
/// It is used only during the offline certification operation; its public
/// key ID is what enters the certificate and control record.
pub struct AuthoritySigner {
    tenant_id: TenantId,
    signing_key: SigningKey,
}

/// The descriptive name used by callers that model the tenant authority.
pub type TenantAuthoritySigner = AuthoritySigner;

impl fmt::Debug for AuthoritySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthoritySigner(<redacted>)")
    }
}

impl AuthoritySigner {
    /// Load the tenant authority signing half from a protected reference.
    /// No constructor accepts a raw seed or private-key string.
    ///
    /// # Errors
    /// [`ReceiptKeyError::SecretReference`] when the reference cannot be
    /// resolved to one Ed25519 seed.
    pub fn from_secret_reference(
        tenant_id: TenantId,
        reference: &ProtectedReference,
    ) -> Result<Self, ReceiptKeyError> {
        let bytes = reference
            .resolve()
            .map_err(ReceiptKeyError::SecretReference)?;
        let seed = decode_seed(&bytes).ok_or(ReceiptKeyError::SecretReference(
            IdentityError::IdentityCorrupt,
        ))?;
        Ok(Self {
            tenant_id,
            signing_key: SigningKey::from_seed(seed),
        })
    }

    /// The authority tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The public authority half's ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        KeyId::from_public_key(&Ed25519PublicKey::from_raw(self.signing_key.public_key()))
    }

    fn sign(&self, message: &[u8]) -> Ed25519Signature {
        Ed25519Signature::from_raw(*self.signing_key.sign(message).as_bytes())
    }
}

/// The public certificate embedded in every receipt signed by one receipt
/// key.  Its authority signature covers the complete certificate except for
/// `authority_signature`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptKeyCertificate {
    tenant_id: TenantId,
    key_id: KeyId,
    public_key: Ed25519PublicKey,
    valid_from: Timestamp,
    valid_until: Timestamp,
    authority_key_id: KeyId,
    authority_signature: Ed25519Signature,
}

impl ReceiptKeyCertificate {
    /// Parse a by-value certificate, retaining unknown receipt fields outside
    /// the certificate while failing closed on this certificate's shape.
    ///
    /// # Errors
    /// [`ReceiptKeyError::MalformedRecord`] when the certificate shape,
    /// grammar, or version is not the v1 contract.
    pub fn parse(value: &Value) -> Result<Self, ReceiptKeyError> {
        let Value::Object(object) = value else {
            return Err(ReceiptKeyError::MalformedRecord);
        };
        if object.len() != CERTIFICATE_MEMBERS.len()
            || CERTIFICATE_MEMBERS
                .iter()
                .any(|member| object.get(member).is_none())
        {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        if int_member(object, "certificate_version") != Some(CERTIFICATE_VERSION)
            || text_member(object, "key_algorithm") != Some(ALGORITHM.token())
        {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        let tenant_id = parse_tenant(object, "tenant_id")?;
        let public_key = parse_public_key(object, "public_key")?;
        let key_id = parse_key_id(object, "key_id")?;
        if key_id != KeyId::from_public_key(&public_key) {
            return Err(ReceiptKeyError::KeyDerivation);
        }
        let valid_from = parse_timestamp(object, "valid_from")?;
        let valid_until = parse_timestamp(object, "valid_until")?;
        validate_window(&valid_from, &valid_until)?;
        let authority_key_id = parse_key_id(object, "authority_key_id")?;
        let authority_signature = parse_signature(object, "authority_signature")?;
        Ok(Self {
            tenant_id,
            key_id,
            public_key,
            valid_from,
            valid_until,
            authority_key_id,
            authority_signature,
        })
    }

    /// The tenant this certificate serves.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The certified receipt key ID.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The certified public half.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The instant at which receipts signed by this key become valid.
    #[must_use]
    pub const fn valid_from(&self) -> &Timestamp {
        &self.valid_from
    }

    /// The last instant at which this key may sign a receipt.
    #[must_use]
    pub const fn valid_until(&self) -> &Timestamp {
        &self.valid_until
    }

    /// The tenant authority key that certified this receipt key.
    #[must_use]
    pub const fn authority_key_id(&self) -> &KeyId {
        &self.authority_key_id
    }

    /// The bare certificate bytes covered by `receipt-key-v1`.
    #[must_use]
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        Value::Object(self.certificate_object(false)).canonical_bytes()
    }

    /// The complete canonical certificate bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Value::Object(self.certificate_object(true)).canonical_bytes()
    }

    /// Verify the authority link and this certificate's signature offline.
    /// The `fetch` closure supplies retained authority-rotation records by
    /// predecessor key ID.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when the tenant, authority chain, window,
    /// or certificate signature fails verification.
    pub fn verify(
        &self,
        root: &PinnedAuthorityRoot,
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<ResolvedAuthority, ReceiptKeyError> {
        if self.tenant_id != *root.tenant_id() {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        let resolved =
            verify_signing_authority(root, &self.authority_key_id, &self.valid_from, fetch)?;
        let signature = ed25519::Signature::from_bytes(*self.authority_signature.as_raw());
        if !ed25519::verify(
            resolved.public_key().as_raw(),
            &self.unsigned_canonical_bytes(),
            &signature,
        ) {
            return Err(ReceiptKeyError::Signature);
        }
        Ok(resolved)
    }

    fn certificate_object(&self, include_signature: bool) -> Object {
        let mut object = Object::new();
        object.set("certificate_version", Value::Int(CERTIFICATE_VERSION));
        object.set("tenant_id", text(self.tenant_id.as_str()));
        object.set("key_id", text(&self.key_id.to_hex()));
        object.set("key_algorithm", text(ALGORITHM.token()));
        object.set("public_key", text(&self.public_key.to_hex()));
        object.set("valid_from", text(self.valid_from.as_str()));
        object.set("valid_until", text(self.valid_until.as_str()));
        object.set("authority_key_id", text(&self.authority_key_id.to_hex()));
        if include_signature {
            object.set(
                "authority_signature",
                text(&self.authority_signature.to_hex()),
            );
        }
        object
    }
}

/// The authoritative immutable control-prefix public record for a receipt
/// key.  It is retained across rotations and is never overwritten by this
/// module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptKeyRecord {
    tenant_id: TenantId,
    key_id: KeyId,
    public_key: Ed25519PublicKey,
    valid_from: Timestamp,
    valid_until: Timestamp,
    signed_at: Timestamp,
    authority_key_id: KeyId,
    authority_signature: Ed25519Signature,
}

impl ReceiptKeyRecord {
    /// Parse and validate one complete `archivist.control/v1` receipt-key
    /// record.
    ///
    /// # Errors
    /// [`ReceiptKeyError::MalformedRecord`] when the closed record shape or
    /// any member grammar is invalid.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReceiptKeyError> {
        let value =
            archivist_protocol::json::parse(bytes).map_err(|_| ReceiptKeyError::MalformedRecord)?;
        let Value::Object(object) = value else {
            return Err(ReceiptKeyError::MalformedRecord);
        };
        if object.len() != CONTROL_MEMBERS.len()
            || CONTROL_MEMBERS
                .iter()
                .any(|member| object.get(member).is_none())
        {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        if text_member(&object, "schema") != Some(CONTROL_NAMESPACE)
            || text_member(&object, "record_type") != Some(CONTROL_RECORD_TYPE)
            || text_member(&object, "record_kind") != Some(CONTROL_RECORD_KIND)
            || text_member(&object, "key_algorithm") != Some(ALGORITHM.token())
        {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        let public_key = parse_public_key(&object, "public_key")?;
        let key_id = parse_key_id(&object, "key_id")?;
        if key_id != KeyId::from_public_key(&public_key) {
            return Err(ReceiptKeyError::KeyDerivation);
        }
        let valid_from = parse_timestamp(&object, "valid_from")?;
        let valid_until = parse_timestamp(&object, "valid_until")?;
        let signed_at = parse_timestamp(&object, "signed_at")?;
        validate_window(&valid_from, &valid_until)?;
        if timestamp_cmp(&signed_at, &valid_from).is_gt() {
            return Err(ReceiptKeyError::InvalidWindow);
        }
        let authority_key_id = parse_key_id(&object, "authority_key_id")?;
        let authority_signature = parse_signature(&object, "authority_signature")?;
        Ok(Self {
            tenant_id,
            key_id,
            public_key,
            valid_from,
            valid_until,
            signed_at,
            authority_key_id,
            authority_signature,
        })
    }

    /// The tenant this public record serves.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The receipt key ID named by this record.
    #[must_use]
    pub const fn key_id(&self) -> &KeyId {
        &self.key_id
    }

    /// The certified public half.
    #[must_use]
    pub const fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// When this public key starts signing.
    #[must_use]
    pub const fn valid_from(&self) -> &Timestamp {
        &self.valid_from
    }

    /// When this public key stops signing.  This does not expire receipt
    /// verification for receipts already signed inside the window.
    #[must_use]
    pub const fn valid_until(&self) -> &Timestamp {
        &self.valid_until
    }

    /// The authority certification instant.
    #[must_use]
    pub const fn signed_at(&self) -> &Timestamp {
        &self.signed_at
    }

    /// The control record's authority signer.
    #[must_use]
    pub const fn authority_key_id(&self) -> &KeyId {
        &self.authority_key_id
    }

    /// The server-derived immutable control object key.
    #[must_use]
    pub fn object_key(&self) -> String {
        format!(
            "tenants/{}/v1/control/receipt-keys/{}.json",
            self.tenant_id, self.key_id
        )
    }

    /// The canonical control-record bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Value::Object(self.record_object(true)).canonical_bytes()
    }

    /// The control-record-v1 bytes covered by the authority signature.
    #[must_use]
    pub fn unsigned_canonical_bytes(&self) -> Vec<u8> {
        Value::Object(self.record_object(false)).canonical_bytes()
    }

    /// Verify this control record against a pinned authority chain.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when the tenant, authority chain, or
    /// control-record signature fails verification.
    pub fn verify(
        &self,
        root: &PinnedAuthorityRoot,
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<ResolvedAuthority, ReceiptKeyError> {
        if self.tenant_id != *root.tenant_id() {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        let resolved = crate::authority::verify_signing_authority(
            root,
            &self.authority_key_id,
            &self.signed_at,
            fetch,
        )?;
        let signature = ed25519::Signature::from_bytes(*self.authority_signature.as_raw());
        if !ed25519::verify(
            resolved.public_key().as_raw(),
            &self.unsigned_canonical_bytes(),
            &signature,
        ) {
            return Err(ReceiptKeyError::Signature);
        }
        Ok(resolved)
    }

    fn record_object(&self, include_signature: bool) -> Object {
        let mut object = Object::new();
        object.set("schema", text(CONTROL_NAMESPACE));
        object.set("record_type", text(CONTROL_RECORD_TYPE));
        object.set("record_kind", text(CONTROL_RECORD_KIND));
        object.set("tenant_id", text(self.tenant_id.as_str()));
        object.set("key_id", text(&self.key_id.to_hex()));
        object.set("key_algorithm", text(ALGORITHM.token()));
        object.set("public_key", text(&self.public_key.to_hex()));
        object.set("valid_from", text(self.valid_from.as_str()));
        object.set("valid_until", text(self.valid_until.as_str()));
        object.set("signed_at", text(self.signed_at.as_str()));
        object.set("authority_key_id", text(&self.authority_key_id.to_hex()));
        if include_signature {
            object.set(
                "authority_signature",
                text(&self.authority_signature.to_hex()),
            );
        }
        object
    }
}

/// A receipt key with its private signing half and its two public,
/// authority-certified projections.
pub struct CertifiedReceiptKey {
    signing_key: ReceiptSigningKey,
    certificate: ReceiptKeyCertificate,
    record: ReceiptKeyRecord,
}

/// A concise alias for the certified receipt-key bundle.
pub type ReceiptKey = CertifiedReceiptKey;

impl fmt::Debug for CertifiedReceiptKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertifiedReceiptKey")
            .field("tenant_id", &self.tenant_id())
            .field("key_id", &self.key_id())
            .field("certificate", &self.certificate)
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

impl CertifiedReceiptKey {
    /// Load a receipt private key through a protected reference and certify
    /// its public half with the tenant authority.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when either secret reference cannot be
    /// resolved or the tenant/window relationship is invalid.
    pub fn from_secret_reference(
        tenant_id: TenantId,
        receipt_reference: &ProtectedReference,
        authority: &AuthoritySigner,
        signed_at: Timestamp,
        valid_from: Timestamp,
    ) -> Result<Self, ReceiptKeyError> {
        let signing_key = ReceiptSigningKey::from_secret_reference(tenant_id, receipt_reference)?;
        Self::certify(signing_key, authority, signed_at, valid_from)
    }

    /// Certify a key that was loaded through [`ReceiptSigningKey`] with the
    /// tenant authority, producing both retained public records.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError::TenantMismatch`] or
    /// [`ReceiptKeyError::InvalidWindow`] when certification inputs disagree.
    pub fn certify(
        signing_key: ReceiptSigningKey,
        authority: &AuthoritySigner,
        signed_at: Timestamp,
        valid_from: Timestamp,
    ) -> Result<Self, ReceiptKeyError> {
        if signing_key.tenant_id != authority.tenant_id {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        let valid_until = add_days(&valid_from, RECEIPT_KEY_VALIDITY_DAYS)?;
        if !signed_at.calendar_valid()
            || !valid_from.calendar_valid()
            || timestamp_cmp(&signed_at, &valid_from).is_gt()
        {
            return Err(ReceiptKeyError::InvalidWindow);
        }
        let key_id = signing_key.key_id();
        let public_key = signing_key.public_key();
        let authority_key_id = authority.key_id();

        let mut certificate = ReceiptKeyCertificate {
            tenant_id: signing_key.tenant_id.clone(),
            key_id,
            public_key,
            valid_from: valid_from.clone(),
            valid_until: valid_until.clone(),
            authority_key_id,
            authority_signature: Ed25519Signature::from_raw([0; 64]),
        };
        certificate.authority_signature = authority.sign(&certificate.unsigned_canonical_bytes());

        let mut record = ReceiptKeyRecord {
            tenant_id: signing_key.tenant_id.clone(),
            key_id,
            public_key,
            valid_from,
            valid_until,
            signed_at,
            authority_key_id,
            authority_signature: Ed25519Signature::from_raw([0; 64]),
        };
        record.authority_signature = authority.sign(&record.unsigned_canonical_bytes());

        Ok(Self {
            signing_key,
            certificate,
            record,
        })
    }

    /// The tenant scope.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        self.signing_key.tenant_id()
    }

    /// The public key ID.
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.signing_key.key_id()
    }

    /// The embedded public certificate.
    #[must_use]
    pub const fn certificate(&self) -> &ReceiptKeyCertificate {
        &self.certificate
    }

    /// The retained public control record.
    #[must_use]
    pub const fn record(&self) -> &ReceiptKeyRecord {
        &self.record
    }

    /// Sign one receipt object, selecting this key's certificate by value.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when the receipt has a protected field,
    /// wrong tenant, invalid commit time, or an out-of-window commit.
    pub fn sign_receipt(&self, object: Object) -> Result<Receipt, ReceiptKeyError> {
        Receipt::sign(object, self)
    }
}

/// A retained collection of receipt keys.  Old public records remain in the
/// map after rotation, while signing chooses the newest valid key at the
/// receipt's commit instant.
pub struct ReceiptKeySchedule {
    tenant_id: TenantId,
    keys: BTreeMap<KeyId, CertifiedReceiptKey>,
}

impl fmt::Debug for ReceiptKeySchedule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiptKeySchedule")
            .field("tenant_id", &self.tenant_id)
            .field("retained_key_count", &self.keys.len())
            .finish()
    }
}

impl ReceiptKeySchedule {
    /// Start a schedule with the first certified key.
    #[must_use]
    pub fn new(initial: CertifiedReceiptKey) -> Self {
        let tenant_id = initial.tenant_id().clone();
        let key_id = initial.key_id();
        let mut keys = BTreeMap::new();
        keys.insert(key_id, initial);
        Self { tenant_id, keys }
    }

    /// Add the next certified key.  Its start must be exactly 30 days after
    /// the latest retained start, and the old key is retained for the seven-
    /// day signing overlap rather than removed.
    ///
    /// # Errors
    /// [`ReceiptKeyError::RotationCadence`] when the next key is not exactly
    /// the next 30-day slot; tenant and duplicate conflicts are rejected too.
    pub fn rotate(&mut self, next: CertifiedReceiptKey) -> Result<(), ReceiptKeyError> {
        if next.tenant_id() != &self.tenant_id {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        if self.keys.contains_key(&next.key_id()) {
            return Err(ReceiptKeyError::ConflictingRecord);
        }
        let latest = self
            .keys
            .values()
            .max_by(|left, right| {
                timestamp_cmp(
                    left.certificate().valid_from(),
                    right.certificate().valid_from(),
                )
            })
            .ok_or(ReceiptKeyError::RotationCadence)?;
        let expected = add_days(latest.certificate().valid_from(), RECEIPT_KEY_ROTATION_DAYS)?;
        if timestamp_cmp(next.certificate().valid_from(), &expected) != std::cmp::Ordering::Equal {
            return Err(ReceiptKeyError::RotationCadence);
        }
        self.keys.insert(next.key_id(), next);
        Ok(())
    }

    /// The number of retained private/public key bundles.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the schedule has no retained keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Return every retained public control record in signing-window order.
    /// No deletion operation exists, so old certificates remain available
    /// for receipts issued before rotation.
    #[must_use]
    pub fn retained_public_records(&self) -> Vec<ReceiptKeyRecord> {
        let mut records: Vec<_> = self.keys.values().map(|key| key.record.clone()).collect();
        records.sort_by(|left, right| timestamp_cmp(left.valid_from(), right.valid_from()));
        records
    }

    /// Choose the newest retained key whose signing window contains `at`.
    #[must_use]
    pub fn signing_key_at(&self, at: &Timestamp) -> Option<&CertifiedReceiptKey> {
        self.keys
            .values()
            .filter(|key| {
                timestamp_cmp(key.certificate().valid_from(), at).is_le()
                    && timestamp_cmp(at, key.certificate().valid_until()).is_le()
            })
            .max_by(|left, right| {
                timestamp_cmp(
                    left.certificate().valid_from(),
                    right.certificate().valid_from(),
                )
            })
    }

    /// Sign a receipt using the newest key valid at its `commit_time` field.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError::OutsideSigningWindow`] when no retained key
    /// can sign at the receipt's commit instant, or another signing error.
    pub fn sign_receipt(&self, object: Object) -> Result<Receipt, ReceiptKeyError> {
        let commit_time = parse_timestamp(&object, "commit_time")?;
        let key = self
            .signing_key_at(&commit_time)
            .ok_or(ReceiptKeyError::OutsideSigningWindow)?;
        key.sign_receipt(object)
    }
}

/// A signed receipt with its embedded public certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    value: Value,
}

impl Receipt {
    /// Sign an object after adding the receipt version, algorithm, key ID, and
    /// embedded certificate.  The caller must provide `tenant_id` and
    /// `commit_time`; both are identity-bearing and therefore cannot be
    /// silently invented by the signer.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when caller-controlled identity fields are
    /// missing or signer-controlled fields were supplied.
    pub fn sign(mut object: Object, key: &CertifiedReceiptKey) -> Result<Self, ReceiptKeyError> {
        if RECEIPT_PROTECTED_MEMBERS
            .iter()
            .any(|member| object.contains(member))
        {
            return Err(ReceiptKeyError::ProtectedField);
        }
        let tenant_id = parse_tenant(&object, "tenant_id")?;
        if tenant_id != *key.tenant_id() {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        let commit_time = parse_timestamp(&object, "commit_time")?;
        if timestamp_cmp(&commit_time, key.certificate().valid_from()).is_lt()
            || timestamp_cmp(&commit_time, key.certificate().valid_until()).is_gt()
        {
            return Err(ReceiptKeyError::OutsideSigningWindow);
        }
        object.set("receipt_version", Value::Int(RECEIPT_VERSION));
        object.set("receipt_key_id", text(&key.key_id().to_hex()));
        object.set("certificate", certificate_value(key.certificate()));
        object.set("signature_algorithm", text(ALGORITHM.token()));
        let signature = key
            .signing_key
            .sign(&Value::Object(object.clone()).canonical_bytes());
        object.set("signature", text(&signature.to_hex()));
        Ok(Self {
            value: Value::Object(object),
        })
    }

    /// Parse a receipt without trusting its signature.  Call [`Self::verify`]
    /// before treating it as an acknowledgement.
    ///
    /// # Errors
    /// [`ReceiptKeyError::MalformedRecord`] when the bytes are not a JSON
    /// object in the protocol value domain.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReceiptKeyError> {
        let value =
            archivist_protocol::json::parse(bytes).map_err(|_| ReceiptKeyError::MalformedRecord)?;
        if !matches!(value, Value::Object(_)) {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        Ok(Self { value })
    }

    /// The canonical receipt bytes, including the receipt signature.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.value.canonical_bytes()
    }

    /// Verify the embedded certificate and receipt signature from a pinned
    /// tenant authority root.  The closure supplies retained authority
    /// rotation links by predecessor key ID; no current server state is
    /// required.
    ///
    /// # Errors
    /// Returns [`ReceiptKeyError`] when the embedded certificate, authority
    /// chain, signing window, or receipt signature fails closed.
    pub fn verify(
        &self,
        root: &PinnedAuthorityRoot,
        fetch: impl FnMut(&KeyId) -> Option<Vec<u8>>,
    ) -> Result<VerifiedReceipt, ReceiptKeyError> {
        let Value::Object(object) = &self.value else {
            return Err(ReceiptKeyError::MalformedRecord);
        };
        if int_member(object, "receipt_version") != Some(RECEIPT_VERSION)
            || text_member(object, "signature_algorithm") != Some(ALGORITHM.token())
        {
            return Err(ReceiptKeyError::MalformedRecord);
        }
        let tenant_id = parse_tenant(object, "tenant_id")?;
        let commit_time = parse_timestamp(object, "commit_time")?;
        let receipt_key_id = parse_key_id(object, "receipt_key_id")?;
        let certificate_value = object
            .get("certificate")
            .ok_or(ReceiptKeyError::MalformedRecord)?;
        let certificate = ReceiptKeyCertificate::parse(certificate_value)?;
        if certificate.tenant_id != tenant_id || certificate.key_id != receipt_key_id {
            return Err(ReceiptKeyError::TenantMismatch);
        }
        if timestamp_cmp(&commit_time, &certificate.valid_from).is_lt()
            || timestamp_cmp(&commit_time, &certificate.valid_until).is_gt()
        {
            return Err(ReceiptKeyError::OutsideSigningWindow);
        }
        certificate.verify(root, fetch)?;
        let signature = parse_signature(object, "signature")?;
        let mut unsigned = object.clone();
        let _ = unsigned.remove("signature");
        let signature = ed25519::Signature::from_bytes(*signature.as_raw());
        if !ed25519::verify(
            certificate.public_key.as_raw(),
            &Value::Object(unsigned).canonical_bytes(),
            &signature,
        ) {
            return Err(ReceiptKeyError::Signature);
        }
        Ok(VerifiedReceipt {
            tenant_id,
            receipt_key_id,
            commit_time,
            certificate,
        })
    }
}

/// The authenticated facts a client may use after verifying a receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedReceipt {
    tenant_id: TenantId,
    receipt_key_id: KeyId,
    commit_time: Timestamp,
    certificate: ReceiptKeyCertificate,
}

impl VerifiedReceipt {
    /// The receipt tenant.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The key that signed the receipt.
    #[must_use]
    pub const fn receipt_key_id(&self) -> &KeyId {
        &self.receipt_key_id
    }

    /// The commit instant covered by the receipt.
    #[must_use]
    pub const fn commit_time(&self) -> &Timestamp {
        &self.commit_time
    }

    /// The retained public certificate authenticated by the tenant root.
    #[must_use]
    pub const fn certificate(&self) -> &ReceiptKeyCertificate {
        &self.certificate
    }
}

fn certificate_value(certificate: &ReceiptKeyCertificate) -> Value {
    Value::Object(certificate.certificate_object(true))
}

fn decode_seed(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        return bytes.try_into().ok();
    }
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut seed = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        seed[index] = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(seed)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn text_member<'a>(object: &'a Object, name: &str) -> Option<&'a str> {
    match object.get(name) {
        Some(Value::Text(value)) => Some(value),
        _ => None,
    }
}

fn int_member(object: &Object, name: &str) -> Option<i64> {
    match object.get(name) {
        Some(Value::Int(value)) => Some(*value),
        _ => None,
    }
}

fn parse_tenant(object: &Object, name: &str) -> Result<TenantId, ReceiptKeyError> {
    TenantId::parse(text_member(object, name).ok_or(ReceiptKeyError::MalformedRecord)?)
        .map_err(|_| ReceiptKeyError::MalformedRecord)
}

fn parse_key_id(object: &Object, name: &str) -> Result<KeyId, ReceiptKeyError> {
    KeyId::parse(text_member(object, name).ok_or(ReceiptKeyError::MalformedRecord)?)
        .map_err(|_| ReceiptKeyError::MalformedRecord)
}

fn parse_public_key(object: &Object, name: &str) -> Result<Ed25519PublicKey, ReceiptKeyError> {
    Ed25519PublicKey::parse(text_member(object, name).ok_or(ReceiptKeyError::MalformedRecord)?)
        .map_err(|_| ReceiptKeyError::MalformedRecord)
}

fn parse_timestamp(object: &Object, name: &str) -> Result<Timestamp, ReceiptKeyError> {
    let timestamp =
        Timestamp::parse(text_member(object, name).ok_or(ReceiptKeyError::MalformedRecord)?)
            .map_err(|_| ReceiptKeyError::MalformedRecord)?;
    if timestamp.calendar_valid() {
        Ok(timestamp)
    } else {
        Err(ReceiptKeyError::MalformedRecord)
    }
}

fn parse_signature(object: &Object, name: &str) -> Result<Ed25519Signature, ReceiptKeyError> {
    Ed25519Signature::parse(text_member(object, name).ok_or(ReceiptKeyError::MalformedRecord)?)
        .map_err(|_| ReceiptKeyError::MalformedRecord)
}

fn validate_window(valid_from: &Timestamp, valid_until: &Timestamp) -> Result<(), ReceiptKeyError> {
    if timestamp_cmp(valid_from, valid_until).is_gt()
        || timestamp_cmp(
            &add_days(valid_from, RECEIPT_KEY_VALIDITY_DAYS)?,
            valid_until,
        ) != std::cmp::Ordering::Equal
    {
        return Err(ReceiptKeyError::InvalidWindow);
    }
    Ok(())
}

fn timestamp_cmp(left: &Timestamp, right: &Timestamp) -> std::cmp::Ordering {
    instant(left).cmp(&instant(right))
}

fn instant(timestamp: &Timestamp) -> (i64, u32) {
    let bytes = timestamp.as_str().as_bytes();
    let number = |slice: &[u8]| {
        slice
            .iter()
            .fold(0i64, |acc, byte| acc * 10 + i64::from(byte - b'0'))
    };
    let year = number(&bytes[..4]);
    let month = number(&bytes[5..7]);
    let day = number(&bytes[8..10]);
    let hour = number(&bytes[11..13]);
    let minute = number(&bytes[14..16]);
    let second = number(&bytes[17..19]);
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second;
    let nanoseconds = if bytes.len() > 20 {
        let digits = &bytes[20..bytes.len() - 1];
        let mut value = 0u32;
        for digit in digits {
            value = value * 10 + u32::from(digit - b'0');
        }
        for _ in digits.len()..9 {
            value *= 10;
        }
        value
    } else {
        0
    };
    (seconds, nanoseconds)
}

fn add_days(timestamp: &Timestamp, days: i64) -> Result<Timestamp, ReceiptKeyError> {
    let (seconds, nanoseconds) = instant(timestamp);
    let seconds = seconds
        .checked_add(
            days.checked_mul(86_400)
                .ok_or(ReceiptKeyError::InvalidWindow)?,
        )
        .ok_or(ReceiptKeyError::InvalidWindow)?;
    let day = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let (year, month, date) = civil_from_days(day);
    if !(0..=9999).contains(&year) {
        return Err(ReceiptKeyError::InvalidWindow);
    }
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let value = if nanoseconds == 0 {
        format!("{year:04}-{month:02}-{date:02}T{hour:02}:{minute:02}:{second:02}Z")
    } else {
        format!(
            "{year:04}-{month:02}-{date:02}T{hour:02}:{minute:02}:{second:02}.{nanoseconds:09}Z"
        )
    };
    Timestamp::parse(&value).map_err(|_| ReceiptKeyError::InvalidWindow)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_offset = if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * (month + month_offset) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use archivist_protocol::json::Object;

    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).expect("tenant")
    }

    fn secret(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn authority(seed: u8) -> AuthoritySigner {
        AuthoritySigner {
            tenant_id: tenant(),
            signing_key: SigningKey::from_seed(secret(seed)),
        }
    }

    fn receipt_key(seed: u8) -> ReceiptSigningKey {
        ReceiptSigningKey {
            tenant_id: tenant(),
            signing_key: SigningKey::from_seed(secret(seed)),
        }
    }

    fn certified_by(
        seed: u8,
        authority_seed: u8,
        signed_at: &str,
        valid_from: &str,
    ) -> CertifiedReceiptKey {
        CertifiedReceiptKey::certify(
            receipt_key(seed),
            &authority(authority_seed),
            Timestamp::parse(signed_at).expect("signed_at"),
            Timestamp::parse(valid_from).expect("valid_from"),
        )
        .expect("certificate")
    }

    fn certified(seed: u8, signed_at: &str, valid_from: &str) -> CertifiedReceiptKey {
        certified_by(seed, 1, signed_at, valid_from)
    }

    fn receipt_object(commit_time: &str) -> Object {
        let mut object = Object::new();
        object.set("tenant_id", text(TENANT));
        object.set("commit_time", text(commit_time));
        object.set("request_id", text("018f0b65-7c15-7e7a-8c01-9e3f2bc6d6d8"));
        object
    }

    #[test]
    fn schedule_rotates_every_thirty_days_and_retains_the_old_record() {
        let first = certified(2, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        let second = certified(3, "2026-01-31T00:00:00Z", "2026-01-31T00:00:00Z");
        let mut schedule = ReceiptKeySchedule::new(first);
        schedule.rotate(second).expect("exact cadence");
        assert_eq!(schedule.len(), 2);
        assert_eq!(schedule.retained_public_records().len(), 2);
        assert_eq!(
            schedule
                .signing_key_at(&Timestamp::parse("2026-01-30T23:59:59Z").unwrap())
                .unwrap()
                .key_id(),
            schedule.retained_public_records()[0].key_id().to_owned()
        );
        assert_eq!(
            schedule
                .signing_key_at(&Timestamp::parse("2026-02-01T00:00:00Z").unwrap())
                .unwrap()
                .key_id(),
            schedule.retained_public_records()[1].key_id().to_owned()
        );
    }

    #[test]
    fn receipt_verifies_offline_after_rotation_and_rejects_tampering() {
        let first = certified(2, "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z");
        let second = certified(3, "2026-01-31T00:00:00Z", "2026-01-31T00:00:00Z");
        let first_id = first.key_id();
        let second_id = second.key_id();
        let mut schedule = ReceiptKeySchedule::new(first);
        schedule.rotate(second).expect("rotation");
        let old_receipt = schedule
            .sign_receipt(receipt_object("2026-01-30T23:59:59Z"))
            .expect("old-window receipt");
        let receipt = schedule
            .sign_receipt(receipt_object("2026-02-01T00:00:00Z"))
            .expect("new-window receipt");
        let root_public = Ed25519PublicKey::from_raw(authority(1).signing_key.public_key());
        let root = PinnedAuthorityRoot::new(tenant(), root_public);
        let verified_old = old_receipt
            .verify(&root, |_| None)
            .expect("old offline verify");
        assert_eq!(*verified_old.receipt_key_id(), first_id);
        let verified = receipt.verify(&root, |_| None).expect("new offline verify");
        assert_eq!(*verified.receipt_key_id(), second_id);

        let mut tampered = receipt.canonical_bytes();
        let marker = b"2026-02-01T00:00:00Z";
        let position = tampered
            .windows(marker.len())
            .position(|window| window == marker)
            .expect("commit marker");
        tampered[position + 9] = b'3';
        let tampered = Receipt::parse(&tampered).expect("still JSON");
        assert_eq!(
            tampered.verify(&root, |_| None),
            Err(ReceiptKeyError::Signature)
        );
    }

    #[test]
    fn receipt_certificate_walks_a_rotated_tenant_authority_offline() {
        let previous = authority(1);
        let successor = authority(2);
        let previous_public = Ed25519PublicKey::from_raw(previous.signing_key.public_key());
        let successor_public = Ed25519PublicKey::from_raw(successor.signing_key.public_key());
        let previous_key_id = KeyId::from_public_key(&previous_public);
        let mut link = Object::new();
        link.set("schema", text(CONTROL_NAMESPACE));
        link.set("record_type", text("authority-rotation"));
        link.set("record_kind", text("immutable"));
        link.set("tenant_id", text(TENANT));
        link.set("previous_public_key", text(&previous_public.to_hex()));
        link.set("previous_key_id", text(&previous_key_id.to_hex()));
        link.set("key_algorithm", text(ALGORITHM.token()));
        link.set("public_key", text(&successor_public.to_hex()));
        link.set(
            "key_id",
            text(&KeyId::from_public_key(&successor_public).to_hex()),
        );
        link.set("signed_at", text("2026-01-15T00:00:00Z"));
        link.set("authority_key_id", text(&previous_key_id.to_hex()));
        let signature = previous.sign(&Value::Object(link.clone()).canonical_bytes());
        link.set("authority_signature", text(&signature.to_hex()));
        let link_bytes = Value::Object(link).canonical_bytes();

        let key = certified_by(3, 2, "2026-01-20T00:00:00Z", "2026-01-20T00:00:00Z");
        let receipt = key
            .sign_receipt(receipt_object("2026-01-21T00:00:00Z"))
            .expect("receipt");
        let root = PinnedAuthorityRoot::new(tenant(), previous_public);
        let verified = receipt
            .verify(&root, |key_id| {
                (*key_id == previous_key_id).then(|| link_bytes.clone())
            })
            .expect("successor certificate verifies from the pinned root");
        assert_eq!(
            *verified.certificate().authority_key_id(),
            successor.key_id()
        );
    }

    #[test]
    fn secret_loader_accepts_a_protected_hex_reference_without_exposing_the_seed() {
        let path = std::env::temp_dir().join(format!(
            "archivist-receipt-secret-{}-{}.key",
            std::process::id(),
            2
        ));
        std::fs::write(
            &path,
            b"0101010101010101010101010101010101010101010101010101010101010101",
        )
        .expect("secret file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("secret mode");
        }
        let reference =
            ProtectedReference::parse(&format!("file:{}", path.display())).expect("reference");
        let loaded = ReceiptSigningKey::from_secret_reference(tenant(), &reference)
            .expect("load through reference");
        assert_eq!(format!("{loaded:?}"), "ReceiptSigningKey(<redacted>)");
        let _ = std::fs::remove_file(path);
    }
}
