// SPDX-License-Identifier: Apache-2.0

//! The installation identity: a client-generated `UUIDv4` client ID bound to
//! an Ed25519 signing key, generated locally, persisted at a restrictive
//! mode, and discovered only through a protected reference.
//!
//! Plan Section 7.4 fixes the client ID as an installation-generated `UUIDv4`;
//! ID-001 and SEC-006 fix the private half to the host that generated it.
//! This module is that host side: [`InstallationIdentity::generate`] mints
//! both halves from the OS entropy source, [`InstallationIdentity::write_new`]
//! persists the identity at mode `0600` (refusing to overwrite), and
//! [`InstallationIdentity::discover`] loads it back through a
//! [`ProtectedReference`] — never a
//! literal value — re-deriving and re-checking every invariant before the
//! identity is usable.
//!
//! The link-request half of the surface — the one document an installation
//! sends anywhere — lives in [`crate::link`] and is constructible only from
//! an identity's [`PublicIdentity`].

use std::fmt;

use archivist_protocol::vocabulary::{ClientId, Ed25519PublicKey, KeyId};

use crate::ed25519;
use crate::error::IdentityError;
use crate::random;
use crate::reference::ProtectedReference;

/// The local identity document's namespace token. Local state, never a wire
/// value: it travels no further than the host's own identity file.
const IDENTITY_SCHEMA: &str = "archivist.client-identity/v1";

/// An Ed25519 signing key: the 32-byte RFC 8032 seed and the public half
/// derived from it.
///
/// The seed is the installation's private half. This type renders as
/// `SigningKey(<redacted>)` in [`Debug`] — derive would print the seed, so
/// it is manual, and that redaction is pinned by a test. The seed enters
/// and leaves this type only through generation from OS entropy, a
/// protected-reference discovery, or the byte-exact local document.
pub struct SigningKey {
    seed: [u8; 32],
    public: [u8; 32],
}

impl SigningKey {
    /// Generate a signing key from the OS entropy source.
    ///
    /// # Errors
    /// [`IdentityError::Entropy`] when the entropy source is unavailable;
    /// there is no weaker fallback.
    pub fn generate() -> Result<Self, IdentityError> {
        let mut seed = [0u8; 32];
        random::fill_random(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    /// Adopt `seed` (the RFC 8032 private half) and derive the public half.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            seed,
            public: ed25519::public_key_from_seed(&seed),
        }
    }

    /// The 32-byte encoded public half.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// The 32-byte private seed. Callers sign with this; nothing serializes
    /// it except the mode-restricted local identity document.
    #[must_use]
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign `message` with this key (RFC 8032 §5.1.6). The signature is
    /// deterministic — it is a pure function of the seed and the message —
    /// and verifies against [`Self::public_key`].
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> ed25519::Signature {
        ed25519::sign(&self.seed, message)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

/// The public identity of an installation: exactly the members a link
/// request or any public surface may carry (SEC-006 — public halves only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    /// The installation-generated client ID.
    pub client_id: ClientId,
    /// The signing algorithm, pinned to Ed25519 in v1.
    pub algorithm: archivist_protocol::vocabulary::SignatureAlgorithm,
    /// The encoded Ed25519 public half.
    pub public_key: Ed25519PublicKey,
    /// `SHA-256` of the encoded public half — computable from
    /// [`Self::public_key`], re-checked on every discovery.
    pub key_id: KeyId,
}

impl PublicIdentity {
    /// Re-derive the key ID from the public key and fail unless they agree.
    ///
    /// The constructor for anything read back from disk; a mismatching pair
    /// is corrupt material, not a usable identity.
    fn from_parts(
        client_id: ClientId,
        algorithm: archivist_protocol::vocabulary::SignatureAlgorithm,
        public_key: Ed25519PublicKey,
        key_id: KeyId,
    ) -> Result<Self, IdentityError> {
        if key_id != KeyId::from_public_key(&public_key) {
            return Err(IdentityError::IdentityCorrupt);
        }
        Ok(Self {
            client_id,
            algorithm,
            public_key,
            key_id,
        })
    }
}

/// An installation's identity: the client ID and the signing key, generated
/// on this host, persisted only in the mode-restricted local document.
pub struct InstallationIdentity {
    client_id: ClientId,
    signing_key: SigningKey,
}

impl fmt::Debug for InstallationIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InstallationIdentity")
            .field("client_id", &self.client_id.as_str())
            .field("key_id", &self.public_identity().key_id.to_hex())
            .finish_non_exhaustive()
    }
}

impl InstallationIdentity {
    /// Mint a fresh identity: a `UUIDv4` client ID and an Ed25519 signing
    /// key, both from the OS entropy source (plan Section 7.4, ID-001).
    ///
    /// # Errors
    /// [`IdentityError::Entropy`] when the entropy source is unavailable.
    pub fn generate() -> Result<Self, IdentityError> {
        // One draw covers both: 16 bytes for the client ID, 32 for the seed.
        let mut bytes = [0u8; 48];
        random::fill_random(&mut bytes)?;

        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&bytes[..16]);
        uuid[6] = (uuid[6] & 0x0f) | 0x40; // version 4
        uuid[8] = (uuid[8] & 0x3f) | 0x80; // RFC 4122 variant
        let uuid_text = format_uuid(&uuid);
        let client_id =
            ClientId::parse(&uuid_text).map_err(|_grammar_error| IdentityError::IdentityCorrupt)?;

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[16..]);
        Ok(Self {
            client_id,
            signing_key: SigningKey::from_seed(seed),
        })
    }

    /// Assemble an identity from known parts — the reconstruction path a
    /// restore uses, and the deterministic path the tests pin.
    ///
    /// # Errors
    /// [`IdentityError::IdentityCorrupt`] when the seed does not derive the
    /// given public key.
    pub fn from_seed(
        client_id: ClientId,
        seed: [u8; 32],
        public_key: Ed25519PublicKey,
    ) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_seed(seed);
        if signing_key.public_key() != *public_key.as_raw() {
            return Err(IdentityError::IdentityCorrupt);
        }
        Ok(Self {
            client_id,
            signing_key,
        })
    }

    /// The installation's client ID.
    #[must_use]
    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    /// The signing key. Private material stays inside this process.
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// The public identity — everything any external surface may see.
    #[must_use]
    pub fn public_identity(&self) -> PublicIdentity {
        let public_key = Ed25519PublicKey::from_raw(self.signing_key.public_key());
        PublicIdentity {
            client_id: self.client_id.clone(),
            algorithm: archivist_protocol::vocabulary::SignatureAlgorithm::Ed25519,
            public_key,
            key_id: KeyId::from_public_key(&public_key),
        }
    }

    /// Persist a freshly generated identity to `path`, creating the file at
    /// mode `0600` and refusing to overwrite (an installation identity is
    /// minted once; a silent re-mint would orphan the linked record).
    ///
    /// The parent directory carries the same posture as the client state
    /// and spool directories (CFG-023): it is created at mode `0700` when
    /// absent — pinned explicitly so a permissive process umask cannot
    /// widen it — and refused when it pre-exists at any other mode, so
    /// neither the document nor its directory is ever left loose.
    ///
    /// # Errors
    /// [`IdentityError::IdentityExists`] when the target exists,
    /// [`IdentityError::ReferenceUnsafe`] when the created file's mode is
    /// looser than `0600` (a permissive umask) or the parent directory
    /// cannot be created or found at mode `0700`, and
    /// [`IdentityError::ReferenceUnreadable`] when the write or durability
    /// sync fails. The path is not echoed in any error.
    #[cfg(unix)]
    pub fn write_new(&self, path: &std::path::Path) -> Result<(), IdentityError> {
        use std::fs::OpenOptions;
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        prepare_parent_directory(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => IdentityError::IdentityExists,
                std::io::ErrorKind::NotFound => IdentityError::ReferenceMissing,
                _ => IdentityError::ReferenceUnreadable,
            })?;
        file.write_all(&self.canonical_document())
            .and_then(|()| file.sync_all())
            .map_err(|_io_error| IdentityError::ReferenceUnreadable)?;
        // The mode request can be loosened by the process umask on some
        // platforms; verify the created file by property (CFG-030).
        let metadata = file
            .metadata()
            .map_err(|_io_error| IdentityError::ReferenceUnreadable)?;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::ReferenceUnsafe);
        }
        Ok(())
    }

    /// Discover the installation identity through a protected reference.
    ///
    /// The reference is resolved with its own safety checks (a `file:`
    /// target must be a regular file at mode `0600` or stricter; CFG-030),
    /// the document is parsed as the closed local identity shape, and every
    /// invariant is re-derived before the identity is returned: the key ID
    /// must match the public key, and the seed must derive it. A document
    /// whose members disagree is corrupt, not usable.
    ///
    /// # Errors
    /// Reference resolution failures
    /// ([`IdentityError::ReferenceMissing`], `ReferenceUnsafe`,
    /// `ReferenceUnreadable`, `ReferenceUnsupportedPlatform`) and
    /// [`IdentityError::IdentityCorrupt`] for any malformed or
    /// self-inconsistent document. No error echoes the path or any value.
    pub fn discover(reference: &ProtectedReference) -> Result<Self, IdentityError> {
        let bytes = reference.resolve()?;
        let document = archivist_protocol::json::parse(&bytes)
            .map_err(|_parse_error| IdentityError::IdentityCorrupt)?;
        let archivist_protocol::json::Value::Object(members) = document else {
            return Err(IdentityError::IdentityCorrupt);
        };
        // Closed shape: a member outside the six is not this document.
        let mut names: Vec<&str> = members.iter().map(|(name, _value)| name).collect();
        names.sort_unstable();
        if names
            != [
                "client_id",
                "key_algorithm",
                "key_id",
                "private_seed",
                "public_key",
                "schema",
            ]
        {
            return Err(IdentityError::IdentityCorrupt);
        }

        let schema = text_member(&members, "schema")?;
        if schema != IDENTITY_SCHEMA {
            return Err(IdentityError::IdentityCorrupt);
        }
        let client_id = ClientId::parse(text_member(&members, "client_id")?)
            .map_err(|_grammar_error| IdentityError::IdentityCorrupt)?;
        let algorithm = archivist_protocol::vocabulary::SignatureAlgorithm::parse(text_member(
            &members,
            "key_algorithm",
        )?)
        .map_err(|_grammar_error| IdentityError::IdentityCorrupt)?;
        let public_key = Ed25519PublicKey::parse(text_member(&members, "public_key")?)
            .map_err(|_grammar_error| IdentityError::IdentityCorrupt)?;
        let key_id = KeyId::parse(text_member(&members, "key_id")?)
            .map_err(|_grammar_error| IdentityError::IdentityCorrupt)?;

        let seed_text = text_member(&members, "private_seed")?;
        let seed = decode_seed(seed_text)?;
        let public = PublicIdentity::from_parts(client_id.clone(), algorithm, public_key, key_id)?;
        let signing_key = SigningKey::from_seed(seed);
        if signing_key.public_key() != *public.public_key.as_raw() {
            return Err(IdentityError::IdentityCorrupt);
        }
        Ok(Self {
            client_id,
            signing_key,
        })
    }

    /// The canonical local document: the closed identity shape with the
    /// private seed, written only to the mode-restricted local file.
    ///
    /// This is the one serialization the seed ever enters, and the one
    /// destination — the `0600` identity file a protected reference names.
    fn canonical_document(&self) -> Vec<u8> {
        let public = self.public_identity();
        let mut members = archivist_protocol::json::Object::new();
        let _ = members.insert("schema", text(IDENTITY_SCHEMA));
        let _ = members.insert("client_id", text(self.client_id.as_str()));
        let _ = members.insert("key_algorithm", text(public.algorithm.token()));
        let _ = members.insert("key_id", text(&public.key_id.to_hex()));
        let _ = members.insert("public_key", text(&public.public_key.to_hex()));
        let _ = members.insert("private_seed", text(&hex(self.signing_key.seed())));
        let value = archivist_protocol::json::Value::Object(members);
        value.canonical_bytes()
    }
}

/// Create the identity document's parent directory when absent — mode
/// `0700`, pinned explicitly so a permissive process umask cannot widen
/// it — and refuse anything that pre-exists with any other mode (CFG-023).
/// The document holding the installation's private seed keeps the same
/// directory posture as the client state and spool directories: a location
/// that is not exactly `0700` is an unsafe state, refused rather than
/// adopted. Failures name no path.
#[cfg(unix)]
fn prepare_parent_directory(document: &std::path::Path) -> Result<(), IdentityError> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::PermissionsExt;

    let dir = document
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(IdentityError::ReferenceUnsafe)?;
    if !dir.is_dir() {
        DirBuilder::new()
            .recursive(true)
            .create(dir)
            .map_err(|_io_error| IdentityError::ReferenceUnsafe)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_io_error| IdentityError::ReferenceUnsafe)?;
    }
    let mode = dir
        .metadata()
        .map_err(|_io_error| IdentityError::ReferenceUnsafe)?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(IdentityError::ReferenceUnsafe);
    }
    Ok(())
}

/// Insert a text member into the identity document.
fn text(value: &str) -> archivist_protocol::json::Value {
    archivist_protocol::json::Value::Text(value.to_owned())
}

/// Read one required text member from the discovered document.
fn text_member<'a>(
    members: &'a archivist_protocol::json::Object,
    name: &str,
) -> Result<&'a str, IdentityError> {
    match members.get(name) {
        Some(archivist_protocol::json::Value::Text(text)) => Ok(text),
        _ => Err(IdentityError::IdentityCorrupt),
    }
}

/// Decode the private seed from its lowercase-hex document form.
fn decode_seed(text: &str) -> Result<[u8; 32], IdentityError> {
    let bytes = text.as_bytes();
    let lowercase_hex = bytes
        .iter()
        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'));
    if bytes.len() != 64 || !lowercase_hex {
        return Err(IdentityError::IdentityCorrupt);
    }
    let mut seed = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        seed[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_e| IdentityError::IdentityCorrupt)?,
            16,
        )
        .map_err(|_e| IdentityError::IdentityCorrupt)?;
    }
    Ok(seed)
}

/// Lowercase hex. Used only to write the local document; no diagnostic path
/// formats a seed.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Canonical lowercase UUID text from 16 bytes.
fn format_uuid(uuid: &[u8; 16]) -> String {
    let hex = hex(uuid);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4122 version and variant bits survive minting, and the minted
    /// client ID satisfies the wire grammar (protocol's `ClientId`).
    #[test]
    fn minted_client_id_is_canonical_uuid_v4() {
        for _ in 0..64 {
            let identity = InstallationIdentity::generate().expect("entropy is available");
            let text = identity.client_id().as_str();
            assert_eq!(text.len(), 36);
            assert_eq!(text.as_bytes()[14], b'4', "version nibble: {text}");
            assert!(
                matches!(text.as_bytes()[19], b'8' | b'9' | b'a' | b'b'),
                "variant nibble: {text}"
            );
        }
    }

    /// Two mints never collide on client ID or key.
    #[test]
    fn mints_are_distinct() {
        let a = InstallationIdentity::generate().expect("entropy is available");
        let b = InstallationIdentity::generate().expect("entropy is available");
        assert_ne!(a.client_id(), b.client_id());
        assert_ne!(
            a.public_identity().public_key,
            b.public_identity().public_key
        );
    }

    /// The RFC 8032 vector seed derives the vector public key through the
    /// identity layer, and `from_seed` refuses a mismatched pair.
    #[test]
    fn from_seed_pins_to_rfc8032_and_refuses_mismatch() {
        let seed: [u8; 32] =
            decode_seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .expect("vector hex");
        let public = Ed25519PublicKey::parse(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        )
        .expect("vector hex");
        let client_id = ClientId::parse("11111111-2222-4333-8444-555555555555").expect("grammar");
        let identity =
            InstallationIdentity::from_seed(client_id.clone(), seed, public).expect("consistent");
        assert_eq!(identity.client_id(), &client_id);

        let wrong = Ed25519PublicKey::parse(
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        )
        .expect("vector hex");
        assert!(matches!(
            InstallationIdentity::from_seed(client_id, seed, wrong),
            Err(IdentityError::IdentityCorrupt)
        ));
    }

    /// The signing path through the identity layer: a minted key signs, the
    /// signature verifies against the derived public half, and tampered
    /// message, signature, or key are all refused.
    #[test]
    fn minted_key_signs_and_verifies() {
        let key = SigningKey::generate().expect("entropy is available");
        let message = b"link request body";
        let signature = key.sign(message);
        assert!(ed25519::verify(&key.public_key(), message, &signature));

        let mut flipped = *signature.as_bytes();
        flipped[0] ^= 0x01;
        let flipped = ed25519::Signature::from_bytes(flipped);
        assert!(!ed25519::verify(&key.public_key(), message, &flipped));
        assert!(!ed25519::verify(
            &key.public_key(),
            b"a different message",
            &signature
        ));
    }
}
