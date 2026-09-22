// SPDX-License-Identifier: Apache-2.0

//! AWS Signature Version 4 request signing for the S3-family storage
//! backends, over the crate's owned hash primitives.
//!
//! The S3 adapter's production request transport
//! (`archivist-storage-s3::request`) signs every request it issues with the
//! `AWS4-HMAC-SHA256` scheme: a canonical request string, a string to sign,
//! and a signing key derived by a four-step HMAC-SHA256 chain from the
//! identity's secret key. Signing is cryptography, so per crate-ownership
//! boundary rule 5 it lives here and nowhere else — the storage crate
//! assembles canonical requests and applies signatures but computes none.
//!
//! The module is pure: no I/O, no clock, no network. The caller supplies
//! the compact instant (`YYYYMMDDTHHMMSSZ`) and every canonical component
//! already URI-encoded, and receives the `Authorization` header value
//! together with the signed-header list it commits to. The reference
//! profile's `MinIO` and the S3-compatible family (B2, ARMOR, AWS S3,
//! Garage) all accept this scheme.
//!
//! # Secret discipline (SEC-004, SEC-006)
//!
//! [`SigV4Credentials`] holds the access key ID and the secret access key
//! behind redacted `Debug` rendering — the same discipline every other
//! private-material type in this crate keeps. No error, Display, or
//! derived output carries either value; the signature itself is public
//! wire material.
//!
//! # Vectors
//!
//! The signing chain is pinned end to end by the scheme's own published
//! examples — the S3 `GET Object` and `PUT Object` pairs from the AWS
//! Signature Version 4 documentation, each carried to its published
//! signature — and the HMAC-SHA256 core underneath is pinned by RFC 4231
//! test cases 1 and 2. Anything that changes a canonical byte moves a
//! published signature and fails here.

use std::fmt;
use std::fmt::Write as _;

use archivist_protocol::sha256;

/// The signature scheme's algorithm token.
const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The service token every S3-family request signs under.
const SERVICE: &str = "s3";

/// The scheme's fixed terminal scope token.
const TERMINATOR: &str = "aws4_request";

/// The secret prefix the signing-key chain starts from.
const SECRET_PREFIX: &str = "AWS4";

/// HMAC-SHA256 (RFC 2104) over the crate's owned SHA-256.
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Block size B = 64 bytes (FIPS 180-4). Keys longer than B are
    // replaced by their hash; shorter keys are zero-padded to B.
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = sha256::Sha256::new();
    for byte in &block {
        inner.update(&[byte ^ 0x36]);
    }
    inner.update(data);
    let inner_digest = inner.finalize();

    let mut outer = sha256::Sha256::new();
    for byte in &block {
        outer.update(&[byte ^ 0x5c]);
    }
    outer.update(&inner_digest);
    outer.finalize()
}

/// The credential pair one S3 identity signs with: the access key ID the
/// backend names in its policy and the secret access key the signature
/// derives from.
///
/// Resolved once, at composition, from the identity's credential
/// reference; never rendered in full by any diagnostic of this type.
#[derive(Clone)]
pub struct SigV4Credentials {
    access_key_id: Box<str>,
    secret_access_key: Box<str>,
}

impl SigV4Credentials {
    /// Pair an access key ID with its secret access key.
    #[must_use]
    pub fn new(access_key_id: &str, secret_access_key: &str) -> Self {
        Self {
            access_key_id: Box::from(access_key_id),
            secret_access_key: Box::from(secret_access_key),
        }
    }
}

impl fmt::Debug for SigV4Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the access key ID nor the secret renders: the pair is
        // private material even where the ID alone would be safe (SEC-006).
        f.write_str("SigV4Credentials(REDACTED)")
    }
}

/// One request in its canonical form: everything the signature covers,
/// already encoded the way the wire will carry it.
///
/// The header list is the signed-header set: names are lowercased, values
/// trimmed, and the canonical form sorts by name — which [`SigV4Signer`]
/// does itself, so the caller may pass headers in any order. Header values
/// must already be the exact text the request carries; the signature
/// commits to them verbatim.
#[derive(Debug)]
pub struct SigV4Request<'a> {
    /// The HTTP method, uppercase (`PUT`, `POST`, `GET`, `HEAD`, `DELETE`).
    pub method: &'a str,
    /// The URI-encoded request path, starting with `/`.
    pub canonical_path: &'a str,
    /// The canonical query string: URI-encoded components joined by `&`,
    /// sorted by name; empty when the request carries no query.
    pub canonical_query: &'a str,
    /// The headers to sign, as `(lowercase name, value)` pairs.
    pub headers: &'a [(&'a str, &'a str)],
    /// The lowercase hex SHA-256 of the exact payload bytes (`GET`, `HEAD`,
    /// and `DELETE` carry the hash of the empty string).
    pub payload_hash: &'a str,
}

/// The signature over one request: the `Authorization` header value and
/// the signed-header list it commits to, in canonical order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigV4Signature {
    authorization: String,
    signed_headers: String,
}

impl SigV4Signature {
    /// The complete `Authorization` header value,
    /// `AWS4-HMAC-SHA256 Credential=…, SignedHeaders=…, Signature=…`.
    #[must_use]
    pub fn authorization(&self) -> &str {
        &self.authorization
    }

    /// The signed-header names, semicolon-joined in canonical order —
    /// exactly the list the `Authorization` header commits to.
    #[must_use]
    pub fn signed_headers(&self) -> &str {
        &self.signed_headers
    }
}

/// The `SigV4` signer for one region: derives the four-step signing key and
/// produces the `Authorization` header for canonical requests.
///
/// The service is pinned to `s3`; the signer is stateless and
/// copy-cheap, so one instance serves every request a transport issues.
#[derive(Clone, Debug)]
pub struct SigV4Signer {
    region: Box<str>,
}

impl SigV4Signer {
    /// Build the signer for one backend region string, exactly as the
    /// configuration validated it.
    #[must_use]
    pub fn new(region: &str) -> Self {
        Self {
            region: Box::from(region),
        }
    }

    /// Sign one canonical request at one compact instant.
    ///
    /// `amz_date` is the `x-amz-date` value the request will carry —
    /// basic-format ISO 8601, `YYYYMMDDTHHMMSSZ`; its first eight
    /// characters form the credential scope's date. The returned
    /// signature commits to `request.headers` plus `host` and the two
    /// `x-amz-` headers the caller supplies inside that list: the scheme
    /// signs whatever set the caller presents, and the transport presents
    /// `host`, `x-amz-content-sha256`, and `x-amz-date` on every request.
    #[must_use]
    pub fn sign(
        &self,
        credentials: &SigV4Credentials,
        request: &SigV4Request<'_>,
        amz_date: &str,
    ) -> SigV4Signature {
        let mut headers: Vec<(&str, &str)> = request.headers.to_vec();
        headers.sort_unstable_by_key(|(left, _)| *left);
        let signed_headers = headers
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(";");
        let mut canonical_headers = String::new();
        for (name, value) in &headers {
            let _ = writeln!(canonical_headers, "{name}:{}", value.trim());
        }

        // Canonical request: method, path, query, canonical headers (each
        // line newline-terminated), signed-header list, payload hash.
        let mut canonical_request = String::with_capacity(256);
        canonical_request.push_str(request.method);
        canonical_request.push('\n');
        canonical_request.push_str(request.canonical_path);
        canonical_request.push('\n');
        canonical_request.push_str(request.canonical_query);
        canonical_request.push('\n');
        canonical_request.push_str(&canonical_headers);
        canonical_request.push('\n');
        canonical_request.push_str(&signed_headers);
        canonical_request.push('\n');
        canonical_request.push_str(request.payload_hash);

        let scope = format!(
            "{}/{}/{}/{}",
            amz_date.get(..8).unwrap_or_default(),
            self.region,
            SERVICE,
            TERMINATOR
        );
        let string_to_sign = format!(
            "{ALGORITHM}\n{amz_date}\n{scope}\n{}",
            sha256::encode_hex(&sha256::digest(canonical_request.as_bytes()))
        );

        // Signing key: HMAC chain secret -> date -> region -> service ->
        // terminator.
        let date_key = hmac_sha256(
            format!("{SECRET_PREFIX}{}", credentials.secret_access_key).as_bytes(),
            amz_date.get(..8).unwrap_or_default().as_bytes(),
        );
        let region_key = hmac_sha256(&date_key, self.region.as_bytes());
        let service_key = hmac_sha256(&region_key, SERVICE.as_bytes());
        let signing_key = hmac_sha256(&service_key, TERMINATOR.as_bytes());
        let signature = sha256::encode_hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        let authorization = format!(
            "{ALGORITHM} Credential={}/{}, SignedHeaders={}, Signature={}",
            credentials.access_key_id, scope, signed_headers, signature
        );
        SigV4Signature {
            authorization,
            signed_headers,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SigV4Credentials, SigV4Request, SigV4Signer};

    // The pair the AWS Signature Version 4 documentation's S3 examples
    // sign with; published wire material, not a secret.
    const DOC_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
    const DOC_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const DOC_REGION: &str = "us-east-1";
    const DOC_INSTANT: &str = "20130524T000000Z";
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn hmac_sha256_rfc_4231_case_1() {
        let mac = super::hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            super::sha256::encode_hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hmac_sha256_rfc_4231_case_2() {
        let mac = super::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            super::sha256::encode_hex(&mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha256_long_key_falls_back_to_hash() {
        // RFC 4231 test case 6: a 131-byte key exercises the hash-the-key
        // branch of the block-size rule.
        let key = [0xaa; 131];
        let mac = super::hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            super::sha256::encode_hex(&mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn signs_the_documented_get_object_example() {
        // AWS SigV4 documentation, "Example: GET Object". The signed
        // headers are host, range, and the two x-amz- headers.
        let signer = SigV4Signer::new(DOC_REGION);
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let headers = [
            ("host", "examplebucket.s3.amazonaws.com"),
            ("range", "bytes=0-9"),
            ("x-amz-content-sha256", EMPTY_SHA256),
            ("x-amz-date", DOC_INSTANT),
        ];
        let request = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        let signature = signer.sign(&credentials, &request, DOC_INSTANT);
        assert_eq!(
            signature.authorization(),
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
        assert_eq!(
            signature.signed_headers(),
            "host;range;x-amz-content-sha256;x-amz-date"
        );
    }

    #[test]
    fn signs_the_documented_put_object_example() {
        // AWS SigV4 documentation, "Example: PUT Object". The payload hash
        // is over "Welcome to Amazon S3.".
        let payload = b"Welcome to Amazon S3.";
        let payload_hash = super::sha256::encode_hex(&super::sha256::digest(payload));
        assert_eq!(
            payload_hash,
            "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072"
        );
        let signer = SigV4Signer::new(DOC_REGION);
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let headers = [
            ("date", "Fri, 24 May 2013 00:00:00 GMT"),
            ("host", "examplebucket.s3.amazonaws.com"),
            ("x-amz-content-sha256", payload_hash.as_str()),
            ("x-amz-date", DOC_INSTANT),
            ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
        ];
        let request = SigV4Request {
            method: "PUT",
            canonical_path: "/test%24file.text",
            canonical_query: "",
            headers: &headers,
            payload_hash: &payload_hash,
        };
        let signature = signer.sign(&credentials, &request, DOC_INSTANT);
        assert_eq!(
            signature.authorization(),
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, \
             Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"
        );
    }

    #[test]
    fn header_order_does_not_change_the_signature() {
        // The canonical form sorts by header name, so the same request
        // with differently ordered headers signs identically.
        let signer = SigV4Signer::new(DOC_REGION);
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let one = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &[
                ("x-amz-date", DOC_INSTANT),
                ("range", "bytes=0-9"),
                ("host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
            ],
            payload_hash: EMPTY_SHA256,
        };
        let two = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", DOC_INSTANT),
                ("range", "bytes=0-9"),
            ],
            payload_hash: EMPTY_SHA256,
        };
        assert_eq!(
            signer.sign(&credentials, &one, DOC_INSTANT),
            signer.sign(&credentials, &two, DOC_INSTANT)
        );
    }

    #[test]
    fn header_value_whitespace_is_trimmed_before_signing() {
        // Canonical form trims surrounding whitespace from values, so a
        // value padded the way some header writers pad signs identically
        // to its trimmed form.
        let signer = SigV4Signer::new(DOC_REGION);
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let plain = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", DOC_INSTANT),
            ],
            payload_hash: EMPTY_SHA256,
        };
        let padded = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", "  examplebucket.s3.amazonaws.com "),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", DOC_INSTANT),
            ],
            payload_hash: EMPTY_SHA256,
        };
        assert_eq!(
            signer.sign(&credentials, &plain, DOC_INSTANT),
            signer.sign(&credentials, &padded, DOC_INSTANT)
        );
    }

    #[test]
    fn credentials_render_redacted() {
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let rendered = format!("{credentials:?}");
        assert!(!rendered.contains(DOC_ACCESS_KEY));
        assert!(!rendered.contains(DOC_SECRET_KEY));
    }

    #[test]
    fn different_region_or_instant_changes_the_signature() {
        let signer = SigV4Signer::new(DOC_REGION);
        let credentials = SigV4Credentials::new(DOC_ACCESS_KEY, DOC_SECRET_KEY);
        let request = SigV4Request {
            method: "GET",
            canonical_path: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("x-amz-content-sha256", EMPTY_SHA256),
                ("x-amz-date", DOC_INSTANT),
            ],
            payload_hash: EMPTY_SHA256,
        };
        let base = signer.sign(&credentials, &request, DOC_INSTANT);
        let other_region = SigV4Signer::new("us-west-2").sign(&credentials, &request, DOC_INSTANT);
        assert_ne!(base.authorization(), other_region.authorization());
        let other_instant = signer.sign(&credentials, &request, "20130525T000000Z");
        assert_ne!(base.authorization(), other_instant.authorization());
    }
}
