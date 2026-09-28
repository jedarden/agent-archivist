// SPDX-License-Identifier: Apache-2.0

//! The production S3-family request binding.
//!
//! [`S3RequestBackend`] is the composition-time binding between the typed
//! storage seams and an S3-compatible HTTP endpoint. It resolves one
//! protected credential reference into the auth crate's redacted `SigV4`
//! credential type, builds path- or virtual-hosted requests, and keeps the
//! backend-specific HTTP details below this crate's public seams.
//!
//! The binding deliberately has no general object API. Its constructors
//! produce an authority-specific instance, and the trait implementations
//! expose only the verbs that authority is provisioned for: raw
//! write/multipart, control read/HEAD, control administration GET/PUT, the
//! capability probe's write-shaped instrument, or the audit identity's
//! versions listing. Scope is checked again at this boundary before a
//! request exists, so a composition mistake cannot turn a typed key into a
//! request for another tenant or prefix.
//!
//! Response bodies are collected through a fixed cap. This applies to
//! successful control records, S3 XML responses, and failures alike; a
//! `Content-Length` over the cap is rejected before body collection and a
//! chunked response is stopped when the cap would be crossed.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use archivist_auth::sigv4::{SigV4Credentials, SigV4Request, SigV4Signer};
use archivist_protocol::envelope::CANONICAL_MAX_BYTES;
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{TenantId, Timestamp};
use archivist_storage::audit_restore::{
    ContinuationToken, InventoryEntry, InventoryKey, InventoryPage, InventoryScope, ObjectBody,
    ObjectMetadata,
};
use archivist_storage::commit::{CreateIfAbsent, ExistingObject};
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::lifecycle_audit::{VersionedEntry, VersionedPage};
use archivist_storage::metadata::{ObjectTag, Observation, StorageVersionId};
use archivist_storage::probe::{ProbeKey, VersioningObservation};
use archivist_storage::raw_write::{PartCommitment, PartNumber};
use archivist_storage::scoped_write::{
    CatalogCheckpointKey, CatalogListPrefix, DerivedListPrefix, DerivedObjectKey,
};
use bytes::{Buf, Bytes};
use http::header::{CONTENT_LENGTH, ETAG, HOST, HeaderMap, HeaderValue};
use http::{Method, Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector as HyperHttpConnector;
use hyper_util::rt::TokioExecutor;

use crate::config::{
    ControlAdminConfig, ControlReadConfig, CredentialReference, CredentialResolutionError,
    EndpointUrl, PathStyle, S3StorageConfig,
};
use crate::control_admin::{ControlAdminBackend, ControlObjectKey};
use crate::control_read::ControlReadBackend;
use crate::lifecycle_audit::VersionAuditBackend;
use crate::probe::{ProbeObjectObservation, ProbeReceipt, ProbeWriteBackend};
use crate::raw_write::{RawObjectKey, RawWriteBackend};
use crate::scoped_write::{
    CatalogWriteBackend, CatalogWriterConfig, DerivedWriteBackend, DerivedWriterConfig,
};

const RESPONSE_MAX_BYTES: usize = CANONICAL_MAX_BYTES;
const COMPLETE_XML_MAX_BYTES: usize = 8 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const DETAIL_CREDENTIALS_UNAVAILABLE: &str = "credential reference could not be resolved";
const DETAIL_CREDENTIALS_MALFORMED: &str = "resolved credential document is malformed";
const DETAIL_ENDPOINT: &str = "validated endpoint could not be prepared";
const DETAIL_SCOPE: &str = "request is outside this backend identity";
const DETAIL_RESPONSE: &str = "backend response is malformed";
const DETAIL_RESPONSE_TOO_LARGE: &str = "backend response exceeds the bounded read limit";
const DETAIL_REQUEST: &str = "S3 request could not be constructed";
const DETAIL_UNAVAILABLE: &str = "S3 backend request failed";
const DETAIL_COMPLETE_BOUNDS: &str = "multipart completion document exceeds its bound";
const DETAIL_UPLOAD_ID: &str = "multipart response did not contain a valid upload id";
const DETAIL_ETAG: &str = "multipart response did not contain a valid etag";
const DETAIL_VERSIONS_RESPONSE: &str = "versions listing response is malformed";
const DETAIL_LIST_RESPONSE: &str = "object listing response is malformed";
/// The sentinel a listing parser adopts for a version the backend did not
/// name — an object stored before versioning was ever enabled. The token
/// rounds only through this crate's own listing; a runner reporting
/// version-id claims filters it out, because an unnamed version is not a
/// version identity the run may claim.
const NULL_VERSION_SENTINEL: &str = "null";
/// The most keys one versions-listing page asks for. The freeze contract
/// bounds the whole sequence, so a large page only reduces request count.
const VERSIONS_PAGE_KEYS: usize = 1000;

type HttpBody = Full<Bytes>;
type HttpConnector = hyper_rustls::HttpsConnector<HyperHttpConnector>;
type HttpClient = Client<HttpConnector, HttpBody>;

/// Why composition of a production request binding failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum S3RequestErrorKind {
    /// The credential reference target could not be read.
    CredentialUnavailable,
    /// The target was readable but did not contain the pinned pair.
    CredentialMalformed,
    /// The already-validated endpoint could not be converted to a request
    /// authority.
    EndpointMalformed,
}

impl fmt::Display for S3RequestErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CredentialUnavailable => "credential-unavailable",
            Self::CredentialMalformed => "credential-malformed",
            Self::EndpointMalformed => "endpoint-malformed",
        })
    }
}

/// A content-free composition failure for the concrete S3 request backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct S3RequestError {
    kind: S3RequestErrorKind,
    detail: &'static str,
}

impl S3RequestError {
    /// Build one request-composition error.
    #[must_use]
    pub const fn new(kind: S3RequestErrorKind, detail: &'static str) -> Self {
        Self { kind, detail }
    }

    /// The closed failure class.
    #[must_use]
    pub const fn kind(&self) -> S3RequestErrorKind {
        self.kind
    }

    /// The content-free detail.
    #[must_use]
    pub const fn detail(&self) -> &'static str {
        self.detail
    }
}

impl fmt::Display for S3RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "s3 request {}: {}", self.kind, self.detail)
    }
}

impl std::error::Error for S3RequestError {}

/// The authority a concrete binding carries. One instance never combines
/// credentials from two roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Authority {
    RawWrite,
    ControlRead,
    ControlAdmin,
    /// The capability probe's write-shaped instrument: writes, reads, and
    /// multipart sessions aimed only at the reserved probe namespace.
    ProbeWrite,
    /// The audit identity's versions listing: read-only enumeration across
    /// the tenant prefixes and nothing else.
    VersionAudit,
    /// The catalog checkpoint writer: put and list below one tenant catalog
    /// prefix and nothing else.
    CatalogWrite,
    /// The derived projection writer: put and list below one tenant derived
    /// prefix and nothing else.
    DerivedWrite,
    /// The offline audit/restore identity: list, head, and get below the
    /// tenant's raw, control, catalog, and derived prefixes.
    AuditRestore,
}

/// The validated endpoint pieces needed for request URI construction.
#[derive(Clone, Debug)]
struct EndpointParts {
    scheme: Box<str>,
    authority: Box<str>,
    base_path: Box<str>,
}

impl EndpointParts {
    fn parse(endpoint: &EndpointUrl) -> Result<Self, S3RequestError> {
        let text = endpoint.as_str();
        let (scheme, rest) = text.split_once("://").ok_or_else(endpoint_error)?;
        let authority_end = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..authority_end];
        if authority.is_empty() {
            return Err(endpoint_error());
        }
        let base_path = rest[authority_end..].trim_end_matches('/');
        Ok(Self {
            scheme: scheme.into(),
            authority: authority.into(),
            base_path: base_path.into(),
        })
    }

    fn authority_for(&self, bucket: &str, path_style: PathStyle) -> Result<String, StorageError> {
        match path_style {
            PathStyle::Path => Ok(self.authority.to_string()),
            PathStyle::VirtualHosted => {
                if self.authority.starts_with('[') {
                    return Err(StorageError::new(
                        StorageErrorKind::MalformedInput,
                        DETAIL_ENDPOINT,
                    ));
                }
                let (host, port) = match self.authority.rsplit_once(':') {
                    Some((host, port)) if port.bytes().all(|byte| byte.is_ascii_digit()) => {
                        (host, Some(port))
                    }
                    _ => (self.authority.as_ref(), None),
                };
                let mut result = String::with_capacity(bucket.len() + self.authority.len() + 1);
                result.push_str(bucket);
                result.push('.');
                result.push_str(host);
                if let Some(port) = port {
                    result.push(':');
                    result.push_str(port);
                }
                Ok(result)
            }
        }
    }
}

fn endpoint_error() -> S3RequestError {
    S3RequestError::new(S3RequestErrorKind::EndpointMalformed, DETAIL_ENDPOINT)
}

/// The reusable HTTP client and immutable request-authentication state.
struct BackendInner {
    client: HttpClient,
    endpoint: EndpointParts,
    path_style: PathStyle,
    bucket: Box<str>,
    /// The audit identity enumerates both tenant buckets, so the versions
    /// authority carries the control bucket alongside the primary (raw)
    /// one. Every other authority leaves it unset.
    alternate_bucket: Option<Box<str>>,
    tenant: Box<str>,
    prefix: Box<str>,
    authority: Authority,
    signer: SigV4Signer,
    credentials: SigV4Credentials,
}

impl fmt::Debug for BackendInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BackendInner")
            .field("authority", &self.authority)
            .field("endpoint", &self.endpoint)
            .field("path_style", &self.path_style)
            .field("bucket", &"REDACTED")
            .field("alternate_bucket", &"REDACTED")
            .field("tenant", &"REDACTED")
            .field("prefix", &"REDACTED")
            .field("signer", &self.signer)
            .field("credentials", &self.credentials)
            .finish_non_exhaustive()
    }
}

/// The production S3 request binding.
///
/// Construct it with [`S3RequestBackend::raw_write`],
/// [`S3RequestBackend::control_read`], or
/// [`S3RequestBackend::control_admin`]. The selected constructor resolves
/// its `CredentialReference` immediately; this type stores only the auth
/// crate's redacting credential wrapper, never the reference target.
#[derive(Clone)]
pub struct S3RequestBackend {
    inner: Arc<BackendInner>,
}

impl fmt::Debug for S3RequestBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3RequestBackend")
            .field("inner", &self.inner)
            .finish()
    }
}

impl S3RequestBackend {
    /// Compose a raw-writer request binding for one tenant.
    ///
    /// The raw-writer credential is checked against the supplied tenant
    /// before every request. The returned binding implements
    /// [`RawWriteBackend`] and no read or list seam.
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn raw_write(config: &S3StorageConfig, tenant: &TenantId) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.raw_bucket(),
            None,
            tenant,
            config.identities().raw_write(),
            Authority::RawWrite,
        )
    }

    /// Compose the capability probe's request binding for one tenant.
    ///
    /// The instrument rides the same write-shaped credential reference the
    /// raw writer composes with — the configuration's one write-shaped
    /// role (a qualification run provisions one write-shaped identity for
    /// the probe instrument and the write path together) — but its scope
    /// is the reserved probe namespace and nothing else: every request it
    /// issues targets `tenants/<tenant>/v1/probe/` or the bucket-level
    /// versioning and encryption configuration surfaces of the raw bucket.
    /// The returned binding implements [`crate::probe::ProbeWriteBackend`]
    /// and no other seam.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn probe_write(
        config: &S3StorageConfig,
        tenant: &TenantId,
    ) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.raw_bucket(),
            None,
            tenant,
            config.identities().raw_write(),
            Authority::ProbeWrite,
        )
    }

    /// Compose the audit identity's versions-listing binding for one
    /// tenant.
    ///
    /// The binding rides the configuration's optional offline-restore
    /// credential — the one authority with list grants across the tenant
    /// prefixes — and enumerates the raw and control buckets' versions
    /// listings over the closed [`InventoryScope`]s. A configuration that
    /// never granted the offline-restore identity has no such binding.
    ///
    /// # Errors
    ///
    /// Returns [`S3RequestErrorKind::CredentialUnavailable`] when the
    /// configuration did not grant the offline-restore identity, and a
    /// credential or endpoint composition error when the validated
    /// configuration cannot otherwise produce a usable request binding.
    pub fn version_audit(
        config: &S3StorageConfig,
        tenant: &TenantId,
    ) -> Result<Self, S3RequestError> {
        let control_bucket = config.control_bucket();
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.raw_bucket(),
            Some(control_bucket),
            tenant,
            config.identities().offline_restore().ok_or_else(|| {
                S3RequestError::new(
                    S3RequestErrorKind::CredentialUnavailable,
                    DETAIL_CREDENTIALS_UNAVAILABLE,
                )
            })?,
            Authority::VersionAudit,
        )
    }

    /// Compose a raw-writer binding by borrowing an existing validated
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn from_raw_write_config(
        config: &S3StorageConfig,
        tenant: &TenantId,
    ) -> Result<Self, S3RequestError> {
        Self::raw_write(config, tenant)
    }

    /// Compose a control-reader request binding.
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn control_read(config: &ControlReadConfig) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.control_bucket(),
            None,
            config.tenant(),
            config.control_read_credentials(),
            Authority::ControlRead,
        )
    }

    /// Compose a control-reader binding by borrowing an existing validated
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn from_control_read_config(config: &ControlReadConfig) -> Result<Self, S3RequestError> {
        Self::control_read(config)
    }

    /// Compose a control-administration request binding.
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn control_admin(config: &ControlAdminConfig) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.control_bucket(),
            None,
            config.tenant(),
            config.control_admin_credentials(),
            Authority::ControlAdmin,
        )
    }

    /// Compose a control-administration binding by borrowing an existing
    /// validated configuration.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn from_control_admin_config(config: &ControlAdminConfig) -> Result<Self, S3RequestError> {
        Self::control_admin(config)
    }

    /// Compose the catalog checkpoint writer's request binding. The
    /// dedicated credential is resolved here and is never combined with an
    /// ingest or derived-writer authority.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn catalog_write(config: &CatalogWriterConfig) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.tenant_bucket(),
            None,
            config.tenant(),
            config.catalog_write_credentials(),
            Authority::CatalogWrite,
        )
    }

    /// Compose the derived projection writer's request binding. The
    /// dedicated credential is resolved here and is never combined with an
    /// ingest or catalog-writer authority.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn derived_write(config: &DerivedWriterConfig) -> Result<Self, S3RequestError> {
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.tenant_bucket(),
            None,
            config.tenant(),
            config.derived_write_credentials(),
            Authority::DerivedWrite,
        )
    }

    /// Compose the offline audit/restore request binding. It is the only
    /// binding in this module that can enumerate or read raw objects, and it
    /// carries the separately provisioned offline-restore credential.
    ///
    /// # Errors
    ///
    /// Returns a credential or endpoint composition error when the validated
    /// configuration cannot produce a usable request binding.
    pub fn audit_restore(
        config: &S3StorageConfig,
        tenant: &TenantId,
    ) -> Result<Self, S3RequestError> {
        let credential = config.identities().offline_restore().ok_or_else(|| {
            S3RequestError::new(
                S3RequestErrorKind::CredentialUnavailable,
                DETAIL_CREDENTIALS_UNAVAILABLE,
            )
        })?;
        Self::compose(
            config.endpoint(),
            config.path_style(),
            config.region(),
            config.raw_bucket(),
            Some(config.control_bucket()),
            tenant,
            credential,
            Authority::AuditRestore,
        )
    }

    #[allow(clippy::too_many_arguments)] // one authority's full composition, read top to bottom
    fn compose(
        endpoint: &EndpointUrl,
        path_style: PathStyle,
        region: &str,
        bucket: &str,
        alternate_bucket: Option<&str>,
        tenant: &TenantId,
        reference: &CredentialReference,
        authority: Authority,
    ) -> Result<Self, S3RequestError> {
        let endpoint = EndpointParts::parse(endpoint)?;
        let (access_key, secret_key) = reference
            .resolve_s3_credentials()
            .map_err(credential_error)?;
        let connector = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build();
        let client = Client::builder(TokioExecutor::new()).build(connector);
        let prefix = match authority {
            Authority::RawWrite => format!("tenants/{tenant}/v1/raw/"),
            Authority::ControlRead | Authority::ControlAdmin => {
                format!("tenants/{tenant}/v1/control/")
            }
            Authority::ProbeWrite => format!("tenants/{tenant}/v1/probe/"),
            Authority::VersionAudit | Authority::AuditRestore => format!("tenants/{tenant}/"),
            Authority::CatalogWrite => format!("tenants/{tenant}/v1/catalog/"),
            Authority::DerivedWrite => format!("tenants/{tenant}/v1/derived/"),
        };
        Ok(Self {
            inner: Arc::new(BackendInner {
                client,
                endpoint,
                path_style,
                bucket: bucket.into(),
                alternate_bucket: alternate_bucket.map(Box::from),
                tenant: tenant.to_string().into_boxed_str(),
                prefix: prefix.into_boxed_str(),
                authority,
                signer: SigV4Signer::new(region),
                credentials: SigV4Credentials::new(&access_key, &secret_key),
            }),
        })
    }

    fn check_scope(
        &self,
        authority: Authority,
        tenant: &str,
        key: &str,
    ) -> Result<(), StorageError> {
        if self.inner.authority != authority
            || self.inner.tenant.as_ref() != tenant
            || !key.starts_with(self.inner.prefix.as_ref())
        {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        key: &str,
        query: &str,
        payload: &[u8],
        conditional: bool,
    ) -> Result<HttpResponse, StorageError> {
        self.request_on_bucket(&self.inner.bucket, method, key, query, payload, conditional)
            .await
    }

    /// Issue one signed request against `bucket` — the authority's primary
    /// bucket for every verb, plus the control bucket for the versions
    /// authority's control-scope listings.
    async fn request_on_bucket(
        &self,
        bucket: &str,
        method: Method,
        key: &str,
        query: &str,
        payload: &[u8],
        conditional: bool,
    ) -> Result<HttpResponse, StorageError> {
        let authority = self
            .inner
            .endpoint
            .authority_for(bucket, self.inner.path_style)?;
        let path = request_path(&self.inner.endpoint.base_path, bucket, key);
        let payload_hash = sha256::encode_hex(&sha256::digest(payload));
        let (amz_date, _) = request_clock()?;
        let signing_headers = signing_headers(&authority, &payload_hash, &amz_date, conditional);
        let signature = self.inner.signer.sign(
            &self.inner.credentials,
            &SigV4Request {
                method: method.as_str(),
                canonical_path: &path,
                canonical_query: query,
                headers: &signing_headers,
                payload_hash: &payload_hash,
            },
            &amz_date,
        );
        let uri_text = if query.is_empty() {
            format!("{}://{}{}", self.inner.endpoint.scheme, authority, path)
        } else {
            format!(
                "{}://{}{}?{}",
                self.inner.endpoint.scheme, authority, path, query
            )
        };
        let uri: Uri = uri_text.parse().map_err(|_| storage_request_error())?;
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Full::new(Bytes::copy_from_slice(payload)))
            .map_err(|_| storage_request_error())?;
        let headers = request.headers_mut();
        headers.insert(HOST, header_value(&authority)?);
        headers.insert("x-amz-content-sha256", header_value(&payload_hash)?);
        headers.insert("x-amz-date", header_value(&amz_date)?);
        headers.insert("authorization", header_value(signature.authorization())?);
        if conditional {
            headers.insert("if-none-match", HeaderValue::from_static("*"));
        }
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.inner.client.request(request))
            .await
            .map_err(|_| unavailable_error())?
            .map_err(|_| unavailable_error())?;
        let content_length = response
            .headers()
            .get(CONTENT_LENGTH)
            .map(parse_content_length)
            .transpose()?;
        if content_length.is_some_and(|length| length > RESPONSE_MAX_BYTES as u64) {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_RESPONSE_TOO_LARGE,
            ));
        }
        let status = response.status();
        let headers = response.headers().clone();
        let body = read_bounded(response.into_body(), RESPONSE_MAX_BYTES).await?;
        Ok(HttpResponse {
            status,
            headers,
            body,
            content_length,
        })
    }

    async fn raw_put(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
        conditional: bool,
    ) -> Result<CreateIfAbsent, StorageError> {
        self.check_scope(Authority::RawWrite, key.tenant(), key.as_str())?;
        let response = self
            .request(Method::PUT, key.as_str(), "", bytes, conditional)
            .await?;
        if conditional && response.status == StatusCode::PRECONDITION_FAILED {
            return Ok(CreateIfAbsent::AlreadyExists(ExistingObject::new()));
        }
        if response.status.is_success() {
            return Ok(CreateIfAbsent::Created);
        }
        Err(status_error(response.status))
    }

    async fn create_multipart_request(&self, key: &RawObjectKey) -> Result<String, StorageError> {
        self.check_scope(Authority::RawWrite, key.tenant(), key.as_str())?;
        let response = self
            .request(Method::POST, key.as_str(), "uploads=", &[], false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        extract_xml_value(&response.body, "UploadId")
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .map(str::to_owned)
            .ok_or_else(|| StorageError::new(StorageErrorKind::Unavailable, DETAIL_UPLOAD_ID))
    }

    async fn upload_part_request(
        &self,
        key: &RawObjectKey,
        upload_id: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        self.check_scope(Authority::RawWrite, key.tenant(), key.as_str())?;
        let query = format!(
            "partNumber={}&uploadId={}",
            part,
            encode_component(upload_id)
        );
        let response = self
            .request(Method::PUT, key.as_str(), &query, bytes, false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ObjectTag::parse(value).ok())
            .map(|tag| tag.to_string())
            .ok_or_else(|| StorageError::new(StorageErrorKind::Unavailable, DETAIL_ETAG))
    }

    async fn complete_multipart_request(
        &self,
        key: &RawObjectKey,
        upload_id: &str,
        parts: &[PartCommitment],
    ) -> Result<(), StorageError> {
        self.check_scope(Authority::RawWrite, key.tenant(), key.as_str())?;
        let payload = complete_document(parts)?;
        let query = format!("uploadId={}", encode_component(upload_id));
        let response = self
            .request(Method::POST, key.as_str(), &query, &payload, false)
            .await?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }

    async fn abort_multipart_request(
        &self,
        key: &RawObjectKey,
        upload_id: &str,
    ) -> Result<(), StorageError> {
        self.check_scope(Authority::RawWrite, key.tenant(), key.as_str())?;
        let query = format!("uploadId={}", encode_component(upload_id));
        let response = self
            .request(Method::DELETE, key.as_str(), &query, &[], false)
            .await?;
        if response.status.is_success() || response.status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }

    async fn control_get(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<HttpResponse>, StorageError> {
        self.check_scope(Authority::ControlRead, key.tenant().as_str(), key.as_str())?;
        let response = self
            .request(Method::GET, key.as_str(), "", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status.is_success() {
            return Ok(Some(response));
        }
        Err(status_error(response.status))
    }

    async fn control_head(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<HttpResponse>, StorageError> {
        self.check_scope(Authority::ControlRead, key.tenant().as_str(), key.as_str())?;
        let response = self
            .request(Method::HEAD, key.as_str(), "", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status.is_success() {
            return Ok(Some(response));
        }
        Err(status_error(response.status))
    }

    async fn admin_get(&self, key: &ControlObjectKey) -> Result<Option<Vec<u8>>, StorageError> {
        self.check_scope(Authority::ControlAdmin, key.tenant().as_str(), key.as_str())?;
        let response = self
            .request(Method::GET, key.as_str(), "", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if response.status.is_success() {
            return Ok(Some(response.body));
        }
        Err(status_error(response.status))
    }

    async fn admin_put(&self, key: &ControlObjectKey, bytes: &[u8]) -> Result<(), StorageError> {
        self.check_scope(Authority::ControlAdmin, key.tenant().as_str(), key.as_str())?;
        let response = self
            .request(Method::PUT, key.as_str(), "", bytes, false)
            .await?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }

    async fn scoped_put(
        &self,
        authority: Authority,
        key: &str,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.check_scope(authority, &self.inner.tenant, key)?;
        let response = self.request(Method::PUT, key, "", bytes, false).await?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }

    async fn list_scoped(
        &self,
        authority: Authority,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        if self.inner.authority != authority || !prefix.starts_with(self.inner.prefix.as_ref()) {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        let mut keys = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .list_page(self.inner.bucket.as_ref(), prefix, after.as_ref())
                .await?;
            keys.extend(
                page.entries()
                    .iter()
                    .map(|entry| entry.key().as_str().to_owned()),
            );
            after = page.next().cloned();
            if after.is_none() {
                return Ok(keys);
            }
        }
    }

    async fn list_page(
        &self,
        bucket: &str,
        prefix: &str,
        after: Option<&ContinuationToken>,
    ) -> Result<InventoryPage, StorageError> {
        let mut query = format!(
            "list-type=2&prefix={}&max-keys={}",
            encode_component(prefix),
            VERSIONS_PAGE_KEYS
        );
        if let Some(token) = after {
            query.push_str("&continuation-token=");
            query.push_str(&encode_component(token.as_str()));
        }
        let response = self
            .request_on_bucket(bucket, Method::GET, "", &query, &[], false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        let (_, observed_at) = request_clock()?;
        parse_inventory_page(&response.body, &observed_at)
    }

    /// List one `ListObjectsV2` page for the offline audit/restore identity.
    ///
    /// # Errors
    ///
    /// Returns a scope or backend error when the request is outside the
    /// provisioned identity or the S3 response cannot be decoded.
    pub async fn audit_list_page(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> Result<InventoryPage, StorageError> {
        if self.inner.authority != Authority::AuditRestore {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        let tenant = match scope {
            InventoryScope::TenantRaw(tenant)
            | InventoryScope::TenantControl(tenant)
            | InventoryScope::TenantCatalog(tenant)
            | InventoryScope::TenantDerived(tenant) => tenant,
        };
        if tenant.as_str() != self.inner.tenant.as_ref() {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        let bucket = match scope {
            InventoryScope::TenantControl(_) => self
                .inner
                .alternate_bucket
                .as_deref()
                .ok_or_else(unavailable_error)?,
            InventoryScope::TenantRaw(_)
            | InventoryScope::TenantCatalog(_)
            | InventoryScope::TenantDerived(_) => self.inner.bucket.as_ref(),
        };
        self.list_page(bucket, &scope.prefix(), after).await
    }

    /// Inspect one object for the offline audit/restore identity.
    ///
    /// # Errors
    ///
    /// Returns a scope or backend error when the request is outside the
    /// provisioned identity or the S3 response cannot be decoded.
    pub async fn audit_inspect_object(
        &self,
        key: &InventoryKey,
    ) -> Result<ObjectMetadata, StorageError> {
        let response = self.audit_object_request(Method::HEAD, key).await?;
        let size = response
            .content_length
            .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
        Ok(ObjectMetadata::new(size, observation(&response.headers)?))
    }

    /// Read one object for the offline audit/restore identity.
    ///
    /// # Errors
    ///
    /// Returns a scope or backend error when the request is outside the
    /// provisioned identity or the S3 response cannot be decoded.
    pub async fn audit_read_object(&self, key: &InventoryKey) -> Result<ObjectBody, StorageError> {
        let response = self.audit_object_request(Method::GET, key).await?;
        let size = response
            .content_length
            .unwrap_or(response.body.len() as u64);
        if size > RESPONSE_MAX_BYTES as u64 {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_RESPONSE_TOO_LARGE,
            ));
        }
        Ok(ObjectBody::new(
            response.body,
            observation(&response.headers)?,
        ))
    }

    async fn audit_object_request(
        &self,
        method: Method,
        key: &InventoryKey,
    ) -> Result<HttpResponse, StorageError> {
        if self.inner.authority != Authority::AuditRestore
            || !key.as_str().starts_with(self.inner.prefix.as_ref())
            || key.as_str().split('/').nth(1) != Some(self.inner.tenant.as_ref())
        {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        let bucket = if key.as_str().contains("/v1/control/") {
            self.inner
                .alternate_bucket
                .as_deref()
                .ok_or_else(unavailable_error)?
        } else {
            self.inner.bucket.as_ref()
        };
        let response = self
            .request_on_bucket(bucket, method, key.as_str(), "", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Err(unavailable_error());
        }
        if response.status.is_success() {
            Ok(response)
        } else {
            Err(status_error(response.status))
        }
    }
}

impl CatalogWriteBackend for S3RequestBackend {
    async fn put_catalog_object(
        &self,
        key: &CatalogCheckpointKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.scoped_put(Authority::CatalogWrite, key.as_str(), bytes)
            .await
    }

    async fn list_catalog_objects(
        &self,
        prefix: &CatalogListPrefix,
    ) -> Result<Vec<String>, StorageError> {
        self.list_scoped(Authority::CatalogWrite, prefix.as_str())
            .await
    }
}

impl DerivedWriteBackend for S3RequestBackend {
    async fn put_derived_object(
        &self,
        key: &DerivedObjectKey,
        bytes: &[u8],
    ) -> Result<(), StorageError> {
        self.scoped_put(Authority::DerivedWrite, key.as_str(), bytes)
            .await
    }

    async fn list_derived_objects(
        &self,
        prefix: &DerivedListPrefix,
    ) -> Result<Vec<String>, StorageError> {
        self.list_scoped(Authority::DerivedWrite, prefix.as_str())
            .await
    }
}

impl RawWriteBackend for S3RequestBackend {
    async fn put_raw_object(&self, key: &RawObjectKey, bytes: &[u8]) -> Result<(), StorageError> {
        let _ = self.raw_put(key, bytes, false).await?;
        Ok(())
    }

    async fn create_raw_object_if_absent(
        &self,
        key: &RawObjectKey,
        bytes: &[u8],
    ) -> Result<CreateIfAbsent, StorageError> {
        self.raw_put(key, bytes, true).await
    }

    async fn create_multipart(&self, key: &RawObjectKey) -> Result<String, StorageError> {
        self.create_multipart_request(key).await
    }

    async fn upload_part(
        &self,
        key: &RawObjectKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        self.upload_part_request(key, session, part, bytes).await
    }

    async fn complete_multipart(
        &self,
        key: &RawObjectKey,
        session: &str,
        parts: &[PartCommitment],
    ) -> Result<(), StorageError> {
        self.complete_multipart_request(key, session, parts).await
    }

    async fn abort_multipart(&self, key: &RawObjectKey, session: &str) -> Result<(), StorageError> {
        self.abort_multipart_request(key, session).await
    }
}

impl ControlReadBackend for S3RequestBackend {
    async fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<ObjectBody>, StorageError> {
        let Some(response) = self.control_get(key).await? else {
            return Ok(None);
        };
        let size = response
            .content_length
            .unwrap_or(response.body.len() as u64);
        if size > RESPONSE_MAX_BYTES as u64 {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_RESPONSE_TOO_LARGE,
            ));
        }
        let observation = observation(&response.headers)?;
        Ok(Some(ObjectBody::new(response.body, observation)))
    }

    async fn head_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<ObjectMetadata>, StorageError> {
        let Some(response) = self.control_head(key).await? else {
            return Ok(None);
        };
        let size = response
            .content_length
            .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
        if size > RESPONSE_MAX_BYTES as u64 {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_RESPONSE_TOO_LARGE,
            ));
        }
        let observation = observation(&response.headers)?;
        Ok(Some(ObjectMetadata::new(size, observation)))
    }
}

impl ControlAdminBackend for S3RequestBackend {
    async fn get_control_object(
        &self,
        key: &ControlObjectKey,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.admin_get(key).await
    }

    async fn put_control_object(
        &self,
        key: &ControlObjectKey,
        envelope: &[u8],
    ) -> Result<(), StorageError> {
        self.admin_put(key, envelope).await
    }
}

impl ProbeWriteBackend for S3RequestBackend {
    async fn write_probe_if_absent(
        &self,
        key: &ProbeKey,
        bytes: &[u8],
    ) -> Result<ProbeReceipt, StorageError> {
        check_probe_scope(&self.inner, key)?;
        let response = self
            .request(Method::PUT, key.as_str(), "", bytes, true)
            .await?;
        if response.status == StatusCode::PRECONDITION_FAILED {
            return Ok(probe_receipt(false, &response.headers));
        }
        if response.status.is_success() {
            return Ok(probe_receipt(true, &response.headers));
        }
        Err(status_error(response.status))
    }

    async fn read_probe_object(
        &self,
        key: &ProbeKey,
    ) -> Result<Option<ProbeObjectObservation>, StorageError> {
        check_probe_scope(&self.inner, key)?;
        let response = self
            .request(Method::HEAD, key.as_str(), "", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        let size = response
            .content_length
            .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
        Ok(Some(ProbeObjectObservation::new(
            size,
            header_text(&response.headers, "x-amz-version-id"),
            header_text(&response.headers, ETAG.as_str()),
            response
                .headers
                .contains_key("x-amz-server-side-encryption"),
        )))
    }

    async fn bucket_versioning(&self) -> Result<Option<VersioningObservation>, StorageError> {
        let response = self
            .request(Method::GET, "", "versioning=", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND
            || response.status == StatusCode::NOT_IMPLEMENTED
        {
            return Ok(None);
        }
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        let text = std::str::from_utf8(&response.body)
            .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
        Ok(Some(match extract_xml_value(text.as_bytes(), "Status") {
            Some("Enabled") => VersioningObservation::Enabled,
            _ => VersioningObservation::Disabled,
        }))
    }

    async fn bucket_encryption(&self) -> Result<bool, StorageError> {
        let response = self
            .request(Method::GET, "", "encryption=", &[], false)
            .await?;
        if response.status == StatusCode::NOT_FOUND
            || response.status == StatusCode::NOT_IMPLEMENTED
        {
            return Ok(false);
        }
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        let text = std::str::from_utf8(&response.body)
            .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
        Ok(extract_xml_value(text.as_bytes(), "ServerSideEncryptionConfiguration").is_some())
    }

    async fn create_probe_multipart(&self, key: &ProbeKey) -> Result<String, StorageError> {
        check_probe_scope(&self.inner, key)?;
        let response = self
            .request(Method::POST, key.as_str(), "uploads=", &[], false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        extract_xml_value(&response.body, "UploadId")
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .map(str::to_owned)
            .ok_or_else(|| StorageError::new(StorageErrorKind::Unavailable, DETAIL_UPLOAD_ID))
    }

    async fn upload_probe_part(
        &self,
        key: &ProbeKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> Result<String, StorageError> {
        check_probe_scope(&self.inner, key)?;
        let query = format!("partNumber={}&uploadId={}", part, encode_component(session));
        let response = self
            .request(Method::PUT, key.as_str(), &query, bytes, false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        response
            .headers
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| ObjectTag::parse(value).ok())
            .map(|tag| tag.to_string())
            .ok_or_else(|| StorageError::new(StorageErrorKind::Unavailable, DETAIL_ETAG))
    }

    async fn complete_probe_multipart(
        &self,
        key: &ProbeKey,
        session: &str,
        parts: &[PartCommitment],
    ) -> Result<(), StorageError> {
        check_probe_scope(&self.inner, key)?;
        let payload = complete_document(parts)?;
        let query = format!("uploadId={}", encode_component(session));
        let response = self
            .request(Method::POST, key.as_str(), &query, &payload, false)
            .await?;
        if response.status.is_success() {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }

    async fn abort_probe_multipart(
        &self,
        key: &ProbeKey,
        session: &str,
    ) -> Result<(), StorageError> {
        check_probe_scope(&self.inner, key)?;
        let query = format!("uploadId={}", encode_component(session));
        let response = self
            .request(Method::DELETE, key.as_str(), &query, &[], false)
            .await?;
        if response.status.is_success() || response.status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(status_error(response.status))
        }
    }
}

impl VersionAuditBackend for S3RequestBackend {
    async fn list_object_versions(
        &self,
        scope: &InventoryScope,
        after: Option<&ContinuationToken>,
    ) -> Result<VersionedPage, StorageError> {
        if self.inner.authority != Authority::VersionAudit {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        let scope_tenant = match scope {
            InventoryScope::TenantRaw(tenant)
            | InventoryScope::TenantControl(tenant)
            | InventoryScope::TenantCatalog(tenant)
            | InventoryScope::TenantDerived(tenant) => tenant.as_str(),
        };
        if scope_tenant != self.inner.tenant.as_ref() {
            return Err(StorageError::new(
                StorageErrorKind::ScopeViolation,
                DETAIL_SCOPE,
            ));
        }
        // The control bucket is the one reserved namespace on its own
        // bucket; catalog and derived share the raw bucket's namespace
        // (plan Section 7.5), so the audit identity lists them there.
        let bucket = match scope {
            InventoryScope::TenantRaw(_)
            | InventoryScope::TenantCatalog(_)
            | InventoryScope::TenantDerived(_) => self.inner.bucket.as_ref(),
            InventoryScope::TenantControl(_) => self
                .inner
                .alternate_bucket
                .as_deref()
                .ok_or_else(unavailable_error)?,
        };
        let prefix = scope.prefix();
        let mut query = format!(
            "versions=&prefix={}&max-keys={}",
            encode_component(&prefix),
            VERSIONS_PAGE_KEYS
        );
        if let Some(token) = after {
            let (key_marker, version_marker) = decode_markers(token.as_str())?;
            query.push_str("&key-marker=");
            query.push_str(&encode_component(&key_marker));
            query.push_str("&version-id-marker=");
            query.push_str(&encode_component(&version_marker));
        }
        let response = self
            .request_on_bucket(bucket, Method::GET, "", &query, &[], false)
            .await?;
        if !response.status.is_success() {
            return Err(status_error(response.status));
        }
        let (_, observed_at) = request_clock()?;
        parse_versions_page(&response.body, &observed_at)
    }
}

/// A bounded response after the body has been drained.
struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Vec<u8>,
    content_length: Option<u64>,
}

/// The header `name`'s text, when present and UTF-8.
fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// Assemble one probe write receipt from a response's headers.
fn probe_receipt(created: bool, headers: &HeaderMap) -> ProbeReceipt {
    ProbeReceipt::new(
        created,
        header_text(headers, "x-amz-version-id"),
        header_text(headers, ETAG.as_str()),
        headers.contains_key("x-amz-server-side-encryption"),
    )
}

/// The probe namespace scope check: the key's tenant segment must be the
/// composed tenant, and the key must sit under the composed probe prefix.
/// The derived [`ProbeKey`] grammar guarantees the shape; this re-check is
/// the boundary that keeps a composition mistake from aiming the probe
/// instrument at content.
fn check_probe_scope(inner: &BackendInner, key: &ProbeKey) -> Result<(), StorageError> {
    let tenant = key.as_str().split('/').nth(1).unwrap_or_default();
    if inner.authority != Authority::ProbeWrite
        || inner.tenant.as_ref() != tenant
        || !key.as_str().starts_with(inner.prefix.as_ref())
    {
        return Err(StorageError::new(
            StorageErrorKind::ScopeViolation,
            DETAIL_SCOPE,
        ));
    }
    Ok(())
}

/// Decode one versions-continuation token into its two markers. The token
/// is `percent-encoded-key ":" percent-encoded-version`; the encoded key
/// never carries a literal colon, so the first colon splits the pair.
fn decode_markers(token: &str) -> Result<(String, String), StorageError> {
    let malformed =
        || StorageError::new(StorageErrorKind::MalformedInput, DETAIL_VERSIONS_RESPONSE);
    let (key, version) = token.split_once(':').ok_or_else(malformed)?;
    Ok((
        decode_component(key).ok_or_else(malformed)?,
        decode_component(version).ok_or_else(malformed)?,
    ))
}

/// Percent-decode one marker component. Inverse of [`encode_component`]
/// for the ASCII repertoire the components carry; a malformed escape is a
/// malformed token, never a partially decoded marker.
fn decode_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex_value(*bytes.get(index + 1)?)?;
            let low = hex_value(*bytes.get(index + 2)?)?;
            output.push(high * 16 + low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

/// One hexadecimal digit's value.
const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Every `<element>` block's inner text, in document order. The listing
/// parser's walker: the same string discipline as [`extract_xml_value`],
/// repeated, so no XML crate enters the dependency tree.
fn xml_blocks<'a>(text: &'a str, element: &str) -> Vec<&'a str> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let mut blocks = Vec::new();
    let mut cursor = 0;
    while let Some(found) = text[cursor..].find(&open) {
        let start = cursor + found + open.len();
        let Some(end_offset) = text[start..].find(&close) else {
            break;
        };
        blocks.push(&text[start..start + end_offset]);
        cursor = start + end_offset + close.len();
    }
    blocks
}

/// Parse one versions-listing page: the `<Version>` entries and the
/// truncation markers the freeze paginator follows.
///
/// A version the backend did not name — an object stored before
/// versioning was ever enabled — parses under the null-version sentinel,
/// so the freeze can group and currency-check it like any other version.
/// `<DeleteMarker>` blocks are skipped: they are deletion records, not
/// stored versions, and the run's prefixes hold no deletions.
fn parse_versions_page(
    body: &[u8],
    observed_at: &Timestamp,
) -> Result<VersionedPage, StorageError> {
    let malformed =
        || StorageError::new(StorageErrorKind::MalformedInput, DETAIL_VERSIONS_RESPONSE);
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let mut entries = Vec::new();
    for block in xml_blocks(text, "Version") {
        let key_text = extract_xml_value(block.as_bytes(), "Key").ok_or_else(malformed)?;
        let size_text = extract_xml_value(block.as_bytes(), "Size").ok_or_else(malformed)?;
        let size = size_text.parse::<u64>().map_err(|_| malformed())?;
        let version_text =
            extract_xml_value(block.as_bytes(), "VersionId").unwrap_or(NULL_VERSION_SENTINEL);
        let latest =
            extract_xml_value(block.as_bytes(), "IsLatest").is_some_and(|value| value == "true");
        let key = InventoryKey::parse(key_text).map_err(|_| malformed())?;
        let version = StorageVersionId::parse(version_text).map_err(|_| malformed())?;
        let etag = extract_xml_value(block.as_bytes(), "ETag")
            .and_then(|value| ObjectTag::parse(value).ok());
        let observation = Observation::new(etag, Some(version.clone()), observed_at.clone());
        entries.push(VersionedEntry::new(key, size, version, latest, observation));
    }
    let truncated =
        extract_xml_value(text.as_bytes(), "IsTruncated").is_some_and(|value| value == "true");
    let next = if truncated {
        let key_marker =
            extract_xml_value(text.as_bytes(), "NextKeyMarker").ok_or_else(malformed)?;
        let version_marker = extract_xml_value(text.as_bytes(), "NextVersionIdMarker")
            .unwrap_or(NULL_VERSION_SENTINEL);
        let token_text = format!(
            "{}:{}",
            encode_component(key_marker),
            encode_component(version_marker)
        );
        Some(ContinuationToken::parse(&token_text).map_err(|_| malformed())?)
    } else {
        None
    };
    Ok(VersionedPage::new(entries, next))
}

/// Parse one bounded `ListObjectsV2` response into the shared inventory page
/// contract. The object listing is deliberately converted to opaque
/// `InventoryEntry` values here; typed raw/catalog/derived consumers perform
/// their own key-family validation after the audit identity has frozen it.
fn parse_inventory_page(
    body: &[u8],
    observed_at: &Timestamp,
) -> Result<InventoryPage, StorageError> {
    let malformed = || StorageError::new(StorageErrorKind::MalformedInput, DETAIL_LIST_RESPONSE);
    let text = std::str::from_utf8(body).map_err(|_| malformed())?;
    let mut entries = Vec::new();
    for block in xml_blocks(text, "Contents") {
        let key_text = extract_xml_value(block.as_bytes(), "Key").ok_or_else(malformed)?;
        let key = InventoryKey::parse(key_text).map_err(|_| malformed())?;
        let size = extract_xml_value(block.as_bytes(), "Size")
            .ok_or_else(malformed)?
            .parse::<u64>()
            .map_err(|_| malformed())?;
        let etag = extract_xml_value(block.as_bytes(), "ETag")
            .and_then(|value| ObjectTag::parse(value).ok());
        let version = extract_xml_value(block.as_bytes(), "VersionId")
            .map(StorageVersionId::parse)
            .transpose()
            .map_err(|_| malformed())?;
        entries.push(InventoryEntry::new(
            key,
            size,
            Observation::new(etag, version, observed_at.clone()),
        ));
    }
    let truncated =
        extract_xml_value(text.as_bytes(), "IsTruncated").is_some_and(|value| value == "true");
    let next = if truncated {
        let token =
            extract_xml_value(text.as_bytes(), "NextContinuationToken").ok_or_else(malformed)?;
        Some(ContinuationToken::parse(token).map_err(|_| malformed())?)
    } else {
        None
    };
    Ok(InventoryPage::new(entries, next))
}

fn credential_error(error: CredentialResolutionError) -> S3RequestError {
    match error {
        CredentialResolutionError::Unavailable => S3RequestError::new(
            S3RequestErrorKind::CredentialUnavailable,
            DETAIL_CREDENTIALS_UNAVAILABLE,
        ),
        CredentialResolutionError::Malformed => S3RequestError::new(
            S3RequestErrorKind::CredentialMalformed,
            DETAIL_CREDENTIALS_MALFORMED,
        ),
    }
}

fn storage_request_error() -> StorageError {
    StorageError::new(StorageErrorKind::Unavailable, DETAIL_REQUEST)
}

fn unavailable_error() -> StorageError {
    StorageError::new(StorageErrorKind::Unavailable, DETAIL_UNAVAILABLE)
}

fn status_error(status: StatusCode) -> StorageError {
    if status == StatusCode::FORBIDDEN {
        StorageError::new(StorageErrorKind::ScopeViolation, DETAIL_SCOPE)
    } else {
        unavailable_error()
    }
}

fn header_value(value: &str) -> Result<HeaderValue, StorageError> {
    HeaderValue::from_str(value).map_err(|_| storage_request_error())
}

fn parse_content_length(value: &HeaderValue) -> Result<u64, StorageError> {
    value
        .to_str()
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))
}

fn signing_headers<'a>(
    authority: &'a str,
    payload_hash: &'a str,
    amz_date: &'a str,
    conditional: bool,
) -> Vec<(&'a str, &'a str)> {
    let mut headers = vec![
        ("host", authority),
        ("x-amz-content-sha256", payload_hash),
        ("x-amz-date", amz_date),
    ];
    if conditional {
        headers.push(("if-none-match", "*"));
    }
    headers
}

fn request_path(base_path: &str, bucket: &str, key: &str) -> String {
    let mut path = String::with_capacity(base_path.len() + bucket.len() + key.len() + 2);
    if !base_path.is_empty() {
        path.push_str(&encode_path(base_path));
    }
    path.push('/');
    path.push_str(&encode_component(bucket));
    for segment in key.split('/') {
        path.push('/');
        path.push_str(&encode_component(segment));
    }
    path
}

fn encode_path(path: &str) -> String {
    path.split('/')
        .map(encode_component)
        .collect::<Vec<_>>()
        .join("/")
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
    }
    encoded
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'A' + value - 10) as char,
        _ => '?',
    }
}

fn complete_document(parts: &[PartCommitment]) -> Result<Vec<u8>, StorageError> {
    let mut document = String::from("<CompleteMultipartUpload>");
    for part in parts {
        document.push_str("<Part><PartNumber>");
        document.push_str(&part.number().to_string());
        document.push_str("</PartNumber><ETag>");
        append_xml_escaped(&mut document, part.tag().as_str());
        document.push_str("</ETag></Part>");
        if document.len() > COMPLETE_XML_MAX_BYTES {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_COMPLETE_BOUNDS,
            ));
        }
    }
    document.push_str("</CompleteMultipartUpload>");
    if document.len() > COMPLETE_XML_MAX_BYTES {
        return Err(StorageError::new(
            StorageErrorKind::MalformedInput,
            DETAIL_COMPLETE_BOUNDS,
        ));
    }
    Ok(document.into_bytes())
}

fn append_xml_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
}

fn extract_xml_value<'a>(body: &'a [u8], element: &str) -> Option<&'a str> {
    let open = format!("<{element}>");
    let close = format!("</{element}>");
    let text = std::str::from_utf8(body).ok()?;
    let start = text.find(&open)? + open.len();
    let end = text[start..].find(&close)? + start;
    let value = &text[start..end];
    if value.bytes().all(|byte| (0x21..=0x7e).contains(&byte)) {
        Some(value)
    } else {
        None
    }
}

fn observation(headers: &HeaderMap) -> Result<Observation, StorageError> {
    let etag = headers
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(ObjectTag::parse)
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
    let version = headers
        .get("x-amz-version-id")
        .and_then(|value| value.to_str().ok())
        .map(StorageVersionId::parse)
        .transpose()
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
    let (_, timestamp) = request_clock()?;
    Ok(Observation::new(etag, version, timestamp))
}

fn request_clock() -> Result<(String, Timestamp), StorageError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| unavailable_error())?
        .as_secs();
    let (year, month, day, hour, minute, second) =
        civil_time(seconds).ok_or_else(unavailable_error)?;
    let amz_date = format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z");
    let timestamp_text =
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    let timestamp = Timestamp::parse(&timestamp_text)
        .map_err(|_| StorageError::new(StorageErrorKind::MalformedInput, DETAIL_RESPONSE))?;
    Ok((amz_date, timestamp))
}

/// Convert Unix seconds to UTC calendar fields using the proleptic Gregorian
/// calendar. The request signer needs no clock dependency beyond `std`.
fn civil_time(seconds: u64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let day_seconds = i64::try_from(seconds % 86_400).ok()?;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_part = (5 * doy + 2) / 153;
    let day = doy - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    Some((year, month, day, hour, minute, second))
}

async fn read_bounded(mut body: Incoming, limit: usize) -> Result<Vec<u8>, StorageError> {
    let mut output = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| unavailable_error())?;
        let Ok(mut data) = frame.into_data() else {
            continue;
        };
        if data.remaining() > limit.saturating_sub(output.len()) {
            return Err(StorageError::new(
                StorageErrorKind::MalformedInput,
                DETAIL_RESPONSE_TOO_LARGE,
            ));
        }
        output.extend_from_slice(data.chunk());
        data.advance(data.remaining());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;

    use archivist_protocol::vocabulary::ClientId;

    use super::{ControlReadBackend, S3RequestBackend};
    use crate::config::{ControlReadConfig, Tls};
    use crate::control_admin::ControlObjectKey;

    const TENANT: &str = "1a2b3c4d-5e6f-4a1b-9c2d-3e4f5a6b7c8d";
    const CLIENT: &str = "0f1e2d3c-4b5a-4968-8776-5544332211ff";

    fn credential_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "archivist-s3-request-credentials-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"ACCESS_KEY=test-access\nSECRET_KEY=test-secret\n")
            .expect("write test credential file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .expect("restrict test credential file");
        }
        path
    }

    #[test]
    fn control_get_and_head_use_the_bounded_http_binding() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test endpoint");
        let address = listener.local_addr().expect("endpoint address");
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().expect("accept request");
                let mut request = [0u8; 8192];
                let size = stream.read(&mut request).expect("read request");
                let text = std::str::from_utf8(&request[..size]).expect("request text");
                assert!(
                    text.to_ascii_lowercase()
                        .contains("authorization: aws4-hmac-sha256")
                );
                assert!(text.contains("/control-bucket/tenants/"));
                if text.starts_with("GET ") {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nETag: \"tag\"\r\n\
                             x-amz-version-id: version-1\r\nConnection: close\r\n\r\nabc",
                        )
                        .expect("write GET response");
                } else {
                    assert!(text.starts_with("HEAD "));
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nETag: \"tag\"\r\n\
                             x-amz-version-id: version-1\r\nConnection: close\r\n\r\n",
                        )
                        .expect("write HEAD response");
                }
            }
        });

        let credential_path = credential_file();
        let config = ControlReadConfig::builder()
            .endpoint_url(format!("http://{address}"))
            .tls(Tls::Disabled)
            .region("us-east-1")
            .control_bucket("control-bucket")
            .tenant(TENANT)
            .control_read_credentials(format!("file:{}", credential_path.display()))
            .build()
            .expect("test configuration");
        let backend = S3RequestBackend::control_read(&config).expect("compose backend");
        let tenant = TENANT.parse().expect("tenant");
        let client = CLIENT.parse::<ClientId>().expect("client");
        let key = ControlObjectKey::linked_client(&tenant, &client);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let body = backend
                .get_control_object(&key)
                .await
                .expect("GET")
                .expect("object exists");
            assert_eq!(body.bytes(), b"abc");
            assert_eq!(body.observation().etag().unwrap().as_str(), "\"tag\"");
            assert_eq!(
                body.observation().storage_version().unwrap().as_str(),
                "version-1"
            );
            let metadata = backend
                .head_control_object(&key)
                .await
                .expect("HEAD")
                .expect("object exists");
            assert_eq!(metadata.size(), 3);
        });
        server.join().expect("server");
        std::fs::remove_file(credential_path).expect("remove test credential file");
    }

    #[test]
    fn request_path_preserves_key_segments_and_encodes_reserved_bytes() {
        assert_eq!(
            super::request_path("/gateway", "bucket", "tenants/t/v1/raw/a+b.json"),
            "/gateway/bucket/tenants/t/v1/raw/a%2Bb.json"
        );
    }
}
