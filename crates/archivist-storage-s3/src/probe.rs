// SPDX-License-Identifier: Apache-2.0

//! The S3 capability probe: [`S3ProbeSource`], the live
//! [`CapabilitySource`] over the probe authority's write-shaped
//! instrument, and the [`ProbeWriteBackend`] seam the instrument rides.
//!
//! The probe is the qualification run's first leg: it observes what a
//! backend actually supports and reduces each fact fail-closed onto the
//! capability model, so the write-path suite that follows it can declare
//! the capabilities the run actually saw. The instruments here are the
//! ones the probe model's own documentation pins — a conditional
//! create-if-absent pair, a stored-bytes read-back, the bucket's
//! versioning and encryption configuration surfaces, and one
//! begin/write/commit/abort session the probe owns end to end — and every
//! write-shaped one aims only at a [`ProbeKey`] in the reserved
//! `tenants/<tenant>/v1/probe/` namespace, which one lifecycle rule can
//! expire without touching tenant content.
//!
//! # Fail-closed reduction
//!
//! Every fact an instrument could not establish reports the weakest value
//! the model has, with the reason the transcript cites: an unreachable
//! backend is [`ProbeUnavailable`](UnprovenReason::ProbeUnavailable), an
//! instrument the backend refused (or answered dishonestly — a
//! "conditional" create that overwrote, a versioning configuration the
//! writes contradicted) is [`BackendRefused`](UnprovenReason::BackendRefused),
//! and a configuration surface the backend does not expose is
//! [`MethodUnsupported`](UnprovenReason::MethodUnsupported). There is no
//! input shape that turns an unestablished fact into a stronger claim.

use std::future::Future;

use archivist_protocol::vocabulary::TenantId;
use archivist_storage::error::{StorageError, StorageErrorKind};
use archivist_storage::metadata::ObjectTag;
use archivist_storage::probe::{
    CapabilitySource, ChecksumForm, ProbeFindings, ProbeKey, ProbeMethod, UnprovenReason,
    VersioningObservation,
};
use archivist_storage::raw_write::{PartCommitment, PartNumber};

/// What one probe write observed: the outcome the conditional primitive
/// reported, plus the response headers a probe instrument reads for the
/// versioning, checksum, and encryption corroborations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeReceipt {
    created: bool,
    version_id: Option<String>,
    etag: Option<String>,
    encrypted: bool,
}

impl ProbeReceipt {
    /// A receipt the binding assembles from one write's response headers.
    #[must_use]
    pub fn new(
        created: bool,
        version_id: Option<String>,
        etag: Option<String>,
        encrypted: bool,
    ) -> Self {
        Self {
            created,
            version_id,
            etag,
            encrypted,
        }
    }

    /// Whether the write created the object (as opposed to reporting an
    /// existing one).
    #[must_use]
    pub const fn created(&self) -> bool {
        self.created
    }

    /// The version identity the backend echoed, when it echoed one.
    #[must_use]
    pub fn version_id(&self) -> Option<&str> {
        self.version_id.as_deref()
    }

    /// The commitment tag the backend echoed, when it echoed one.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Whether the backend reported the write landing under its server-
    /// side encryption policy.
    #[must_use]
    pub const fn encrypted(&self) -> bool {
        self.encrypted
    }
}

/// What one probe read-back observed about a stored probe object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeObjectObservation {
    size: u64,
    version_id: Option<String>,
    etag: Option<String>,
    encrypted: bool,
}

impl ProbeObjectObservation {
    /// An observation the binding assembles from one read's response.
    #[must_use]
    pub fn new(
        size: u64,
        version_id: Option<String>,
        etag: Option<String>,
        encrypted: bool,
    ) -> Self {
        Self {
            size,
            version_id,
            etag,
            encrypted,
        }
    }

    /// The stored byte count the backend reported.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// The version identity the backend reported, when it reports one.
    #[must_use]
    pub fn version_id(&self) -> Option<&str> {
        self.version_id.as_deref()
    }

    /// The commitment tag the backend reported, when it reports one.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
    }

    /// Whether the backend reported the object at rest under its server-
    /// side encryption policy.
    #[must_use]
    pub const fn encrypted(&self) -> bool {
        self.encrypted
    }
}

/// The request seam of the probe identity: the write-shaped instrument,
/// the two read-backs, and the bucket configuration surfaces the probe's
/// five facts are established with — over the reserved probe namespace
/// and nothing else.
///
/// Deliberately narrower than an S3 client: every write, read, and
/// multipart session is keyed by a derived [`ProbeKey`], and the only
/// bucket-level calls are the two read-only configuration surfaces the
/// bucket facts come from. There is no delete, no arbitrary-key method,
/// and no tenant-prefix write to call — the probe never touches content.
/// A concrete binding enforces the deployment's backend policy (the
/// probe namespace, plus versioning and encryption reads on the raw
/// bucket, deny every other prefix); the mock in this module's tests
/// mirrors that denial so the probe's requests are proven to stay inside
/// it.
pub trait ProbeWriteBackend {
    /// Create the object at one probe key if — and only if — the key is
    /// absent, atomically.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn write_probe_if_absent(
        &self,
        key: &ProbeKey,
        bytes: &[u8],
    ) -> impl Future<Output = Result<ProbeReceipt, StorageError>> + Send;

    /// Read one probe key's stored evidence (size, tag, version identity,
    /// encryption) — the read-back the checksum and encryption facts
    /// observe. `Ok(None)` when the key holds nothing.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn read_probe_object(
        &self,
        key: &ProbeKey,
    ) -> impl Future<Output = Result<Option<ProbeObjectObservation>, StorageError>> + Send;

    /// Read the raw bucket's versioning configuration. `Ok(None)` means
    /// the backend exposes no versioning surface — a distinct answer from
    /// "versioning is disabled", and an unproven fact either way.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn bucket_versioning(
        &self,
    ) -> impl Future<Output = Result<Option<VersioningObservation>, StorageError>> + Send;

    /// Read the raw bucket's at-rest encryption configuration: `true`
    /// when a policy is configured, `false` when the backend exposes no
    /// such configuration.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down.
    fn bucket_encryption(&self) -> impl Future<Output = Result<bool, StorageError>> + Send;

    /// Begin one multipart session at a probe key.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn create_probe_multipart(
        &self,
        key: &ProbeKey,
    ) -> impl Future<Output = Result<String, StorageError>> + Send;

    /// Upload one part into a probe session.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn upload_probe_part(
        &self,
        key: &ProbeKey,
        session: &str,
        part: PartNumber,
        bytes: &[u8],
    ) -> impl Future<Output = Result<String, StorageError>> + Send;

    /// Complete a probe session.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn complete_probe_multipart(
        &self,
        key: &ProbeKey,
        session: &str,
        parts: &[PartCommitment],
    ) -> impl Future<Output = Result<(), StorageError>> + Send;

    /// Abort a probe session. Aborting a completed or already-aborted
    /// session reports success — cleanup is idempotent.
    ///
    /// # Errors
    /// [`StorageErrorKind::Unavailable`](archivist_storage::error::StorageErrorKind::Unavailable)
    /// when the backend or network is down;
    /// [`StorageErrorKind::ScopeViolation`](archivist_storage::error::StorageErrorKind::ScopeViolation)
    /// when the key is outside the probe namespace.
    fn abort_probe_multipart(
        &self,
        key: &ProbeKey,
        session: &str,
    ) -> impl Future<Output = Result<(), StorageError>> + Send;
}

/// The reserved probe labels the live source instruments, one per fact.
const CONDITIONAL_LABEL: &str = "conditional-create";
const MULTIPART_LABEL: &str = "multipart-session";
const CONDITIONAL_BYTES: &[u8] = b"archivist-probe-conditional";
const MULTIPART_BYTES: &[u8] = b"archivist-probe-part";

/// The live [`CapabilitySource`] over one backend's probe instrument.
///
/// The source drives the instruments in the order the report binds them —
/// the conditional-create pair first (its receipts feed the versioning,
/// checksum, and encryption corroborations), then the bucket
/// configuration reads, then the multipart session — and reduces every
/// outcome fail-closed onto [`ProbeFindings`]. Total by contract: a run
/// that could establish nothing still yields an honest report.
pub struct S3ProbeSource<I> {
    instrument: I,
    tenant: TenantId,
}

impl<I> S3ProbeSource<I> {
    /// Compose the live probe source over one instrument and the tenant
    /// whose probe namespace the instruments aim at.
    #[must_use]
    pub fn new(instrument: I, tenant: TenantId) -> Self {
        Self { instrument, tenant }
    }
}

impl<I: ProbeWriteBackend + Sync> CapabilitySource for S3ProbeSource<I> {
    #[allow(clippy::too_many_lines)] // one instrument per block, read top to bottom
    async fn probe(&self) -> ProbeFindings {
        let (Ok(conditional_key), Ok(multipart_key)) = (
            ProbeKey::new(&self.tenant, CONDITIONAL_LABEL),
            ProbeKey::new(&self.tenant, MULTIPART_LABEL),
        ) else {
            // Unreachable for a parsed tenant: both labels are inside the
            // probe-key grammar. An unprobed report is the honest output
            // if that invariant ever drifts.
            return ProbeFindings::unprobed();
        };

        let mut findings = ProbeFindings::unprobed();

        // Conditional create, established by the two-step pair: the first
        // write must create, the second must report the existing object.
        // A first write that reports "exists" means the probe namespace
        // was not purged — the instrument cannot distinguish a stale key
        // from a concurrent writer, so the fact stays unproven. A second
        // write that reports "created" proves the primitive is not
        // actually conditional, and is refused as dishonest rather than
        // trusted.
        let first = self
            .instrument
            .write_probe_if_absent(&conditional_key, CONDITIONAL_BYTES)
            .await;
        findings.conditional_create = match &first {
            Err(_) => Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::ProbeUnavailable),
            Ok(first) if !first.created() => {
                Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::BackendRefused)
            }
            Ok(_) => {
                let second = self
                    .instrument
                    .write_probe_if_absent(&conditional_key, CONDITIONAL_BYTES)
                    .await;
                match second {
                    Ok(receipt) if !receipt.created() => {
                        Fact::established(ProbeMethod::ProbeKeyWrite, ())
                    }
                    _ => Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::BackendRefused),
                }
            }
        };

        // The stored-checksum form, observed on the bytes the first write
        // stored: the read-back's tag is the form the backend maintains.
        let stored = self.instrument.read_probe_object(&conditional_key).await;
        findings.stored_checksum = match &stored {
            Err(_) => Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::ProbeUnavailable),
            Ok(None) => Fact::unproven(ProbeMethod::ProbeKeyWrite, UnprovenReason::BackendRefused),
            Ok(Some(observation)) => match classify_checksum(observation.etag()) {
                Some(form) => Fact::established(ProbeMethod::ProbeKeyWrite, form),
                None => Fact::unproven(
                    ProbeMethod::ProbeKeyWrite,
                    UnprovenReason::MethodUnsupported,
                ),
            },
        };

        // Versioning: the bucket configuration surface, corroborated by
        // the writes' version-id echoes. A configuration the writes
        // contradict is refused — the honest answer for a backend whose
        // configuration and behavior disagree is unproven, never either
        // claim.
        let echoed_versions = first
            .as_ref()
            .ok()
            .is_some_and(|receipt| receipt.version_id().is_some())
            || stored.as_ref().ok().is_some_and(|read| {
                read.as_ref()
                    .is_some_and(|observation| observation.version_id().is_some())
            });
        findings.versioning = match self.instrument.bucket_versioning().await {
            Err(_) => Fact::unproven(
                ProbeMethod::BucketConfiguration,
                UnprovenReason::ProbeUnavailable,
            ),
            Ok(None) => Fact::unproven(
                ProbeMethod::BucketConfiguration,
                UnprovenReason::MethodUnsupported,
            ),
            // A configuration the writes corroborate establishes the axis;
            // one the writes contradict is refused — the honest answer for
            // a backend whose configuration and behavior disagree is
            // unproven, never either claim.
            Ok(Some(observation)) => {
                let corroborated = match observation {
                    VersioningObservation::Enabled => echoed_versions,
                    VersioningObservation::Disabled => !echoed_versions,
                };
                if corroborated {
                    Fact::established(ProbeMethod::BucketConfiguration, observation)
                } else {
                    Fact::unproven(
                        ProbeMethod::BucketConfiguration,
                        UnprovenReason::BackendRefused,
                    )
                }
            }
        };

        // Server-side encryption: a configured policy observed taking
        // effect on a probe write. Configured-but-never-observed is
        // refused, and a backend with no configuration surface never
        // claims encryption.
        let observed_encrypted = first.as_ref().ok().is_some_and(ProbeReceipt::encrypted)
            || stored
                .as_ref()
                .ok()
                .is_some_and(|read| read.as_ref().is_some_and(ProbeObjectObservation::encrypted));
        findings.server_side_encryption = match self.instrument.bucket_encryption().await {
            Err(_) => Fact::unproven(
                ProbeMethod::BucketConfiguration,
                UnprovenReason::ProbeUnavailable,
            ),
            Ok(false) => Fact::unproven(
                ProbeMethod::BucketConfiguration,
                UnprovenReason::MethodUnsupported,
            ),
            Ok(true) if observed_encrypted => {
                Fact::established(ProbeMethod::BucketConfiguration, ())
            }
            Ok(true) => Fact::unproven(
                ProbeMethod::BucketConfiguration,
                UnprovenReason::BackendRefused,
            ),
        };

        // Multipart commit/abort, the profile-support fact: one full
        // begin/write/commit/abort session the probe owns. The trailing
        // abort of a completed session is cleanup and must report
        // success — the same idempotence the write path's cancellation
        // safety depends on.
        findings.multipart_commit_abort =
            match self.instrument.create_probe_multipart(&multipart_key).await {
                Err(_) => Fact::unproven(
                    ProbeMethod::MultipartSession,
                    UnprovenReason::BackendRefused,
                ),
                Ok(session) => {
                    let part =
                        PartNumber::new(1).expect("part number 1 is inside the trait's bounds");
                    let session_run = async {
                        let tag = self
                            .instrument
                            .upload_probe_part(&multipart_key, &session, part, MULTIPART_BYTES)
                            .await?;
                        // The part's returned tag is the commitment the
                        // completion document cites; a tag outside the object
                        // tag grammar is not a session this source may complete.
                        let tag = ObjectTag::parse(&tag)
                            .map_err(|_| StorageError::of_kind(StorageErrorKind::Unavailable))?;
                        self.instrument
                            .complete_probe_multipart(
                                &multipart_key,
                                &session,
                                &[PartCommitment::new(part, tag)],
                            )
                            .await?;
                        self.instrument
                            .abort_probe_multipart(&multipart_key, &session)
                            .await
                    }
                    .await;
                    match session_run {
                        Ok(()) => Fact::established(ProbeMethod::MultipartSession, ()),
                        Err(_) => Fact::unproven(
                            ProbeMethod::MultipartSession,
                            UnprovenReason::BackendRefused,
                        ),
                    }
                }
            };

        findings
    }
}

use archivist_storage::probe::Fact;

/// Classify a stored commitment tag into the checksum form it evidences.
///
/// The tag is observed, never assumed: a 32-hex form is the MD5-derived
/// form, a 64-hex form is a SHA-256 form, and anything else — a
/// multipart-suffix tag, a prefixed or opaque provider tag — is the
/// provider's own form. A missing tag is no evidence at all.
#[must_use]
pub fn classify_checksum(etag: Option<&str>) -> Option<ChecksumForm> {
    let unquoted = etag?.trim_matches('"');
    match unquoted.len() {
        64 if unquoted.bytes().all(|b| b.is_ascii_hexdigit()) => Some(ChecksumForm::Sha256),
        32 if unquoted.bytes().all(|b| b.is_ascii_hexdigit()) => Some(ChecksumForm::Md5),
        0 => None,
        _ => Some(ChecksumForm::ProviderSpecific),
    }
}
