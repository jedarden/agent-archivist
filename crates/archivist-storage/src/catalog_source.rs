// SPDX-License-Identifier: Apache-2.0

//! The raw catalog source reader: deterministic, validating iteration over
//! one tenant's raw prefix — occurrence manifests, upload attestations, and
//! their referenced blobs — through the offline
//! [`AuditRestoreStore`](crate::audit_restore::AuditRestoreStore) identity
//! (plan Phase 10, `archivist catalog rebuild --from-occurrences`; plan
//! Section 7.7).
//!
//! # The reader grants nothing
//!
//! This module holds no credentials and widens no trait surface. It is
//! constructed from a frozen `inventory-v1`
//! ([`FrozenInventory`](crate::audit_restore::FrozenInventory)) plus an
//! audit/restore store, so being able to build it implies the enumeration
//! and bounded-read authority [`AuditRestoreStore`](crate::audit_restore::AuditRestoreStore)
//! already gates. The ingest composition ([`crate::ingest::IngestStorage`])
//! binds only [`RawWriteStore`](crate::raw_write::RawWriteStore) and
//! [`ControlReadStore`](crate::control::ControlReadStore) — it has no path
//! to this module or to the trait behind it — and no default consumer owns
//! an audit/restore identity at all. Raw bytes exist only inside a process
//! that already holds the offline authority the plan names for rebuild,
//! restore, and reference scans (plan Section 5, Section 7.7).
//!
//! # Validation is fail closed
//!
//! Every raw object is validated before it is exposed:
//!
//! - **Schema** — the document is canonical JSON, names exactly the
//!   schema's required members at their wire types, and declares the v1
//!   major version; unknown majors fail closed (plan Section 7.1).
//!   Additive unknown members are ignored, the old-reader/new-writer
//!   compatibility rule.
//! - **Provenance** — the self-verifying identities are re-derived from
//!   each document's own fields (STO-011): `session_hash`, `artifact_hash`,
//!   and `occurrence_id` for an occurrence; `attestation_id` for an
//!   attestation. A declaration that disagrees with its own inputs is a
//!   fabricated-provenance object (threat PI-07).
//! - **Key coupling** — the document is held at the key its identity
//!   derives; anything else is an incompatible object at a deterministic
//!   key (plan Section 7.11 `EC-06`).
//! - **Reference integrity** — an occurrence's referenced blob must be
//!   present in the frozen inventory, and every attestation must name an
//!   occurrence present in it. A stored blob is further checked against the
//!   `zstd-v1` profile's frame-header contract (content size declared,
//!   content checksum enabled, no dictionary — plan Section 7.6); the
//!   checksum-verified decode itself belongs to the restore path, which owns
//!   the decoder dependency.
//!
//! Any violation, and any listed object that no longer reads, fails the
//! whole source closed — the consumer re-freezes and restarts, and never
//! rebuilds a catalog over a divergent prefix. Faults are deterministic: an
//! identical prefix faults identically, so a rebuild that passed at one
//! commit reproduces at the next.
//!
//! # Deterministic ordering
//!
//! [`RawCatalogSource`] yields one [`OccurrenceRecord`] per occurrence in
//! the frozen inventory's canonical key-byte order, each carrying its
//! attestations in key-byte order and its referenced blob — the order the
//! Phase 10 exit gate's byte-identical rebuilds consume (plan Section 7.7:
//! canonical order is opaque key-byte order).
//!
//! # Memory shape
//!
//! The document pass ([`RawCatalogSource::open`]) reads every occurrence and
//! attestation manifest — bounded documents, the same scale the freeze
//! already holds as key entries — and validates them before any payload
//! moves. [`RawCatalogSource::next_occurrence`] then streams one
//! occurrence's stored blob at a time through the audit/restore identity's
//! owned-byte [`read`](crate::audit_restore::AuditRestoreStore::read_object)
//! contract; a deployment's own size bounds apply, exactly as for any other
//! offline restore read.

use std::collections::{HashMap, HashSet, VecDeque};

use archivist_protocol::derivation;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::object_key::{AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey};
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactHash, ArtifactKind, AttestationId, BlobDigest, ClientId, GenerationId,
    GrammarError, HarnessId, IdSource, OccurrenceId, OpaqueId, RangeKind, RequestId, SessionHash,
    StorageProfile, TenantId, Timestamp, VersionToken,
};

use crate::audit_restore::{AuditRestoreStore, FrozenInventory, InventoryKey, ObjectBody};
use crate::collection::OccurrenceReference;
use crate::error::{StorageError, StorageErrorKind};
use crate::manifests::Delegation;

// ---- The content-safe fault details (static by construction; the error
// type cannot carry keys, tenants, or document text). ----

/// The inventory scope is not a tenant raw prefix.
const RAW_SCOPE_ONLY: &str = "the raw catalog source reads a tenant raw inventory only";
/// An enumerated raw key is none of the three raw object grammars.
const UNRECOGNIZED_RAW_OBJECT: &str =
    "the raw prefix holds an object outside the raw object grammars";
/// An object the frozen inventory lists failed its read.
const LISTED_UNREADABLE: &str =
    "an inventory-listed object could not be read; re-freeze the inventory";

/// The stored occurrence manifest is not canonical JSON.
const OCC_MALFORMED: &str = "stored occurrence manifest is malformed canonical JSON";
/// The stored occurrence manifest is not a JSON object.
const OCC_NOT_OBJECT: &str = "stored occurrence manifest is not a JSON object";
/// The stored occurrence manifest lacks a schema-required member.
const OCC_MISSING_MEMBER: &str = "stored occurrence manifest is missing a required member";
/// A stored occurrence manifest member is present at the wrong JSON type.
const OCC_MEMBER_TYPE: &str = "stored occurrence manifest has a member of the wrong JSON type";
/// A stored occurrence manifest member is outside its wire grammar.
const OCC_MEMBER_GRAMMAR: &str = "stored occurrence manifest has a member outside its wire grammar";
/// The stored occurrence manifest declares an unsupported schema major.
const OCC_UNSUPPORTED_VERSION: &str =
    "stored occurrence manifest declares an unsupported occurrence_version";
/// The stored occurrence manifest's range is empty in the wrong direction.
const OCC_RANGE_ORDER: &str = "stored occurrence manifest range_end precedes range_start";
/// The stored occurrence manifest's optional source time is not a real instant.
const OCC_SOURCE_TIME_CALENDAR: &str =
    "stored occurrence manifest source_time is not a calendar-valid instant";
/// The declared session hash disagrees with the re-derivation.
const OCC_SESSION_MISMATCH: &str =
    "stored occurrence manifest session_hash disagrees with its re-derivation";
/// The declared artifact hash disagrees with the re-derivation.
const OCC_ARTIFACT_MISMATCH: &str =
    "stored occurrence manifest artifact_hash disagrees with its re-derivation";
/// The declared occurrence identity disagrees with the re-derivation.
const OCC_ID_MISMATCH: &str =
    "stored occurrence manifest occurrence_id disagrees with its re-derivation";
/// The manifest is held at a key its validated identity does not derive.
const OCC_FOREIGN_KEY: &str =
    "stored occurrence manifest is held at a key its identity does not derive";
/// The occurrence's blob is not in the frozen inventory.
const OCC_BLOB_ABSENT: &str = "an occurrence references a blob absent from the frozen inventory";

/// The stored attestation is not canonical JSON.
const ATT_MALFORMED: &str = "stored upload attestation is malformed canonical JSON";
/// The stored attestation is not a JSON object.
const ATT_NOT_OBJECT: &str = "stored upload attestation is not a JSON object";
/// The stored attestation lacks a schema-required member.
const ATT_MISSING_MEMBER: &str = "stored upload attestation is missing a required member";
/// A stored attestation member is present at the wrong JSON type.
const ATT_MEMBER_TYPE: &str = "stored upload attestation has a member of the wrong JSON type";
/// A stored attestation member is outside its wire grammar.
const ATT_MEMBER_GRAMMAR: &str = "stored upload attestation has a member outside its wire grammar";
/// The stored attestation declares an unsupported schema major.
const ATT_UNSUPPORTED_VERSION: &str =
    "stored upload attestation declares an unsupported attestation_version";
/// A stored attestation timestamp is not a real instant.
const ATT_TIMESTAMP_CALENDAR: &str =
    "stored upload attestation timestamp is not a calendar-valid instant";
/// The delegation relation contradicts the two client ids.
const ATT_DELEGATION_INCONSISTENT: &str =
    "stored upload attestation delegation relation contradicts its uploader and origin clients";
/// The declared attestation identity disagrees with the re-derivation.
const ATT_ID_MISMATCH: &str =
    "stored upload attestation attestation_id disagrees with its re-derivation";
/// The attestation is held at a key its validated identity does not derive.
const ATT_FOREIGN_KEY: &str =
    "stored upload attestation is held at a key its identity does not derive";
/// An attestation names an occurrence the frozen inventory does not hold.
const ATT_ORPHAN: &str = "an attestation names an occurrence absent from the frozen inventory";

/// The stored bytes are not a zstd frame.
const BLOB_NOT_FRAME: &str = "a referenced blob is not a zstd-v1 frame";
/// The frame header ends before its declared fields do.
const BLOB_TRUNCATED_HEADER: &str = "a referenced blob zstd-v1 frame header is truncated";
/// The frame header sets the reserved descriptor bit.
const BLOB_RESERVED_FLAG: &str = "a referenced blob zstd-v1 frame header uses a reserved flag bit";
/// The frame names a dictionary; the profile pins none.
const BLOB_DICTIONARY: &str = "a referenced blob zstd-v1 frame declares a dictionary";
/// The frame omits the content checksum; the profile pins it enabled.
const BLOB_NO_CHECKSUM: &str = "a referenced blob zstd-v1 frame omits the content checksum";
/// The frame declares no content size; the profile pins it present.
const BLOB_NO_CONTENT_SIZE: &str = "a referenced blob zstd-v1 frame declares no frame content size";

/// Re-derive an occurrence's self-verifying identity from its own fields
/// and require each declared hash to agree (STO-011): a declaration that
/// disagrees with its inputs is a fabricated-provenance object (PI-07).
#[allow(clippy::too_many_arguments)]
fn verify_occurrence_provenance(
    tenant_id: &TenantId,
    origin_client_id: &ClientId,
    harness: &HarnessId,
    upstream_session_id: &str,
    declared_session: &SessionHash,
    artifact_kind: ArtifactKind,
    adapter_id: &AdapterId,
    adapter_projection_version: &VersionToken,
    adapter_artifact_id: &str,
    declared_artifact: &ArtifactHash,
    generation: &GenerationId,
    range_kind: RangeKind,
    range_start: u64,
    range_end: u64,
    blob_digest: &BlobDigest,
    declared_occurrence: &OccurrenceId,
) -> Result<(SessionHash, ArtifactHash, OccurrenceId), StorageError> {
    let session =
        derivation::session_hash(tenant_id, origin_client_id, harness, upstream_session_id);
    if session != *declared_session {
        return Err(fault(OCC_SESSION_MISMATCH));
    }
    let artifact = derivation::artifact_hash(
        &session,
        artifact_kind,
        adapter_id,
        adapter_projection_version,
        adapter_artifact_id,
    );
    if artifact != *declared_artifact {
        return Err(fault(OCC_ARTIFACT_MISMATCH));
    }
    let occurrence = derivation::occurrence_id(
        &session,
        &artifact,
        generation,
        range_kind,
        range_start,
        range_end,
        blob_digest,
    );
    if occurrence != *declared_occurrence {
        return Err(fault(OCC_ID_MISMATCH));
    }
    Ok((session, artifact, occurrence))
}

/// The one supported schema major, checked before any member is read.
fn require_v1(
    object: &Object,
    version_member: &str,
    unsupported: &'static str,
    missing: &'static str,
) -> Result<(), StorageError> {
    match object.get(version_member) {
        Some(Value::Int(1)) => Ok(()),
        Some(_) => Err(fault(unsupported)),
        None => Err(fault(missing)),
    }
}

/// Build the reader's fault: every reader-detected violation is an
/// integrity conflict at a deterministic key (plan Section 7.11 `EC-06`),
/// carried with its static content-safe detail.
fn fault(detail: &'static str) -> StorageError {
    StorageError::new(StorageErrorKind::IntegrityConflict, detail)
}

/// The declared uncompressed byte count of one stored blob, read from its
/// `zstd-v1` frame header (plan Section 7.6: content size and checksum
/// enabled, no dictionary).
///
/// This is header validation, not a decode: the frame's blocks and trailing
/// XXH64 checksum are verified when the restore path decompresses, the one
/// place the decoder dependency lives. What the header pins offline is the
/// profile's recoverable provenance — the uncompressed size the manifest
/// deliberately does not duplicate, the mandatory content checksum, and the
/// absence of a dictionary.
///
/// # Errors
/// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
/// when the bytes do not open with a conforming `zstd-v1` frame header.
fn zstd_v1_frame_content_size(bytes: &[u8]) -> Result<u64, StorageError> {
    const MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
    let header = bytes
        .strip_prefix(&MAGIC[..])
        .ok_or_else(|| fault(BLOB_NOT_FRAME))?;
    let (&descriptor, header) = header
        .split_first()
        .ok_or_else(|| fault(BLOB_TRUNCATED_HEADER))?;
    if descriptor & 0b0000_1000 != 0 {
        return Err(fault(BLOB_RESERVED_FLAG));
    }
    if descriptor & 0b0000_0011 != 0 {
        return Err(fault(BLOB_DICTIONARY));
    }
    if descriptor & 0b0000_0100 == 0 {
        return Err(fault(BLOB_NO_CHECKSUM));
    }
    let single_segment = descriptor & 0b0010_0000 != 0;
    let fcs_field: usize = match descriptor >> 6 {
        0 if single_segment => 1,
        0 => return Err(fault(BLOB_NO_CONTENT_SIZE)),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    // The Window_Descriptor is present exactly when the frame is not
    // single-segment (RFC 8878); it carries no profile fact, so it is
    // skipped without interpretation.
    let header = if single_segment {
        header
    } else {
        header
            .split_first()
            .ok_or_else(|| fault(BLOB_TRUNCATED_HEADER))?
            .1
    };
    if header.len() < fcs_field {
        return Err(fault(BLOB_TRUNCATED_HEADER));
    }
    let mut raw = [0u8; 8];
    raw[..fcs_field].copy_from_slice(&header[..fcs_field]);
    let declared = u64::from_le_bytes(raw);
    // The 2-byte form encodes size - 256 (RFC 8878).
    if fcs_field == 2 {
        return Ok(declared + 256);
    }
    Ok(declared)
}

/// One tenant's frozen raw prefix, classified against the three raw object
/// grammars.
///
/// Built from a [`FrozenInventory`] of
/// [`InventoryScope::TenantRaw`](crate::audit_restore::InventoryScope::TenantRaw);
/// each key must parse as an occurrence, attestation, or blob object key,
/// and anything else fails closed. The classified lists keep the freeze's
/// canonical key-byte order, which is what makes every consumer of this
/// type deterministic.
#[derive(Clone, Debug)]
pub struct RawCatalogIndex {
    tenant: TenantId,
    occurrences: Vec<OccurrenceObjectKey>,
    attestations: Vec<AttestationObjectKey>,
    blobs: Vec<BlobObjectKey>,
    blob_keys: HashSet<String>,
}

impl RawCatalogIndex {
    /// Classify a frozen tenant raw inventory.
    ///
    /// # Errors
    /// [`StorageErrorKind::MalformedInput`](crate::error::StorageErrorKind)
    /// when the inventory froze a scope other than the tenant raw prefix,
    /// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
    /// when any raw key parses as none of the three raw object grammars.
    pub fn new(inventory: &FrozenInventory) -> Result<Self, StorageError> {
        let tenant = match inventory.scope() {
            crate::audit_restore::InventoryScope::TenantRaw(tenant) => tenant.clone(),
            crate::audit_restore::InventoryScope::TenantControl(_) => {
                return Err(StorageError::new(
                    StorageErrorKind::MalformedInput,
                    RAW_SCOPE_ONLY,
                ));
            }
        };
        let mut occurrences = Vec::new();
        let mut attestations = Vec::new();
        let mut blobs = Vec::new();
        let mut blob_keys = HashSet::new();
        for entry in inventory.entries() {
            let key = entry.key().as_str();
            if let Ok(parsed) = OccurrenceObjectKey::parse(key) {
                occurrences.push(parsed);
            } else if let Ok(parsed) = AttestationObjectKey::parse(key) {
                attestations.push(parsed);
            } else if let Ok(parsed) = BlobObjectKey::parse(key) {
                blob_keys.insert(parsed.as_str().to_owned());
                blobs.push(parsed);
            } else {
                return Err(fault(UNRECOGNIZED_RAW_OBJECT));
            }
        }
        Ok(Self {
            tenant,
            occurrences,
            attestations,
            blobs,
            blob_keys,
        })
    }

    /// The tenant whose raw prefix this index classifies.
    #[must_use]
    pub const fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The occurrence-manifest keys, in canonical key-byte order.
    #[must_use]
    pub fn occurrences(&self) -> &[OccurrenceObjectKey] {
        &self.occurrences
    }

    /// The upload-attestation keys, in canonical key-byte order.
    #[must_use]
    pub fn attestations(&self) -> &[AttestationObjectKey] {
        &self.attestations
    }

    /// The stored blob keys, in canonical key-byte order — every blob in
    /// the prefix, including any not yet referenced by an occurrence that
    /// survived its commit (plan Section 7.10's reference scan consumes
    /// this list).
    #[must_use]
    pub fn blobs(&self) -> &[BlobObjectKey] {
        &self.blobs
    }

    /// Whether `key` is a blob this inventory froze.
    fn holds_blob(&self, key: &BlobObjectKey) -> bool {
        self.blob_keys.contains(key.as_str())
    }
}

/// One validated occurrence manifest as stored: the schema's canonical
/// members at their wire types, with every self-verifying identity
/// re-derived and the storage key re-checked (STO-011, `EC-06`).
#[derive(Clone, Debug)]
pub struct OccurrenceManifest {
    key: OccurrenceObjectKey,
    tenant_id: TenantId,
    origin_client_id: ClientId,
    harness: HarnessId,
    upstream_session_id: OpaqueId,
    id_source: IdSource,
    session_hash: SessionHash,
    artifact_kind: ArtifactKind,
    adapter_id: AdapterId,
    adapter_projection_version: VersionToken,
    adapter_artifact_id: OpaqueId,
    artifact_hash: ArtifactHash,
    generation: GenerationId,
    range_kind: RangeKind,
    range_start: u64,
    range_end: u64,
    blob_digest: BlobDigest,
    storage_profile: StorageProfile,
    occurrence_id: OccurrenceId,
    source_time: Option<Timestamp>,
}

impl OccurrenceManifest {
    /// Validate the stored bytes of one occurrence manifest against its
    /// storage key and the frozen blob set.
    ///
    /// The order is deliberate: schema shape first, then wire grammar per
    /// member, then the self-verifying re-derivations, then the key
    /// coupling, then the referenced blob's presence in the frozen
    /// inventory — so a fabricated object is named by the shallowest
    /// applicable fault (PI-07).
    ///
    /// Crate-visible for the authorized exporter
    /// ([`crate::export`](crate::export)), which resolves one selected
    /// occurrence's blob reference through the same validation — at the
    /// manifest's single read — rather than duplicating it.
    ///
    /// # Errors
    /// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
    /// for every fault the module documents.
    pub(crate) fn validate(
        bytes: &[u8],
        key: &OccurrenceObjectKey,
        blobs: &RawCatalogIndex,
    ) -> Result<(Self, BlobObjectKey), StorageError> {
        let value = json::parse(bytes).map_err(|_| fault(OCC_MALFORMED))?;
        let Value::Object(object) = &value else {
            return Err(fault(OCC_NOT_OBJECT));
        };
        require_v1(
            object,
            "occurrence_version",
            OCC_UNSUPPORTED_VERSION,
            OCC_MISSING_MEMBER,
        )?;
        let tenant_id = occurrence_member(object, "tenant_id", TenantId::parse)?;
        let origin_client_id = occurrence_member(object, "origin_client_id", ClientId::parse)?;
        let harness = occurrence_member(object, "harness", HarnessId::parse)?;
        let upstream_session_id =
            occurrence_member(object, "upstream_session_id", OpaqueId::parse)?;
        let id_source = occurrence_member(object, "id_source", IdSource::parse)?;
        let session_hash = occurrence_member(object, "session_hash", SessionHash::parse)?;
        let artifact_kind = occurrence_member(object, "artifact_kind", ArtifactKind::parse)?;
        let adapter_id = occurrence_member(object, "adapter_id", AdapterId::parse)?;
        let adapter_projection_version =
            occurrence_member(object, "adapter_projection_version", VersionToken::parse)?;
        let adapter_artifact_id =
            occurrence_member(object, "adapter_artifact_id", OpaqueId::parse)?;
        let artifact_hash = occurrence_member(object, "artifact_hash", ArtifactHash::parse)?;
        let generation = occurrence_member(object, "generation", GenerationId::parse)?;
        let range_kind = occurrence_member(object, "range_kind", RangeKind::parse)?;
        let blob_digest = occurrence_member(object, "blob_digest", BlobDigest::parse)?;
        let storage_profile = occurrence_member(object, "storage_profile", StorageProfile::parse)?;
        let occurrence_id = occurrence_member(object, "occurrence_id", OccurrenceId::parse)?;
        let range_start = int_member(object, "range_start")?;
        let range_end = int_member(object, "range_end")?;
        if range_end < range_start {
            return Err(fault(OCC_RANGE_ORDER));
        }
        let source_time = optional_timestamp_member(
            object,
            "source_time",
            OCC_MEMBER_TYPE,
            OCC_MEMBER_GRAMMAR,
            OCC_SOURCE_TIME_CALENDAR,
        )?;

        // Provenance: the identity members re-derive from the document's
        // own fields, so the stored object verifies with nothing but
        // itself (STO-011).
        // The struct carries the declared artifact hash, now proven equal
        // to the re-derivation; the re-derived copy itself is not needed.
        let (session, _rederived_artifact, occurrence) = verify_occurrence_provenance(
            &tenant_id,
            &origin_client_id,
            &harness,
            upstream_session_id.as_str(),
            &session_hash,
            artifact_kind,
            &adapter_id,
            &adapter_projection_version,
            adapter_artifact_id.as_str(),
            &artifact_hash,
            &generation,
            range_kind,
            range_start,
            range_end,
            &blob_digest,
            &occurrence_id,
        )?;

        // Key coupling: the key is a pure function of the validated
        // identity, so a document anywhere else is an incompatible object
        // at that key (EC-06).
        let rebuilt = OccurrenceObjectKey::new(
            &tenant_id,
            &origin_client_id,
            &harness,
            &session,
            &occurrence,
        );
        if rebuilt.as_str() != key.as_str() {
            return Err(fault(OCC_FOREIGN_KEY));
        }

        // Reference integrity: the blob the occurrence names must be in
        // the frozen inventory, or the payload the catalog would rebuild
        // from is already divergent.
        let blob_key = BlobObjectKey::new(&tenant_id, storage_profile, &blob_digest);
        if !blobs.holds_blob(&blob_key) {
            return Err(fault(OCC_BLOB_ABSENT));
        }

        Ok((
            Self {
                key: key.clone(),
                tenant_id,
                origin_client_id,
                harness,
                upstream_session_id,
                id_source,
                session_hash,
                artifact_kind,
                adapter_id,
                adapter_projection_version,
                adapter_artifact_id,
                artifact_hash,
                generation,
                range_kind,
                range_start,
                range_end,
                blob_digest,
                storage_profile,
                occurrence_id,
                source_time,
            },
            blob_key,
        ))
    }

    /// The derived key the manifest is stored at.
    #[must_use]
    pub const fn key(&self) -> &OccurrenceObjectKey {
        &self.key
    }

    /// The tenant the occurrence belongs to.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The origin client that captured the source.
    #[must_use]
    pub const fn origin_client_id(&self) -> &ClientId {
        &self.origin_client_id
    }

    /// The harness the source came from.
    #[must_use]
    pub const fn harness(&self) -> &HarnessId {
        &self.harness
    }

    /// The harness's own session identifier.
    #[must_use]
    pub const fn upstream_session_id(&self) -> &OpaqueId {
        &self.upstream_session_id
    }

    /// Where the upstream session identifier came from.
    #[must_use]
    pub const fn id_source(&self) -> IdSource {
        self.id_source
    }

    /// The re-derived session-namespace hash.
    #[must_use]
    pub const fn session_hash(&self) -> &SessionHash {
        &self.session_hash
    }

    /// The artifact kind.
    #[must_use]
    pub const fn artifact_kind(&self) -> ArtifactKind {
        self.artifact_kind
    }

    /// The adapter that projected the source.
    #[must_use]
    pub const fn adapter_id(&self) -> &AdapterId {
        &self.adapter_id
    }

    /// The adapter projection version.
    #[must_use]
    pub const fn adapter_projection_version(&self) -> &VersionToken {
        &self.adapter_projection_version
    }

    /// The adapter's own artifact identifier.
    #[must_use]
    pub const fn adapter_artifact_id(&self) -> &OpaqueId {
        &self.adapter_artifact_id
    }

    /// The re-derived artifact-namespace hash.
    #[must_use]
    pub const fn artifact_hash(&self) -> &ArtifactHash {
        &self.artifact_hash
    }

    /// The source generation.
    #[must_use]
    pub const fn generation(&self) -> &GenerationId {
        &self.generation
    }

    /// The range coordinate kind.
    #[must_use]
    pub const fn range_kind(&self) -> RangeKind {
        self.range_kind
    }

    /// The range start, in `range_kind` coordinates.
    #[must_use]
    pub const fn range_start(&self) -> u64 {
        self.range_start
    }

    /// The range end, in `range_kind` coordinates.
    #[must_use]
    pub const fn range_end(&self) -> u64 {
        self.range_end
    }

    /// The digest that names the referenced blob.
    #[must_use]
    pub const fn blob_digest(&self) -> &BlobDigest {
        &self.blob_digest
    }

    /// The storage profile the referenced blob is committed under.
    #[must_use]
    pub const fn storage_profile(&self) -> StorageProfile {
        self.storage_profile
    }

    /// The re-derived occurrence identity.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The source-encoded event time, when the source had one.
    #[must_use]
    pub const fn source_time(&self) -> Option<&Timestamp> {
        self.source_time.as_ref()
    }
}

/// One validated upload attestation as stored: who presented which frozen
/// request for which occurrence, with the identity re-derived and the
/// storage key re-checked (STO-013, `EC-06`).
#[derive(Clone, Debug)]
pub struct AttestationManifest {
    key: AttestationObjectKey,
    tenant_id: TenantId,
    occurrence_id: OccurrenceId,
    origin_client_id: ClientId,
    uploader_client_id: ClientId,
    request_id: RequestId,
    delegation: Delegation,
    capture_time: Timestamp,
    envelope_creation_time: Timestamp,
}

impl AttestationManifest {
    /// Validate the stored bytes of one upload attestation against its
    /// storage key.
    ///
    /// Crate-visible for the authorized exporter
    /// ([`crate::export`](crate::export)), which validates exactly the
    /// attestations joining a selected occurrence through the same rules,
    /// each at its single read.
    ///
    /// # Errors
    /// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
    /// for every fault the module documents.
    pub(crate) fn validate(bytes: &[u8], key: &AttestationObjectKey) -> Result<Self, StorageError> {
        let value = json::parse(bytes).map_err(|_| fault(ATT_MALFORMED))?;
        let Value::Object(object) = &value else {
            return Err(fault(ATT_NOT_OBJECT));
        };
        require_v1(
            object,
            "attestation_version",
            ATT_UNSUPPORTED_VERSION,
            ATT_MISSING_MEMBER,
        )?;
        let tenant_id = attestation_member(object, "tenant_id", TenantId::parse)?;
        let occurrence_id = attestation_member(object, "occurrence_id", OccurrenceId::parse)?;
        let origin_client_id = attestation_member(object, "origin_client_id", ClientId::parse)?;
        let uploader_client_id = attestation_member(object, "uploader_client_id", ClientId::parse)?;
        let request_id = attestation_member(object, "request_id", RequestId::parse)?;
        let delegation = delegation_member(object)?;
        let capture_time =
            required_timestamp_member(object, "capture_time", ATT_TIMESTAMP_CALENDAR)?;
        let envelope_creation_time =
            required_timestamp_member(object, "envelope_creation_time", ATT_TIMESTAMP_CALENDAR)?;
        let attestation_id = attestation_member(object, "attestation_id", AttestationId::parse)?;

        // The schema's consistency rule: `direct` means the uploader is
        // the origin; `relay` means an authorized third party presented
        // the frozen request (STO-013).
        let consistent = match delegation {
            Delegation::Direct => uploader_client_id == origin_client_id,
            Delegation::Relay => uploader_client_id != origin_client_id,
        };
        if !consistent {
            return Err(fault(ATT_DELEGATION_INCONSISTENT));
        }

        // Provenance: the attestation identity folds the occurrence, the
        // uploader, and the frozen request (STO-013).
        let rederived =
            derivation::attestation_id(&occurrence_id, &uploader_client_id, &request_id);
        if rederived != attestation_id {
            return Err(fault(ATT_ID_MISMATCH));
        }

        // Key coupling.
        let rebuilt = AttestationObjectKey::new(&tenant_id, &occurrence_id, &attestation_id);
        if rebuilt.as_str() != key.as_str() {
            return Err(fault(ATT_FOREIGN_KEY));
        }

        Ok(Self {
            key: key.clone(),
            tenant_id,
            occurrence_id,
            origin_client_id,
            uploader_client_id,
            request_id,
            delegation,
            capture_time,
            envelope_creation_time,
        })
    }

    /// The derived key the attestation is stored at.
    #[must_use]
    pub const fn key(&self) -> &AttestationObjectKey {
        &self.key
    }

    /// The tenant the occurrence belongs to.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The occurrence the frozen request presented.
    #[must_use]
    pub const fn occurrence_id(&self) -> &OccurrenceId {
        &self.occurrence_id
    }

    /// The origin client that captured the source.
    #[must_use]
    pub const fn origin_client_id(&self) -> &ClientId {
        &self.origin_client_id
    }

    /// The client that presented the frozen request.
    #[must_use]
    pub const fn uploader_client_id(&self) -> &ClientId {
        &self.uploader_client_id
    }

    /// The frozen upload-request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// How the uploader stands to the origin.
    #[must_use]
    pub const fn delegation(&self) -> Delegation {
        self.delegation
    }

    /// When the source event was discovered (wire text as stored).
    #[must_use]
    pub const fn capture_time(&self) -> &Timestamp {
        &self.capture_time
    }

    /// When the frozen envelope was built (wire text as stored).
    #[must_use]
    pub const fn envelope_creation_time(&self) -> &Timestamp {
        &self.envelope_creation_time
    }
}

/// One referenced blob as read and header-validated: the exact stored
/// bytes, the derived key, and the frame's declared uncompressed size.
///
/// The stored bytes are the `zstd-v1` frame; decompressing and verifying
/// the content digest and the frame's XXH64 checksum is the restore path's
/// decode step (the module documentation carries the boundary).
#[derive(Clone, Debug)]
pub struct ValidatedBlob {
    key: BlobObjectKey,
    declared_uncompressed_bytes: u64,
    stored: ObjectBody,
}

impl ValidatedBlob {
    /// The derived key the blob is stored at.
    #[must_use]
    pub const fn key(&self) -> &BlobObjectKey {
        &self.key
    }

    /// The uncompressed size the frame header declares — the size the
    /// manifest deliberately does not duplicate.
    #[must_use]
    pub const fn declared_uncompressed_bytes(&self) -> u64 {
        self.declared_uncompressed_bytes
    }

    /// The exact stored bytes and their observation evidence.
    #[must_use]
    pub const fn stored(&self) -> &ObjectBody {
        &self.stored
    }
}

/// One occurrence unit for a downstream rebuild: the validated manifest,
/// its validated attestations in key-byte order, and its referenced blob.
#[derive(Clone, Debug)]
pub struct OccurrenceRecord {
    manifest: OccurrenceManifest,
    attestations: Vec<AttestationManifest>,
    blob: ValidatedBlob,
}

impl OccurrenceRecord {
    /// The validated occurrence manifest.
    #[must_use]
    pub const fn manifest(&self) -> &OccurrenceManifest {
        &self.manifest
    }

    /// The occurrence's validated attestations, in key-byte order.
    #[must_use]
    pub fn attestations(&self) -> &[AttestationManifest] {
        &self.attestations
    }

    /// The referenced blob, read and header-validated.
    #[must_use]
    pub const fn blob(&self) -> &ValidatedBlob {
        &self.blob
    }
}

/// One occurrence validated and joined at open time, awaiting its payload
/// read.
#[derive(Debug)]
struct PreparedOccurrence {
    manifest: OccurrenceManifest,
    blob_key: BlobObjectKey,
    attestations: Vec<AttestationManifest>,
}

/// The raw catalog source: validating, deterministic iteration over one
/// tenant's frozen raw prefix.
///
/// Open against an audit/restore store and a [`RawCatalogIndex`]; the open
/// pass validates every document on the prefix (schemas, provenance, key
/// coupling, reference integrity), then [`RawCatalogSource::next_occurrence`]
/// streams one occurrence record at a time — its manifest, its attestations
/// in key order, and its referenced blob — in canonical key-byte order.
#[derive(Debug)]
pub struct RawCatalogSource {
    prepared: VecDeque<PreparedOccurrence>,
}

impl RawCatalogSource {
    /// Validate the prefix's documents and prepare the occurrence sequence.
    ///
    /// Reads every occurrence manifest and attestation through `store`'s
    /// audit/restore identity and validates each one; a source is only
    /// constructible over a prefix whose documents all verify.
    ///
    /// # Errors
    /// [`StorageErrorKind::InventoryFault`](crate::error::StorageErrorKind)
    /// when a listed object no longer reads (the freeze has diverged from
    /// the store; re-freeze),
    /// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
    /// for every document, provenance, key-coupling, and reference fault
    /// the module documents, and the store's own failures otherwise.
    pub async fn open<S>(store: &S, index: &RawCatalogIndex) -> Result<Self, StorageError>
    where
        S: AuditRestoreStore + ?Sized,
    {
        let mut prepared: Vec<PreparedOccurrence> = Vec::with_capacity(index.occurrences.len());
        let mut slots: HashMap<String, usize> = HashMap::with_capacity(index.occurrences.len());
        for key in index.occurrences() {
            let body = read_listed(store, key.as_str()).await?;
            let (manifest, blob_key) = OccurrenceManifest::validate(body.bytes(), key, index)?;
            slots.insert(manifest.occurrence_id().to_hex(), prepared.len());
            prepared.push(PreparedOccurrence {
                manifest,
                blob_key,
                attestations: Vec::new(),
            });
        }
        // Attestations join their occurrence through the occurrence
        // identity both the key and the document carry; the index's
        // key-byte order is preserved into each occurrence's list.
        for key in index.attestations() {
            let body = read_listed(store, key.as_str()).await?;
            let attestation = AttestationManifest::validate(body.bytes(), key)?;
            let slot = slots
                .get(&attestation.occurrence_id().to_hex())
                .ok_or_else(|| fault(ATT_ORPHAN))?;
            prepared[*slot].attestations.push(attestation);
        }
        Ok(Self {
            prepared: VecDeque::from(prepared),
        })
    }

    /// Yield the next occurrence record, in canonical key-byte order, or
    /// `None` when the prefix is exhausted.
    ///
    /// The record's blob is read here — one occurrence's stored bytes
    /// resident at a time — and header-validated against the `zstd-v1`
    /// profile before it is exposed.
    ///
    /// # Errors
    /// [`StorageErrorKind::InventoryFault`](crate::error::StorageErrorKind)
    /// when a listed object no longer reads (re-freeze),
    /// [`StorageErrorKind::IntegrityConflict`](crate::error::StorageErrorKind)
    /// when the stored blob is not a conforming `zstd-v1` frame, and the
    /// store's own failures otherwise.
    pub async fn next_occurrence<S>(
        &mut self,
        store: &S,
    ) -> Result<Option<OccurrenceRecord>, StorageError>
    where
        S: AuditRestoreStore + ?Sized,
    {
        let Some(prepared) = self.prepared.pop_front() else {
            return Ok(None);
        };
        let stored = read_listed(store, prepared.blob_key.as_str()).await?;
        let declared_uncompressed_bytes = zstd_v1_frame_content_size(stored.bytes())?;
        Ok(Some(OccurrenceRecord {
            manifest: prepared.manifest,
            attestations: prepared.attestations,
            blob: ValidatedBlob {
                key: prepared.blob_key,
                declared_uncompressed_bytes,
                stored,
            },
        }))
    }

    /// Advance past the next occurrence without reading its stored blob,
    /// returning the skipped occurrence's key, or `None` when exhausted.
    ///
    /// The catalog rebuild's resume path uses this to hold the canonical
    /// key-byte order across the occurrences a trusted earlier run
    /// already processed: their derived rows are content-addressed, so
    /// skipping the re-read changes no rebuilt byte and costs none of
    /// the payload traffic.
    #[must_use]
    pub fn skip_next(&mut self) -> Option<OccurrenceObjectKey> {
        let prepared = self.prepared.pop_front()?;
        Some(prepared.manifest.key().clone())
    }

    /// The number of occurrence records not yet yielded.
    #[must_use]
    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    /// Whether every record has been yielded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Return the validated occurrence-to-blob edges prepared by the source.
    ///
    /// The returned order is the same canonical occurrence-key order used by
    /// [`Self::next_occurrence`]. A caller building a two-pass collection
    /// scan can pass these edges to [`crate::collection::ReferenceScan`]
    /// without reading blob bodies a second time.
    #[must_use]
    pub fn references(&self) -> Vec<OccurrenceReference> {
        self.prepared
            .iter()
            .map(|prepared| {
                OccurrenceReference::new(
                    *prepared.manifest.occurrence_id(),
                    prepared.blob_key.clone(),
                )
            })
            .collect()
    }
}

/// Read one frozen-inventory object through the audit/restore identity.
///
/// A listed object that reports unavailable has diverged from the freeze
/// (deleted, rewritten, or an enumeration the freeze no longer describes);
/// the source fails closed as an inventory fault and the consumer
/// re-freezes, exactly as the freeze contract prescribes. Other store
/// errors pass through with their own kinds.
async fn read_listed<S>(store: &S, key: &str) -> Result<ObjectBody, StorageError>
where
    S: AuditRestoreStore + ?Sized,
{
    let listed = InventoryKey::parse(key)
        .map_err(|_| StorageError::of_kind(StorageErrorKind::MalformedInput))?;
    match store.read_object(&listed).await {
        Ok(body) => Ok(body),
        Err(error) if error.kind() == StorageErrorKind::Unavailable => Err(StorageError::new(
            StorageErrorKind::InventoryFault,
            LISTED_UNREADABLE,
        )),
        Err(error) => Err(error),
    }
}

/// Extract one occurrence-manifest string member at its wire grammar.
///
/// # Errors
/// The matching occurrence fault for a missing member, a non-string value,
/// or a grammar violation.
fn occurrence_member<T>(
    object: &Object,
    name: &str,
    parse: fn(&str) -> Result<T, GrammarError>,
) -> Result<T, StorageError> {
    grammar_member(
        object,
        name,
        parse,
        OCC_MISSING_MEMBER,
        OCC_MEMBER_TYPE,
        OCC_MEMBER_GRAMMAR,
    )
}

/// Extract one attestation string member at its wire grammar.
///
/// # Errors
/// The matching attestation fault for a missing member, a non-string
/// value, or a grammar violation.
fn attestation_member<T>(
    object: &Object,
    name: &str,
    parse: fn(&str) -> Result<T, GrammarError>,
) -> Result<T, StorageError> {
    grammar_member(
        object,
        name,
        parse,
        ATT_MISSING_MEMBER,
        ATT_MEMBER_TYPE,
        ATT_MEMBER_GRAMMAR,
    )
}

/// Extract one string member at its wire grammar.
///
/// # Errors
/// The passed static fault for a missing member, a non-string value, or a
/// grammar violation.
fn grammar_member<T>(
    object: &Object,
    name: &str,
    parse: fn(&str) -> Result<T, GrammarError>,
    missing: &'static str,
    typed: &'static str,
    malformed: &'static str,
) -> Result<T, StorageError> {
    match object.get(name) {
        None => Err(fault(missing)),
        Some(Value::Text(text)) => parse(text).map_err(|_| fault(malformed)),
        Some(_) => Err(fault(typed)),
    }
}

/// Extract one non-negative integer member (`u63`).
///
/// # Errors
/// The static fault for a missing member or a wrong-typed or negative
/// value.
fn int_member(object: &Object, name: &str) -> Result<u64, StorageError> {
    match object.get(name) {
        None => Err(fault(OCC_MISSING_MEMBER)),
        Some(Value::Int(value)) if *value >= 0 => {
            Ok(u64::try_from(*value).expect("guarded non-negative"))
        }
        Some(_) => Err(fault(OCC_MEMBER_TYPE)),
    }
}

/// Extract one optional timestamp member.
///
/// # Errors
/// The static faults for a wrong-typed value, a grammar violation, or a
/// non-calendar instant.
fn optional_timestamp_member(
    object: &Object,
    name: &str,
    typed: &'static str,
    malformed: &'static str,
    calendar: &'static str,
) -> Result<Option<Timestamp>, StorageError> {
    match object.get(name) {
        None => Ok(None),
        Some(Value::Text(text)) => {
            let stamp = Timestamp::parse(text).map_err(|_| fault(malformed))?;
            if !stamp.calendar_valid() {
                return Err(fault(calendar));
            }
            Ok(Some(stamp))
        }
        Some(_) => Err(fault(typed)),
    }
}

/// Extract one required timestamp member.
///
/// # Errors
/// The static faults for a missing member, a wrong-typed value, a grammar
/// violation, or a non-calendar instant.
fn required_timestamp_member(
    object: &Object,
    name: &str,
    calendar: &'static str,
) -> Result<Timestamp, StorageError> {
    match object.get(name) {
        None => Err(fault(ATT_MISSING_MEMBER)),
        Some(Value::Text(text)) => {
            let stamp = Timestamp::parse(text).map_err(|_| fault(ATT_MEMBER_GRAMMAR))?;
            if !stamp.calendar_valid() {
                return Err(fault(calendar));
            }
            Ok(stamp)
        }
        Some(_) => Err(fault(ATT_MEMBER_TYPE)),
    }
}

/// Extract the attestation's delegation relation, matching the storage
/// layer's own closed relation set.
///
/// # Errors
/// The static faults for a missing member, a wrong-typed value, or a
/// token outside the closed set.
fn delegation_member(object: &Object) -> Result<Delegation, StorageError> {
    match object.get("delegation") {
        None => Err(fault(ATT_MISSING_MEMBER)),
        Some(Value::Text(text)) => {
            if text == Delegation::Direct.token() {
                Ok(Delegation::Direct)
            } else if text == Delegation::Relay.token() {
                Ok(Delegation::Relay)
            } else {
                Err(fault(ATT_MEMBER_GRAMMAR))
            }
        }
        Some(_) => Err(fault(ATT_MEMBER_TYPE)),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use archivist_protocol::json::{self, Object, Value};
    use archivist_protocol::object_key::{
        AttestationObjectKey, BlobObjectKey, OccurrenceObjectKey,
    };
    use archivist_protocol::vocabulary::{
        AttestationId, BlobDigest, ClientId, HarnessId, OccurrenceId, SessionHash, StorageProfile,
        TenantId, Timestamp,
    };

    use super::super::audit_restore::{
        AuditRestoreStore, ContinuationToken, FrozenInventory, InventoryEntry, InventoryKey,
        InventoryPage, InventoryScope, ObjectBody, ObjectMetadata,
    };
    use super::super::error::{StorageError, StorageErrorKind};
    use super::super::metadata::Observation;
    use super::{RawCatalogIndex, RawCatalogSource, zstd_v1_frame_content_size};

    /// The conformance corpus's tenant.
    const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";
    /// When the fixtures were observed (arbitrary, fixture-only).
    const OBSERVED: &str = "2026-09-13T12:00:00Z";
    /// A grammar-valid digest that is not any fixture's value — the tamper
    /// target.
    const TAMPERED: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn observed_at() -> Timestamp {
        Timestamp::parse(OBSERVED).unwrap()
    }

    fn tenant() -> TenantId {
        TenantId::parse(TENANT).unwrap()
    }

    // ---- Fixtures from the committed provenance bundle ----

    /// One committed provenance-bundle document.
    fn bundle_doc(rel: &str) -> Vec<u8> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas/v1/examples/provenance");
        std::fs::read(root.join(rel))
            .unwrap_or_else(|e| panic!("committed bundle document {rel}: {e}"))
    }

    fn parsed(doc: &[u8]) -> Object {
        match json::parse(doc).expect("bundle document parses") {
            Value::Object(object) => object,
            _ => panic!("bundle document is an object"),
        }
    }

    fn text_of<'a>(object: &'a Object, name: &str) -> &'a str {
        match object.get(name) {
            Some(Value::Text(text)) => text,
            _ => panic!("bundle document member {name} is a string"),
        }
    }

    /// The bundle payload's byte count (the blob's declared content size).
    fn payload_len() -> u64 {
        let len = bundle_doc("payloads/shared-session-chunk.jsonl").len();
        u64::try_from(len).expect("fixture under u64")
    }

    /// Rebuild the derived occurrence key of one bundle occurrence.
    fn occurrence_key(doc: &[u8]) -> OccurrenceObjectKey {
        let object = parsed(doc);
        OccurrenceObjectKey::new(
            &tenant(),
            &ClientId::parse(text_of(&object, "origin_client_id")).unwrap(),
            &HarnessId::parse(text_of(&object, "harness")).unwrap(),
            &SessionHash::parse(text_of(&object, "session_hash")).unwrap(),
            &OccurrenceId::parse(text_of(&object, "occurrence_id")).unwrap(),
        )
    }

    /// Rebuild the derived attestation key of one bundle attestation.
    fn attestation_key(doc: &[u8]) -> AttestationObjectKey {
        let object = parsed(doc);
        AttestationObjectKey::new(
            &tenant(),
            &OccurrenceId::parse(text_of(&object, "occurrence_id")).unwrap(),
            &AttestationId::parse(text_of(&object, "attestation_id")).unwrap(),
        )
    }

    /// The shared blob's derived key and a conforming `zstd-v1` frame whose
    /// declared content size is the payload's length.
    fn blob_fixture() -> (BlobObjectKey, Vec<u8>) {
        let object = parsed(&bundle_doc(
            "occurrences/direct-upload-and-relay-source.json",
        ));
        let digest = BlobDigest::parse(text_of(&object, "blob_digest")).unwrap();
        let key = BlobObjectKey::new(&tenant(), StorageProfile::ZstdV1, &digest);
        (key, zstd_v1_frame(payload_len()))
    }

    /// The committed bundle: two occurrences sharing one blob, three
    /// attestations on the first and one on the second.
    struct Bundle {
        occurrence_keys: [OccurrenceObjectKey; 2],
        occurrences: [Vec<u8>; 2],
        attestation_keys: [AttestationObjectKey; 4],
        attestations: [Vec<u8>; 4],
        blob_key: BlobObjectKey,
        blob: Vec<u8>,
    }

    fn bundle() -> Bundle {
        let occurrence_a = bundle_doc("occurrences/direct-upload-and-relay-source.json");
        let occurrence_b = bundle_doc("occurrences/identical-bytes-second-origin.json");
        let attestation_a = bundle_doc("attestations/origin-direct-first-request.json");
        let attestation_b = bundle_doc("attestations/origin-direct-refrozen-request.json");
        let attestation_c = bundle_doc("attestations/relay-delegated-request.json");
        let attestation_d = bundle_doc("attestations/second-origin-direct-request.json");
        let (blob_key, blob) = blob_fixture();
        Bundle {
            occurrence_keys: [occurrence_key(&occurrence_a), occurrence_key(&occurrence_b)],
            occurrences: [occurrence_a, occurrence_b],
            attestation_keys: [
                attestation_key(&attestation_a),
                attestation_key(&attestation_b),
                attestation_key(&attestation_c),
                attestation_key(&attestation_d),
            ],
            attestations: [attestation_a, attestation_b, attestation_c, attestation_d],
            blob_key,
            blob,
        }
    }

    /// Apply the first `from`→`to` replacement to a canonical document.
    fn mutated(doc: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = std::str::from_utf8(doc).expect("utf-8 fixture");
        let mutated = text.replacen(from, to, 1);
        assert_ne!(mutated, text, "fixture mutation must apply");
        mutated.into_bytes()
    }

    // ---- Fixtures: store, inventory, frames ----

    /// A no-dependency in-memory audit/restore store, following the
    /// manifests-module mock pattern.
    struct MockStore {
        objects: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl MockStore {
        fn with(objects: &[(&str, Vec<u8>)]) -> Self {
            Self {
                objects: Mutex::new(
                    objects
                        .iter()
                        .map(|(key, bytes)| ((*key).to_owned(), bytes.clone()))
                        .collect(),
                ),
            }
        }
    }

    impl AuditRestoreStore for MockStore {
        async fn list_page(
            &self,
            _scope: &InventoryScope,
            _after: Option<&ContinuationToken>,
        ) -> Result<InventoryPage, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }

        async fn freeze_inventory(
            &self,
            _scope: &InventoryScope,
        ) -> Result<FrozenInventory, StorageError> {
            Err(StorageError::of_kind(StorageErrorKind::Unavailable))
        }

        async fn inspect_object(&self, key: &InventoryKey) -> Result<ObjectMetadata, StorageError> {
            let objects = self.objects.lock().expect("mock lock");
            match objects.get(key.as_str()) {
                Some(bytes) => Ok(ObjectMetadata::new(
                    bytes.len() as u64,
                    Observation::new(None, None, observed_at()),
                )),
                None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
            }
        }

        async fn read_object(&self, key: &InventoryKey) -> Result<ObjectBody, StorageError> {
            let objects = self.objects.lock().expect("mock lock");
            match objects.get(key.as_str()) {
                Some(bytes) => Ok(ObjectBody::new(
                    bytes.clone(),
                    Observation::new(None, None, observed_at()),
                )),
                None => Err(StorageError::of_kind(StorageErrorKind::Unavailable)),
            }
        }
    }

    /// Complete first-poll-until-ready, following the manifests-module
    /// pattern (every mock future completes without pending).
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        let mut future = std::pin::pin!(future);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            match future.as_mut().poll(&mut cx) {
                std::task::Poll::Ready(output) => return output,
                std::task::Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    fn entry(key: &str, size: u64) -> InventoryEntry {
        InventoryEntry::new(
            InventoryKey::parse(key).expect("grammatical fixture key"),
            size,
            Observation::new(None, None, observed_at()),
        )
    }

    /// Freeze `entries` across two pages in the given (arbitrary) order,
    /// exercising page-boundary independence through the real freeze
    /// contract.
    fn freeze(entries: &[(&str, u64)]) -> FrozenInventory {
        let scope = InventoryScope::TenantRaw(tenant());
        if entries.is_empty() {
            return FrozenInventory::from_pages(
                &scope,
                vec![Ok(InventoryPage::new(Vec::new(), None))],
            )
            .unwrap();
        }
        let mid = entries.len().div_ceil(2);
        let first: Vec<_> = entries[..mid].iter().map(|(k, s)| entry(k, *s)).collect();
        let second: Vec<_> = entries[mid..].iter().map(|(k, s)| entry(k, *s)).collect();
        FrozenInventory::from_pages(
            &scope,
            vec![
                Ok(InventoryPage::new(
                    first,
                    Some(ContinuationToken::parse("next-page").unwrap()),
                )),
                Ok(InventoryPage::new(second, None)),
            ],
        )
        .unwrap()
    }

    /// A conforming `zstd-v1` frame header: 8-byte content size form,
    /// checksum enabled, no dictionary, arbitrary unparsed body bytes.
    fn zstd_v1_frame(declared: u64) -> Vec<u8> {
        let mut bytes = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC4, 0x00]);
        bytes.extend_from_slice(&declared.to_le_bytes());
        bytes.extend_from_slice(b"frame body the reader never parses");
        bytes
    }

    /// The committed bundle's objects under their derived keys, blob
    /// listed first, in an arbitrary (non-canonical) listing order.
    fn bundle_inventory(b: &Bundle) -> FrozenInventory {
        let mut entries: Vec<(&str, u64)> = vec![(b.blob_key.as_str(), b.blob.len() as u64)];
        for (key, doc) in b.occurrence_keys.iter().zip(&b.occurrences) {
            entries.push((key.as_str(), doc.len() as u64));
        }
        for (key, doc) in b.attestation_keys.iter().zip(&b.attestations) {
            entries.push((key.as_str(), doc.len() as u64));
        }
        freeze(&entries)
    }

    /// The first occurrence's objects only: its blob, its manifest, and
    /// its three attestations, listed in an arbitrary order.
    fn single_occurrence_inventory(b: &Bundle) -> FrozenInventory {
        let mut entries: Vec<(&str, u64)> = vec![(b.blob_key.as_str(), b.blob.len() as u64)];
        entries.push((b.occurrence_keys[0].as_str(), b.occurrences[0].len() as u64));
        for (key, doc) in b.attestation_keys[..3].iter().zip(&b.attestations[..3]) {
            entries.push((key.as_str(), doc.len() as u64));
        }
        freeze(&entries)
    }

    /// Open the source over `store` and drain every record to a plain
    /// comparable tuple list.
    async fn drain(
        store: &MockStore,
        index: &RawCatalogIndex,
    ) -> Result<Vec<(String, String, Vec<String>, u64, String)>, StorageError> {
        let mut source = RawCatalogSource::open(store, index).await?;
        let mut drained = Vec::new();
        while let Some(record) = source.next_occurrence(store).await? {
            drained.push((
                record.manifest().key().as_str().to_owned(),
                record.manifest().occurrence_id().to_hex(),
                record
                    .attestations()
                    .iter()
                    .map(|a| a.key().as_str().to_owned())
                    .collect(),
                record.blob().declared_uncompressed_bytes(),
                record.blob().key().as_str().to_owned(),
            ));
        }
        Ok(drained)
    }

    // ---- Index classification ----

    #[test]
    fn index_requires_a_tenant_raw_scope() {
        let scope = InventoryScope::TenantControl(tenant());
        let inventory =
            FrozenInventory::from_pages(&scope, vec![Ok(InventoryPage::new(Vec::new(), None))])
                .unwrap();
        let error = RawCatalogIndex::new(&inventory).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::MalformedInput);
    }

    #[test]
    fn index_fails_on_an_unrecognized_raw_object() {
        let b = bundle();
        let stray = format!("tenants/{TENANT}/v1/raw/scratch/thing.json");
        let mut entries: Vec<(&str, u64)> =
            vec![(b.blob_key.as_str(), b.blob.len() as u64), (&stray, 4)];
        for (key, doc) in b.occurrence_keys.iter().zip(&b.occurrences) {
            entries.push((key.as_str(), doc.len() as u64));
        }
        let error = RawCatalogIndex::new(&freeze(&entries)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    // ---- The committed bundle, read end to end ----

    #[test]
    fn reads_the_committed_bundle_deterministically() {
        let b = bundle();
        let store = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
            (b.occurrence_keys[1].as_str(), b.occurrences[1].clone()),
            (b.attestation_keys[0].as_str(), b.attestations[0].clone()),
            (b.attestation_keys[1].as_str(), b.attestations[1].clone()),
            (b.attestation_keys[2].as_str(), b.attestations[2].clone()),
            (b.attestation_keys[3].as_str(), b.attestations[3].clone()),
        ]);
        let inventory = bundle_inventory(&b);
        let index = RawCatalogIndex::new(&inventory).unwrap();
        assert_eq!(index.tenant().as_str(), TENANT);
        assert_eq!(index.occurrences().len(), 2);
        assert_eq!(index.attestations().len(), 4);
        assert_eq!(index.blobs().len(), 1);
        assert_eq!(index.blobs()[0], b.blob_key);

        let first = block_on(drain(&store, &index)).unwrap();
        let second = block_on(drain(&store, &index)).unwrap();
        assert_eq!(first, second, "an identical prefix drains identically");

        // Canonical occurrence order, regardless of the listing order the
        // freeze consumed.
        let expected_occurrence_order: Vec<&str> = index
            .occurrences()
            .iter()
            .map(OccurrenceObjectKey::as_str)
            .collect();
        let drained_order: Vec<&str> = first.iter().map(|(key, ..)| key.as_str()).collect();
        assert_eq!(drained_order, expected_occurrence_order);

        // Each occurrence is joined with exactly its own attestations, in
        // key-byte order.
        assert_eq!(first[0].2.len(), 3, "three attestations on the first");
        assert_eq!(first[1].2.len(), 1, "one attestation on the second");
        let mut drained_attestations: Vec<&str> = Vec::new();
        for (_, _, attestation_keys, _, _) in &first {
            let keys: Vec<&str> = attestation_keys.iter().map(String::as_str).collect();
            let mut sorted = keys.clone();
            sorted.sort_unstable();
            assert_eq!(keys, sorted, "per-record attestation key order");
            drained_attestations.extend(keys);
        }
        let mut expected_attestations: Vec<&str> = index
            .attestations()
            .iter()
            .map(AttestationObjectKey::as_str)
            .collect();
        expected_attestations.sort_unstable();
        drained_attestations.sort_unstable();
        assert_eq!(drained_attestations, expected_attestations);

        // Every record carries the shared blob, header-validated, with the
        // frame's declared content size — the size the manifest
        // deliberately does not duplicate.
        for (_, _, _, declared, blob_key) in &first {
            assert_eq!(*declared, payload_len());
            assert_eq!(blob_key.as_str(), b.blob_key.as_str());
        }
    }

    #[test]
    fn empty_inventory_yields_no_records() {
        let store = MockStore::with(&[]);
        let inventory = freeze(&[]);
        let index = RawCatalogIndex::new(&inventory).unwrap();
        let mut source = block_on(RawCatalogSource::open(&store, &index)).unwrap();
        assert!(source.is_empty());
        assert_eq!(source.len(), 0);
        assert!(block_on(source.next_occurrence(&store)).unwrap().is_none());
    }

    /// Additive members are the old-reader/new-writer compatibility rule:
    /// a v1 reader ignores what it does not know (plan Section 7.1).
    #[test]
    fn additive_unknown_member_is_ignored() {
        let b = bundle();
        let future = mutated(
            &b.occurrences[0],
            "{\"adapter_artifact_id\"",
            "{\"archivist.future.member\":\"reserved\",\"adapter_artifact_id\"",
        );
        let store = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (b.occurrence_keys[0].as_str(), future),
            (b.attestation_keys[0].as_str(), b.attestations[0].clone()),
            (b.attestation_keys[1].as_str(), b.attestations[1].clone()),
            (b.attestation_keys[2].as_str(), b.attestations[2].clone()),
        ]);
        let index = RawCatalogIndex::new(&single_occurrence_inventory(&b)).unwrap();
        let drained = block_on(drain(&store, &index)).unwrap();
        assert_eq!(drained.len(), 1);
    }

    // ---- Missing and unreadable raw objects ----

    #[test]
    fn missing_referenced_blob_fails_closed_at_open() {
        let b = bundle();
        // The blob is not listed: the occurrence's reference dangles.
        let mut entries: Vec<(&str, u64)> = Vec::new();
        for (key, doc) in b.occurrence_keys.iter().zip(&b.occurrences) {
            entries.push((key.as_str(), doc.len() as u64));
        }
        let store = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
        ]);
        let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
        let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    #[test]
    fn orphan_attestation_fails_closed() {
        let b = bundle();
        // No occurrence is listed: every attestation names an occurrence
        // the frozen inventory does not hold.
        let mut entries: Vec<(&str, u64)> = vec![(b.blob_key.as_str(), b.blob.len() as u64)];
        let mut objects: Vec<(&str, Vec<u8>)> = vec![(b.blob_key.as_str(), b.blob.clone())];
        for (key, doc) in b.attestation_keys.iter().zip(&b.attestations) {
            entries.push((key.as_str(), doc.len() as u64));
            objects.push((key.as_str(), doc.clone()));
        }
        let store = MockStore::with(&objects);
        let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
        let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    #[test]
    fn listed_object_unreadable_fails_the_source_closed() {
        let b = bundle();
        let index = RawCatalogIndex::new(&single_occurrence_inventory(&b)).unwrap();

        // A listed manifest that no longer reads: the freeze has diverged.
        let store = MockStore::with(&[(b.blob_key.as_str(), b.blob.clone())]);
        let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);

        // And a listed blob that vanishes after open fails the same way at
        // payload time.
        let complete = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
            (b.attestation_keys[0].as_str(), b.attestations[0].clone()),
            (b.attestation_keys[1].as_str(), b.attestations[1].clone()),
            (b.attestation_keys[2].as_str(), b.attestations[2].clone()),
        ]);
        let mut source = block_on(RawCatalogSource::open(&complete, &index)).unwrap();
        let objects = HashMap::from([(
            b.occurrence_keys[0].as_str().to_owned(),
            b.occurrences[0].clone(),
        )]);
        let robbed = MockStore {
            objects: Mutex::new(objects),
        };
        let error = block_on(source.next_occurrence(&robbed)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::InventoryFault);
    }

    // ---- Occurrence schema and provenance faults ----

    #[test]
    fn tampered_occurrence_documents_fail_closed() {
        let b = bundle();
        let object = parsed(&b.occurrences[0]);
        let session_hex = text_of(&object, "session_hash").to_owned();
        let artifact_hex = text_of(&object, "artifact_hash").to_owned();
        let occurrence_hex = text_of(&object, "occurrence_id").to_owned();
        let generation = text_of(&object, "generation").to_owned();
        let source_time = text_of(&object, "source_time").to_owned();
        let mutations: Vec<Vec<u8>> = vec![
            // Unsupported schema major.
            mutated(
                &b.occurrences[0],
                "\"occurrence_version\":1",
                "\"occurrence_version\":2",
            ),
            // Missing required member.
            mutated(
                &b.occurrences[0],
                &format!("\"generation\":\"{generation}\","),
                "",
            ),
            // Wrong member type.
            mutated(
                &b.occurrences[0],
                "\"range_start\":0",
                "\"range_start\":\"0\"",
            ),
            // Member outside its wire grammar.
            mutated(
                &b.occurrences[0],
                "\"harness\":\"claude-code\"",
                "\"harness\":\"Claude-Code\"",
            ),
            // Grammar-valid text that is not a real calendar instant.
            mutated(
                &b.occurrences[0],
                &format!("\"source_time\":\"{source_time}\""),
                "\"source_time\":\"2026-02-30T16:44:02Z\"",
            ),
            // The range in the wrong direction.
            mutated(
                &b.occurrences[0],
                "\"range_start\":0",
                "\"range_start\":170",
            ),
            // Provenance: each self-verifying identity disagrees.
            mutated(
                &b.occurrences[0],
                &format!("\"session_hash\":\"{session_hex}\""),
                &format!("\"session_hash\":\"{TAMPERED}\""),
            ),
            mutated(
                &b.occurrences[0],
                &format!("\"artifact_hash\":\"{artifact_hex}\""),
                &format!("\"artifact_hash\":\"{TAMPERED}\""),
            ),
            mutated(
                &b.occurrences[0],
                &format!("\"occurrence_id\":\"{occurrence_hex}\""),
                &format!("\"occurrence_id\":\"{TAMPERED}\""),
            ),
            // Not canonical JSON at all.
            b"not json".to_vec(),
        ];
        for tampered in mutations {
            let store = MockStore::with(&[
                (b.blob_key.as_str(), b.blob.clone()),
                (b.occurrence_keys[0].as_str(), tampered),
            ]);
            let entries: Vec<(&str, u64)> = vec![
                (b.blob_key.as_str(), b.blob.len() as u64),
                (b.occurrence_keys[0].as_str(), b.occurrences[0].len() as u64),
            ];
            let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
            let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
            assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        }
    }

    #[test]
    fn manifest_at_a_foreign_key_fails_closed() {
        let b = bundle();
        let object = parsed(&b.occurrences[0]);
        let foreign_key = OccurrenceObjectKey::new(
            &tenant(),
            &ClientId::parse(text_of(&object, "origin_client_id")).unwrap(),
            &HarnessId::parse("another-harness").unwrap(),
            &SessionHash::parse(text_of(&object, "session_hash")).unwrap(),
            &OccurrenceId::parse(text_of(&object, "occurrence_id")).unwrap(),
        );
        let store = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (foreign_key.as_str(), b.occurrences[0].clone()),
        ]);
        let entries: Vec<(&str, u64)> = vec![
            (b.blob_key.as_str(), b.blob.len() as u64),
            (foreign_key.as_str(), b.occurrences[0].len() as u64),
        ];
        let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
        let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    // ---- Attestation schema and provenance faults ----

    #[test]
    fn tampered_attestation_documents_fail_closed() {
        let b = bundle();
        let object = parsed(&b.attestations[0]);
        let attestation_hex = text_of(&object, "attestation_id").to_owned();
        let uploader = text_of(&object, "uploader_client_id").to_owned();
        let relay_uploader = text_of(&parsed(&b.attestations[2]), "uploader_client_id").to_owned();
        let mutations: Vec<Vec<u8>> = vec![
            // Unsupported schema major.
            mutated(
                &b.attestations[0],
                "\"attestation_version\":1",
                "\"attestation_version\":7",
            ),
            // Missing required member (the schema's last canonical
            // member, so its preceding comma goes with it).
            mutated(
                &b.attestations[0],
                &format!(",\"uploader_client_id\":\"{uploader}\""),
                "",
            ),
            // Wrong member type.
            mutated(
                &b.attestations[0],
                &format!("\"uploader_client_id\":\"{uploader}\""),
                "\"uploader_client_id\":17",
            ),
            // `direct` with an uploader that is not the origin.
            mutated(
                &b.attestations[0],
                &format!("\"uploader_client_id\":\"{uploader}\""),
                &format!("\"uploader_client_id\":\"{relay_uploader}\""),
            ),
            // The folded identity disagrees with its inputs.
            mutated(
                &b.attestations[0],
                &format!("\"attestation_id\":\"{attestation_hex}\""),
                &format!("\"attestation_id\":\"{TAMPERED}\""),
            ),
            // Not canonical JSON at all.
            b"[]".to_vec(),
        ];
        for tampered in mutations {
            let store = MockStore::with(&[
                (b.blob_key.as_str(), b.blob.clone()),
                (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
                (b.attestation_keys[0].as_str(), tampered),
            ]);
            let entries: Vec<(&str, u64)> = vec![
                (b.blob_key.as_str(), b.blob.len() as u64),
                (b.occurrence_keys[0].as_str(), b.occurrences[0].len() as u64),
                (
                    b.attestation_keys[0].as_str(),
                    b.attestations[0].len() as u64,
                ),
            ];
            let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
            let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
            assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        }
    }

    #[test]
    fn attestation_at_a_foreign_key_fails_closed() {
        let b = bundle();
        let foreign_key = AttestationObjectKey::new(
            &tenant(),
            &OccurrenceId::parse(TAMPERED).unwrap(),
            &AttestationId::parse(TAMPERED).unwrap(),
        );
        let store = MockStore::with(&[
            (b.blob_key.as_str(), b.blob.clone()),
            (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
            (foreign_key.as_str(), b.attestations[0].clone()),
        ]);
        let entries: Vec<(&str, u64)> = vec![
            (b.blob_key.as_str(), b.blob.len() as u64),
            (b.occurrence_keys[0].as_str(), b.occurrences[0].len() as u64),
            (foreign_key.as_str(), b.attestations[0].len() as u64),
        ];
        let index = RawCatalogIndex::new(&freeze(&entries)).unwrap();
        let error = block_on(RawCatalogSource::open(&store, &index)).unwrap_err();
        assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
    }

    // ---- The zstd-v1 frame-header contract ----

    #[test]
    fn frame_header_reads_every_content_size_form() {
        // 8-byte form (the pinned encoder's): magic, descriptor, window
        // descriptor, eight little-endian bytes.
        let declared = 0x01_02_03_04_05_06_07_08u64;
        let mut frame = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC4, 0x00]);
        frame.extend_from_slice(&declared.to_le_bytes());
        assert_eq!(zstd_v1_frame_content_size(&frame).unwrap(), declared);
        // 4-byte form.
        let declared = 70_000u32;
        let mut frame = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0x84, 0x00]);
        frame.extend_from_slice(&declared.to_le_bytes());
        assert_eq!(
            zstd_v1_frame_content_size(&frame).unwrap(),
            u64::from(declared)
        );
        // 2-byte form, offset by 256 (RFC 8878).
        let mut frame = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0x44, 0x00]);
        frame.extend_from_slice(&65_344u16.to_le_bytes());
        assert_eq!(zstd_v1_frame_content_size(&frame).unwrap(), 65_600);
        // 1-byte form in single-segment mode: no window descriptor.
        let frame = Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0x24, 200]);
        assert_eq!(zstd_v1_frame_content_size(&frame).unwrap(), 200);
    }

    #[test]
    fn nonconforming_blob_frames_fail_closed() {
        let b = bundle();
        let frames: Vec<Vec<u8>> = vec![
            // Wrong magic.
            Vec::from([0u8; 32]),
            // Reserved descriptor bit set.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xCC, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]),
            // Dictionary declared; the profile pins none.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC5, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]),
            // Content checksum omitted; the profile pins it enabled.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC0, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]),
            // No content size declared.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0x04, 0x00]),
            // Header truncated before the content size.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC4]),
            // Content size truncated mid-field.
            Vec::from([0x28u8, 0xB5, 0x2F, 0xFD, 0xC4, 0x00, 1, 2, 3]),
        ];
        for frame in frames {
            let store = MockStore::with(&[
                (b.blob_key.as_str(), frame),
                (b.occurrence_keys[0].as_str(), b.occurrences[0].clone()),
                (b.attestation_keys[0].as_str(), b.attestations[0].clone()),
                (b.attestation_keys[1].as_str(), b.attestations[1].clone()),
                (b.attestation_keys[2].as_str(), b.attestations[2].clone()),
            ]);
            let index = RawCatalogIndex::new(&single_occurrence_inventory(&b)).unwrap();
            let mut source = block_on(RawCatalogSource::open(&store, &index)).unwrap();
            let error = block_on(source.next_occurrence(&store)).unwrap_err();
            assert_eq!(error.kind(), StorageErrorKind::IntegrityConflict);
        }
    }
}
