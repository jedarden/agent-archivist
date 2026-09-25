// SPDX-License-Identifier: Apache-2.0

//! The receipt strand of a complete commit: the per-tenant signing
//! schedules, composed once at startup, and the one assembly site that
//! turns three durable objects and a verified attempt into the signed
//! acceptance evidence a client retains (plan Section 7.8; RCPT-002,
//! RCPT-006).
//!
//! A receipt exists only after the blob, occurrence manifest, and upload
//! attestation are all durable (RCPT-001): [`issue`] is the single
//! caller of the tenant's [`ReceiptKeySchedule`], and the route reaches
//! it only on the far side of the three-object commit order. The
//! nineteen-member body it builds is exactly the wire contract of
//! `schemas/v1/ingest-receipt.json`: the identities the envelope froze,
//! the server-derived object keys the commits landed at (ID-008: the
//! receipt reports them, never delegates them), each object's physical
//! outcome exactly as the store reported it (RCPT-003 — never
//! strengthened, never deduplication the backend cannot prove), the
//! authorization key and epoch that admitted the attempt (the receipt is
//! their one sanctioned home, protocol Section 5), and the UTC commit
//! time. [`ReceiptKeySchedule::sign_receipt`] adds the five
//! signer-controlled members — version, key ID, certificate by value,
//! algorithm, signature — so the tenant authority's chain walks offline
//! from a client's pinned root (RCPT-006).
//!
//! A tenant without a schedule commits without issuing evidence: the
//! honest answer for such an attempt remains the retryable
//! partial-commit class, because success is only what a receipt can
//! prove (protocol Section 5.1), and an identical retry converges on the
//! standing objects and is receipted once a schedule exists.

use std::collections::BTreeMap;
use std::fmt;

use archivist_auth::receipt::{Receipt, ReceiptKeyError, ReceiptKeySchedule};
use archivist_protocol::envelope::Envelope;
use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{KeyId, TenantId, Timestamp};
use archivist_storage::blob::BlobCommit;
use archivist_storage::sequence::ProvenanceCommit;

/// Media type of the ingest success body: the signed receipt, canonical
/// JSON (protocol Section 5.1).
pub const RECEIPT_MEDIA_TYPE: &str = "application/vnd.agent-archivist.receipt+json;version=1";

/// The per-tenant receipt signing schedules one replica holds: composed
/// once at startup from certified keys loaded through protected
/// references, shared by reference inside the server state, and never
/// mutated per request. Signing is the only per-request work — a map
/// lookup and one Ed25519 signature over bytes the commit already
/// produced.
///
/// A tenant missing from the map has no key this replica may sign with,
/// so its complete commits still answer without a receipt (see the
/// module docs); that is the fail-closed shape, not an oversight.
#[derive(Debug, Default)]
pub struct ReceiptSigners {
    schedules: BTreeMap<TenantId, ReceiptKeySchedule>,
}

impl ReceiptSigners {
    /// The empty set: every tenant commits unreceipted until a schedule
    /// is installed for it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            schedules: BTreeMap::new(),
        }
    }

    /// Compose the set from one schedule per tenant; a repeated tenant
    /// keeps its last schedule.
    #[must_use]
    pub fn from_schedules(schedules: impl IntoIterator<Item = ReceiptKeySchedule>) -> Self {
        let mut set = Self::new();
        for schedule in schedules {
            set.install(schedule);
        }
        set
    }

    /// Install or replace one tenant's schedule, keyed by the schedule's
    /// own tenant so the map can never disagree with a key's scope.
    pub fn install(&mut self, schedule: ReceiptKeySchedule) {
        self.schedules
            .insert(schedule.tenant_id().clone(), schedule);
    }

    /// The signing schedule for `tenant`, when this replica holds one.
    #[must_use]
    pub fn schedule_for(&self, tenant: &TenantId) -> Option<&ReceiptKeySchedule> {
        self.schedules.get(tenant)
    }

    /// How many tenants this replica can receipt for.
    #[must_use]
    pub fn len(&self) -> usize {
        self.schedules.len()
    }

    /// Whether no tenant holds a schedule.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.schedules.is_empty()
    }
}

/// Why a complete commit still answered without a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptIssue {
    /// The replica holds no signing schedule for the attempt's tenant,
    /// so no key may sign its evidence.
    NoSchedule,
    /// Signing failed under the retained schedule — most plainly a
    /// commit instant outside every retained key's window.
    Signing(ReceiptKeyError),
}

impl fmt::Display for ReceiptIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::NoSchedule => "no receipt signing schedule is retained for the tenant",
            Self::Signing(_) => "the retained receipt signing schedule refused the commit instant",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ReceiptIssue {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::NoSchedule => None,
            Self::Signing(error) => Some(error),
        }
    }
}

/// Assemble and sign the receipt for one complete three-object commit
/// (RCPT-002): the frozen identities, the server-derived keys the
/// objects stand at, each object's physical outcome exactly as the store
/// reported it, the authorization that admitted the attempt, and the
/// instant the commit became complete.
///
/// The envelope's occurrence and attestation identifiers are the
/// committed ones by construction — the manifest layer re-derived both
/// server-side and refused any disagreement before this function is
/// reachable — and `commit_time` is read after the third object stood,
/// so the receipt names the commit that exists, not the attempt that
/// started.
///
/// # Errors
/// [`ReceiptIssue::NoSchedule`] when the tenant has no retained
/// schedule, and [`ReceiptIssue::Signing`] when the schedule's key set
/// cannot sign at `commit_time` (an out-of-window instant, or a
/// caller-controlled member the signer refuses).
pub fn issue(
    signers: &ReceiptSigners,
    envelope: &Envelope,
    blob: &BlobCommit,
    provenance: &ProvenanceCommit,
    authorization_key_id: &KeyId,
    authorization_epoch: u64,
    commit_time: &Timestamp,
) -> Result<Receipt, ReceiptIssue> {
    let schedule = signers
        .schedule_for(&envelope.tenant_id)
        .ok_or(ReceiptIssue::NoSchedule)?;
    let mut object = Object::new();
    object.set("tenant_id", text(envelope.tenant_id.as_str()));
    object.set("request_id", text(envelope.request_id.as_str()));
    object.set("occurrence_id", text(&envelope.occurrence_id.to_hex()));
    object.set("attestation_id", text(&envelope.attestation_id.to_hex()));
    object.set("blob_digest", text(&envelope.blob_digest.to_hex()));
    object.set("blob_object_key", text(blob.key().as_str()));
    object.set(
        "occurrence_object_key",
        text(provenance.occurrence().key().as_str()),
    );
    object.set(
        "attestation_object_key",
        text(provenance.attestation().key().as_str()),
    );
    object.set("blob_outcome", text(blob.outcome().token()));
    object.set(
        "occurrence_outcome",
        text(provenance.occurrence().outcome().token()),
    );
    object.set(
        "attestation_outcome",
        text(provenance.attestation().outcome().token()),
    );
    object.set("authorization_key_id", text(&authorization_key_id.to_hex()));
    // The schema's epoch ceiling is the JSON integer range; a presented
    // record parsed from that same range cannot exceed it.
    object.set(
        "authorization_epoch",
        Value::Int(i64::try_from(authorization_epoch).unwrap_or(i64::MAX)),
    );
    object.set("commit_time", text(commit_time.as_str()));
    schedule.sign_receipt(object).map_err(ReceiptIssue::Signing)
}

/// One text member.
fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{RECEIPT_MEDIA_TYPE, ReceiptIssue, ReceiptSigners};
    use archivist_auth::receipt::{
        AuthoritySigner, CertifiedReceiptKey, ReceiptKeySchedule, ReceiptSigningKey,
    };
    use archivist_auth::reference::ProtectedReference;
    use archivist_protocol::vocabulary::{TenantId, Timestamp};

    // A grammar-clean tenant distinct from every route fixture tenant,
    // so cross-tenant refusals cannot pass by coincidence.
    const OTHER_TENANT: &str = "2b3c4d5e-6f70-4a1b-9c2d-3e4f5a6b7c8d";

    fn tenant() -> TenantId {
        OTHER_TENANT.parse().expect("tenant grammar")
    }

    /// Write one 32-byte seed as a mode-restricted file and return its
    /// protected reference with the file's path. The reference resolves
    /// eagerly at load, so the file must outlive every key load it
    /// feeds; the caller removes both files once its key material is
    /// loaded, exactly as a replica loads keys at startup and never
    /// re-reads them.
    fn seed_reference(seed: [u8; 32], slot: u8) -> (ProtectedReference, std::path::PathBuf) {
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "archivist-server-receipt-{}-{slot}.key",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).expect("seed file");
        file.write_all(&seed).expect("seed bytes");
        file.sync_all().expect("seed sync");
        drop(file);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("seed mode");
        let reference =
            ProtectedReference::parse(&format!("file:{}", path.display())).expect("reference");
        (reference, path)
    }

    /// One certified key schedule whose signing window spans
    /// `valid_from` to 37 days on (the rotation plus overlap constant),
    /// certified by the authority seed its caller names.
    fn schedule_for_tenant(
        tenant: TenantId,
        authority_seed: [u8; 32],
        valid_from: &str,
    ) -> ReceiptKeySchedule {
        let (signing_reference, signing_path) = seed_reference([0x42; 32], 1);
        let signing = ReceiptSigningKey::from_secret_reference(tenant.clone(), &signing_reference)
            .expect("receipt key loads");
        let (authority_reference, authority_path) = seed_reference(authority_seed, 2);
        let authority = AuthoritySigner::from_secret_reference(tenant, &authority_reference)
            .expect("authority key loads");
        let instant = Timestamp::parse(valid_from).expect("window start");
        let certified = CertifiedReceiptKey::certify(signing, &authority, instant.clone(), instant)
            .expect("certification");
        let _ = std::fs::remove_file(signing_path);
        let _ = std::fs::remove_file(authority_path);
        ReceiptKeySchedule::new(certified)
    }

    #[test]
    fn an_empty_signer_set_receipts_for_no_tenant() {
        let signers = ReceiptSigners::new();
        assert!(signers.is_empty());
        assert_eq!(signers.len(), 0);
        // The lookup, not the signing, is what the route keys its
        // honesty on: no schedule means no key may sign.
        assert!(signers.schedule_for(&tenant()).is_none());
    }

    #[test]
    fn installed_schedules_serve_exactly_their_tenants() {
        let signers = ReceiptSigners::from_schedules([schedule_for_tenant(
            tenant(),
            [0x01; 32],
            "2026-09-01T00:00:00Z",
        )]);
        assert_eq!(signers.len(), 1);
        assert!(signers.schedule_for(&tenant()).is_some());
        let absent: TenantId = "3c4d5e6f-7080-4a1b-9c2d-3e4f5a6b7c8d"
            .parse()
            .expect("another tenant");
        assert!(signers.schedule_for(&absent).is_none());
        // Replacement, not accumulation, is the install contract.
        let mut replaced = signers;
        replaced.install(schedule_for_tenant(
            tenant(),
            [0x01; 32],
            "2026-09-02T00:00:00Z",
        ));
        assert_eq!(replaced.len(), 1);
    }

    #[test]
    fn the_success_media_type_is_the_pinned_receipt_type() {
        assert_eq!(
            RECEIPT_MEDIA_TYPE,
            "application/vnd.agent-archivist.receipt+json;version=1"
        );
    }

    #[test]
    fn issue_errors_render_content_free_class_names() {
        assert_eq!(
            ReceiptIssue::NoSchedule.to_string(),
            "no receipt signing schedule is retained for the tenant"
        );
        let signing =
            ReceiptIssue::Signing(archivist_auth::receipt::ReceiptKeyError::OutsideSigningWindow);
        assert_eq!(
            signing.to_string(),
            "the retained receipt signing schedule refused the commit instant"
        );
        assert!(std::error::Error::source(&signing).is_some());
        assert!(std::error::Error::source(&ReceiptIssue::NoSchedule).is_none());
    }
}
