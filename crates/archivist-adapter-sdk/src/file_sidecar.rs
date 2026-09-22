// SPDX-License-Identifier: Apache-2.0

//! The file-source capture core's sidecar artifact relationships (plan
//! Phase 6A): the harness metadata files that travel with a primary
//! JSONL session — summaries, per-session metadata, working state, shell
//! snapshots — captured as artifacts in their own right, each carrying an
//! explicit relationship to the parent artifact it annotates.
//!
//! A sidecar is never folded into its parent's byte stream. It gets its
//! own adapter artifact ID, so its artifact identity derives from its own
//! inputs exactly as the parent's does — parent and sidecar stay
//! independently addressable, and the plan's artifact-hash derivation is
//! the only address there is. What the relationship adds is the
//! annotation the bytes alone cannot carry: which artifact this sidecar
//! belongs to, and what kind of sidecar it is. The ledger records both,
//! and enumerates a parent's sidecars on demand — the per-parent view
//! adapters and the client engine consult instead of re-deriving
//! relationships from file names.
//!
//! Every failure here is content-free and fail-closed: attaching to a
//! parent the ledger has never seen, or reusing an artifact identity,
//! is an error naming the violation ([`SidecarError`] carries no
//! payload) — never a silent relationship guess.

use std::collections::{BTreeMap, BTreeSet};

use archivist_protocol::vocabulary::{GrammarError, OpaqueId};

/// The closed vocabulary of sidecar relationships (plan Phase 6A): the
/// role one harness metadata file plays beside its primary session
/// artifact. Wire-stable tokens; an unknown token fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SidecarKind {
    /// The harness's own metadata about the session — model, versions,
    /// configuration the harness froze alongside the transcript.
    SessionMetadata,
    /// A harness-generated summary of the session.
    SessionSummary,
    /// Derived working state the harness maintains per session — todo
    /// lists, plans, checkpoints.
    WorkingState,
    /// A captured shell environment the session ran against.
    ShellSnapshot,
}

impl SidecarKind {
    /// Every kind, in declaration order.
    #[must_use]
    pub fn all() -> &'static [Self] {
        &[
            Self::SessionMetadata,
            Self::SessionSummary,
            Self::WorkingState,
            Self::ShellSnapshot,
        ]
    }

    /// The canonical token for this kind.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::SessionMetadata => "session-metadata",
            Self::SessionSummary => "session-summary",
            Self::WorkingState => "working-state",
            Self::ShellSnapshot => "shell-snapshot",
        }
    }

    /// Parse one token, failing closed on anything unknown.
    ///
    /// # Errors
    /// [`GrammarError::NotCanonical`] for a token outside the closed set.
    pub fn parse(text: &str) -> Result<Self, GrammarError> {
        match text {
            "session-metadata" => Ok(Self::SessionMetadata),
            "session-summary" => Ok(Self::SessionSummary),
            "working-state" => Ok(Self::WorkingState),
            "shell-snapshot" => Ok(Self::ShellSnapshot),
            _ => Err(GrammarError::NotCanonical),
        }
    }
}

impl std::fmt::Display for SidecarKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.token())
    }
}

/// The most sidecars one parent artifact may carry: the per-parent view
/// is bounded the way every SDK status shape is, so a harness that
/// litters metadata files cannot grow the enumeration without bound.
/// Growing the bound is a deliberate contract change, like
/// [`crate::capability::MAX_CAPABILITIES`].
pub const MAX_SIDECARS_PER_PARENT: usize = 32;

/// Why a sidecar relationship could not be recorded. The variants carry
/// no payload: artifact IDs are opaque harness-controlled content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SidecarError {
    /// The relationship names a parent artifact the ledger has never
    /// registered: relationships are recorded against captured parents,
    /// never guessed.
    ParentUnknown,
    /// The artifact identity is already in the ledger — as this or
    /// another sidecar, or as a parent. One identity addresses one
    /// artifact, so a reuse would make two artifacts share an address.
    DuplicateArtifact,
    /// The parent already carries [`MAX_SIDECARS_PER_PARENT`] sidecars.
    TooManySidecars,
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::ParentUnknown => "sidecar_parent_unknown",
            Self::DuplicateArtifact => "sidecar_artifact_identity_duplicate",
            Self::TooManySidecars => "sidecar_parent_bound_exceeded",
        };
        f.write_str(token)
    }
}

impl std::error::Error for SidecarError {}

/// The explicit relationship one sidecar artifact carries to its parent
/// (plan Phase 6A): the parent's adapter artifact ID, and the
/// [`SidecarKind`] the sidecar plays. The pair is the whole relationship
/// — nothing is inferred from paths, names, or content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SidecarRelationship {
    parent_artifact_id: OpaqueId,
    kind: SidecarKind,
}

impl SidecarRelationship {
    /// Record the relationship: this sidecar annotates that parent, as
    /// this kind.
    #[must_use]
    pub fn new(parent_artifact_id: OpaqueId, kind: SidecarKind) -> Self {
        Self {
            parent_artifact_id,
            kind,
        }
    }

    /// The parent artifact this sidecar annotates.
    #[must_use]
    pub fn parent_artifact_id(&self) -> &OpaqueId {
        &self.parent_artifact_id
    }

    /// The role this sidecar plays beside its parent.
    #[must_use]
    pub fn kind(&self) -> SidecarKind {
        self.kind
    }
}

/// The capture-core ledger of sidecar relationships for one adapter's
/// sources: parents are registered as their artifacts are captured,
/// sidecars are attached with explicit relationships, and the per-parent
/// view is enumerable on demand ([`SidecarLedger::sidecars_of`]) in
/// canonical artifact-ID order — the order is a property of the ledger,
/// not of discovery.
///
/// Artifact identities share one namespace: a parent and a sidecar
/// cannot collide, and no artifact ID addresses two entries.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SidecarLedger {
    parents: BTreeSet<OpaqueId>,
    sidecars: BTreeMap<OpaqueId, SidecarRelationship>,
}

impl SidecarLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a parent artifact sidecars may attach to. Registering
    /// the same parent twice is idempotent; the return says whether this
    /// call made it known.
    pub fn register_parent(&mut self, parent_artifact_id: OpaqueId) -> bool {
        self.parents.insert(parent_artifact_id)
    }

    /// Whether the parent artifact is registered.
    #[must_use]
    pub fn parent_is_known(&self, parent_artifact_id: &OpaqueId) -> bool {
        self.parents.contains(parent_artifact_id)
    }

    /// Attach one sidecar to its parent with an explicit relationship.
    ///
    /// # Errors
    /// [`SidecarError::ParentUnknown`] when the parent was never
    /// registered; [`SidecarError::DuplicateArtifact`] when
    /// `artifact_id` already addresses anything in the ledger;
    /// [`SidecarError::TooManySidecars`] when the parent already carries
    /// the per-parent bound.
    pub fn attach(
        &mut self,
        parent_artifact_id: &OpaqueId,
        artifact_id: OpaqueId,
        kind: SidecarKind,
    ) -> Result<(), SidecarError> {
        if !self.parents.contains(parent_artifact_id) {
            return Err(SidecarError::ParentUnknown);
        }
        if self.parents.contains(&artifact_id) || self.sidecars.contains_key(&artifact_id) {
            return Err(SidecarError::DuplicateArtifact);
        }
        let carried = self
            .sidecars
            .values()
            .filter(|relationship| relationship.parent_artifact_id() == parent_artifact_id)
            .count();
        if carried >= MAX_SIDECARS_PER_PARENT {
            return Err(SidecarError::TooManySidecars);
        }
        self.sidecars.insert(
            artifact_id,
            SidecarRelationship::new(parent_artifact_id.clone(), kind),
        );
        Ok(())
    }

    /// The sidecars of one parent, each with its artifact ID, in
    /// canonical artifact-ID order. Unknown and childless parents
    /// enumerate to nothing.
    pub fn sidecars_of<'a>(
        &'a self,
        parent_artifact_id: &'a OpaqueId,
    ) -> impl Iterator<Item = (&'a OpaqueId, &'a SidecarRelationship)> {
        self.sidecars.iter().filter(move |(_, relationship)| {
            relationship.parent_artifact_id() == parent_artifact_id
        })
    }

    /// The relationship one artifact identity carries, if it is a
    /// sidecar in this ledger.
    #[must_use]
    pub fn relationship_of(&self, artifact_id: &OpaqueId) -> Option<&SidecarRelationship> {
        self.sidecars.get(artifact_id)
    }

    /// Whether the artifact identity addresses a sidecar in this ledger.
    #[must_use]
    pub fn is_sidecar(&self, artifact_id: &OpaqueId) -> bool {
        self.sidecars.contains_key(artifact_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use archivist_protocol::derivation::artifact_hash as derive_artifact_hash;
    use archivist_protocol::vocabulary::{AdapterId, ArtifactKind, SessionHash, VersionToken};

    fn parent() -> OpaqueId {
        OpaqueId::parse("session-4f9c2f1e-jsonl").expect("parent artifact id")
    }

    fn sidecar(seed: u8) -> OpaqueId {
        OpaqueId::parse(&format!("session-4f9c2f1e/sidecar/{seed}")).expect("sidecar artifact id")
    }

    #[test]
    fn sidecars_carry_an_explicit_relationship_and_enumerate_per_parent() {
        let parent = parent();
        let mut ledger = SidecarLedger::new();
        assert!(ledger.register_parent(parent.clone()));

        ledger
            .attach(&parent, sidecar(1), SidecarKind::SessionMetadata)
            .expect("metadata sidecar");
        ledger
            .attach(&parent, sidecar(2), SidecarKind::SessionSummary)
            .expect("summary sidecar");
        ledger
            .attach(&parent, sidecar(3), SidecarKind::WorkingState)
            .expect("working-state sidecar");

        let enumerated: Vec<_> = ledger.sidecars_of(&parent).collect();
        assert_eq!(enumerated.len(), 3, "every sidecar enumerates");
        for (artifact_id, relationship) in &enumerated {
            assert_eq!(
                relationship.parent_artifact_id(),
                &parent,
                "the relationship names the parent explicitly"
            );
            assert!(ledger.relationship_of(artifact_id).is_some());
            assert!(ledger.is_sidecar(artifact_id));
        }
        // The relationship is the one attached — kind included.
        assert_eq!(
            ledger.relationship_of(&sidecar(2)).expect("attached"),
            &SidecarRelationship::new(parent.clone(), SidecarKind::SessionSummary)
        );

        // A second parent's view is independent: childless enumerates
        // to nothing and the first parent's sidecars do not leak in.
        let other = OpaqueId::parse("session-other-jsonl").expect("other parent");
        assert!(ledger.register_parent(other.clone()));
        assert_eq!(ledger.sidecars_of(&other).count(), 0);
        assert_eq!(ledger.sidecars_of(&parent).count(), 3);
    }

    #[test]
    fn sidecars_are_independently_addressable_artifacts() {
        // Parent and sidecar derive their artifact identities from their
        // own inputs: distinct adapter artifact IDs, so distinct
        // addresses — the sidecar is not a slice of the parent.
        let session = SessionHash::from_raw([9u8; 32]);
        let adapter = AdapterId::parse("claude-jsonl").expect("adapter id");
        let projection = VersionToken::parse("1").expect("projection version");
        let parent_hash = derive_artifact_hash(
            &session,
            ArtifactKind::FileSlice,
            &adapter,
            &projection,
            parent().as_str(),
        );
        let sidecar_hash = derive_artifact_hash(
            &session,
            ArtifactKind::FileSlice,
            &adapter,
            &projection,
            sidecar(1).as_str(),
        );
        assert_ne!(parent_hash, sidecar_hash);
        // The address is the derivation, stable under re-derivation.
        assert_eq!(
            sidecar_hash,
            derive_artifact_hash(
                &session,
                ArtifactKind::FileSlice,
                &adapter,
                &projection,
                sidecar(1).as_str(),
            )
        );
    }

    #[test]
    fn attachment_requires_a_known_parent_and_fails_closed() {
        let mut ledger = SidecarLedger::new();
        let unknown = OpaqueId::parse("session-never-registered").expect("unknown parent");
        assert_eq!(
            ledger.attach(&unknown, sidecar(1), SidecarKind::SessionMetadata),
            Err(SidecarError::ParentUnknown)
        );
        assert_eq!(
            SidecarError::ParentUnknown.to_string(),
            "sidecar_parent_unknown",
            "content-free"
        );
        // The failed attach recorded nothing.
        assert!(!ledger.is_sidecar(&sidecar(1)));
    }

    #[test]
    fn a_duplicate_artifact_identity_fails_closed() {
        let mut ledger = SidecarLedger::new();
        assert!(ledger.register_parent(parent()));
        ledger
            .attach(&parent(), sidecar(1), SidecarKind::SessionMetadata)
            .expect("first attach");

        // The same identity cannot attach twice.
        assert_eq!(
            ledger.attach(&parent(), sidecar(1), SidecarKind::SessionSummary),
            Err(SidecarError::DuplicateArtifact)
        );
        // Nor collide with a registered parent's identity.
        assert_eq!(
            ledger.attach(&parent(), parent(), SidecarKind::SessionSummary),
            Err(SidecarError::DuplicateArtifact)
        );
        // Nor attach under a second parent after the first claimed it.
        let other = OpaqueId::parse("session-other-jsonl").expect("other parent");
        assert!(ledger.register_parent(other.clone()));
        assert_eq!(
            ledger.attach(&other, sidecar(1), SidecarKind::ShellSnapshot),
            Err(SidecarError::DuplicateArtifact)
        );
        // The original relationship survived every rejected attach.
        assert_eq!(
            ledger.relationship_of(&sidecar(1)),
            Some(&SidecarRelationship::new(
                parent(),
                SidecarKind::SessionMetadata
            ))
        );
        assert_eq!(
            SidecarError::DuplicateArtifact.to_string(),
            "sidecar_artifact_identity_duplicate",
            "content-free"
        );
    }

    #[test]
    fn the_per_parent_bound_holds_and_is_per_parent() {
        let mut ledger = SidecarLedger::new();
        assert!(ledger.register_parent(parent()));
        for seed in 0..MAX_SIDECARS_PER_PARENT {
            let seed = u8::try_from(seed).expect("bound fits u8");
            ledger
                .attach(&parent(), sidecar(seed), SidecarKind::WorkingState)
                .expect("inside the bound");
        }
        assert_eq!(
            ledger.attach(&parent(), sidecar(200), SidecarKind::WorkingState),
            Err(SidecarError::TooManySidecars)
        );
        assert_eq!(
            SidecarError::TooManySidecars.to_string(),
            "sidecar_parent_bound_exceeded",
            "content-free"
        );
        // The bound is per parent, not per ledger.
        let other = OpaqueId::parse("session-other-jsonl").expect("other parent");
        assert!(ledger.register_parent(other.clone()));
        ledger
            .attach(&other, sidecar(201), SidecarKind::WorkingState)
            .expect("the other parent has its own budget");
    }

    #[test]
    fn sidecar_kinds_round_trip_and_fail_closed() {
        for kind in SidecarKind::all() {
            assert_eq!(SidecarKind::parse(kind.token()).as_ref(), Ok(kind));
        }
        assert!(SidecarKind::parse("summary").is_err());
        assert!(SidecarKind::parse("Session-Metadata").is_err());
        assert!(SidecarKind::parse("").is_err());
    }

    #[test]
    fn registration_is_idempotent_and_queries_are_total() {
        let mut ledger = SidecarLedger::new();
        assert!(
            ledger.register_parent(parent()),
            "first registration is new"
        );
        assert!(
            !ledger.register_parent(parent()),
            "re-registration is a no-op"
        );
        assert!(ledger.parent_is_known(&parent()));
        let unknown = OpaqueId::parse("session-unknown").expect("unknown");
        assert!(!ledger.parent_is_known(&unknown));
        assert_eq!(ledger.relationship_of(&unknown), None);
        assert!(!ledger.is_sidecar(&unknown));
        assert_eq!(SidecarLedger::new().sidecars_of(&parent()).count(), 0);
    }
}
