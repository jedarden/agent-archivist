// SPDX-License-Identifier: Apache-2.0

//! The `redaction-v1` policy and its immutable detector corpus (plan Phase
//! 10; [docs/notes/derived-episode-schema.md];
//! [`schemas/v1/examples/episodes/pipeline/redaction-v1-corpus.json`]): the
//! typed seam every later redaction-v1 stage consumes — the fixed
//! structured-field allowlist, the ordered secret-detector registry, the
//! typed irreversible marker and pseudonym vocabularies, the pinned formats,
//! and the corpus digest the derived episode carries as
//! `detector_corpus_digest`.
//!
//! Ownership sits here by the layering rules
//! ([docs/notes/crate-ownership.md]): the corpus is the policy artifact the
//! whole pipeline is frozen inside — "detector order, patterns, entropy
//! parameters, structured-field allowlists, pseudonym format, and test
//! corpus are part of the immutable pipeline version" — so its types are
//! layer-0 wire material alongside the derivation cores they feed. The
//! per-occurrence transformation that *applies* the registry, and the
//! episode composition that applies the tenant-HMAC pseudonyms, are later
//! stages in the same Phase 10 work: they call into this module and can
//! never widen what it allows.
//!
//! # Immutability is structural, not conventional
//!
//! The plan's derivation-stability rule makes the corpus the one input a
//! rebuild is *not* allowed to vary: two producers claiming the same
//! pipeline version but differing effective detectors are exposed by
//! differing corpus digests before their episodes can be mistaken for each
//! other. So this module does not load configuration at runtime, accept a
//! registry contribution, or default a missing member. The corpus is
//! compiled in ([`RedactionCorpus::pinned`]), and the one constructible
//! value of [`RedactionCorpus`] *is* that corpus — a hand-built one cannot
//! drift from it because the type has exactly one value. Everything the
//! seam exposes (allowlist, detector order, marker shape, digest) is a
//! function of the pinned constants, never of input data.
//!
//! The document form still exists — the pinned example corpus is its
//! canonical rendering, and a stored or configured corpus document must be
//! recognizable as v1 before anything may act on it.
//! [`RedactionCorpus::from_value`] is that recognition, and it fails
//! closed: the member set is closed, every pinned member must equal the
//! compiled-in value, the detector table must be exactly the pinned ten
//! rows, and any deviation — unknown member, unsupported corpus version,
//! drifted detector row, reordered-but-intact arrays aside — is a typed
//! error, never a best-effort parse. Only the *array order* of the
//! allowlist and the detector table is normalized on the way in: the
//! registry's own `order` field, not document order, decides what the seam
//! exposes, so input data cannot change ordering by rearranging a document.
//!
//! The corpus carries **metadata only**: detector slugs, their emitted
//! classes, their order, and the *count* of synthetic leak test vectors
//! each detector is committed to (child corpus, not vector bytes). No
//! secret material, no pattern text, and no reversible-redaction member can
//! be represented — the closed shape rejects them by name.
//!
//! [`schemas/v1/examples/episodes/pipeline/redaction-v1-corpus.json`]:
//! ../../../schemas/v1/examples/episodes/pipeline/redaction-v1-corpus.json
//! [docs/notes/derived-episode-schema.md]: ../../../docs/notes/derived-episode-schema.md
//! [docs/notes/crate-ownership.md]: ../../../docs/notes/crate-ownership.md

use crate::json::{Object, Value};
use crate::sha256;

/// The derived pipeline this corpus belongs to (`pipeline_id`; the episode
/// schema's closed v1 enum ships exactly this one producer).
pub const PIPELINE_ID: &str = "redaction";

/// The immutable pipeline version (`pipeline_version`; v1 pins `1`): the
/// allowlist, the registry, the formats, and the test-corpus commitment
/// below are frozen inside it, and a changed detector is a new version
/// writing a new derived prefix segment — never a silent rewrite.
pub const PIPELINE_VERSION: &str = "1";

/// The corpus document's own version (`corpus_version`): v1 moves it
/// together with [`PIPELINE_VERSION`] — one frozen artifact, one version
/// axis while v1 is the only pipeline version.
pub const CORPUS_VERSION: &str = "1";

/// The irreversible marker rendering format: `{class_token}` is replaced
/// by a [`MarkerClass`] token, so a marker names *what was removed* and
/// nothing else. Part of the frozen pipeline version; the episode schema
/// bounds the resulting bytes.
pub const MARKER_FORMAT: &str = "[redacted:{class_token}]";

/// The tenant-scoped HMAC pseudonym rendering spec for the five
/// [`PseudonymClass`] families: a `ps_` prefix, the class token, and 12
/// lowercase hex digits of HMAC-SHA256 truncated from the keyed digest.
/// Stated as a specification string — the keyed rendering itself is the
/// episode-composition stage's job, and the key never appears in any
/// record, file, or argument.
pub const PSEUDONYM_FORMAT: &str = "ps_<class>_<12 lowercase hex of HMAC-SHA256>";

/// The pinned construction of a tenant's `pseudonym_key_id`: keyed
/// HMAC-SHA256 over the UTF-8 label [`PSEUDONYM_KEY_ID_LABEL`], rendered
/// lowercase hex. Recomputable and verifiable only by key holders, and
/// disclosing nothing about the key.
pub const PSEUDONYM_KEY_ID_CONSTRUCTION: &str =
    "HMAC-SHA256(pseudonym key, 'pseudonym-key-id-v1'), lowercase hex";

/// The HMAC input label inside [`PSEUDONYM_KEY_ID_CONSTRUCTION`], pinned
/// here so the episode-composition stage and any verifier agree on the one
/// domain-separated string the keyed self-ID is computed over.
pub const PSEUDONYM_KEY_ID_LABEL: &str = "pseudonym-key-id-v1";

/// The exact synthetic test-corpus byte string the corpus commits to via
/// its `test_suite_sha256` member: SHA-256 over these bytes names the leak
/// fixture suite the v1 detectors are verified against, without carrying
/// any fixture byte in the corpus itself.
pub const TEST_SUITE_CORPUS: &[u8] = b"agent-archivist synthetic redaction-v1 test corpus";

/// A structured occurrence field `redaction-v1` retains, in the pinned
/// allowlist order. The set is closed: a field outside it produces no
/// episode material at all, never a best-effort copy — the allowlist is the
/// plan's whole statement of what survives redaction besides the redacted
/// content rendering itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StructuredField {
    /// The record's harness-agnostic role (the episode schema's closed
    /// four-role set).
    Role,
    /// The episode-local position: contiguous, ascending from zero, the
    /// handle `parent_ordinals` references.
    Ordinal,
    /// The optional source-stable UTC event time; never a derivation
    /// timestamp.
    SourceTime,
    /// Backward-only references to earlier records this one answers or
    /// continues.
    ParentOrdinals,
}

impl StructuredField {
    /// Every allowlisted field, in the pinned allowlist order — the order
    /// the corpus document and [`RedactionCorpus::allowlist`] both use.
    pub const ALL: [Self; 4] = [
        crate::redaction_policy::StructuredField::Role,
        crate::redaction_policy::StructuredField::Ordinal,
        crate::redaction_policy::StructuredField::SourceTime,
        crate::redaction_policy::StructuredField::ParentOrdinals,
    ];

    /// The wire token the corpus document carries.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Role => "role",
            Self::Ordinal => "ordinal",
            Self::SourceTime => "source_time",
            Self::ParentOrdinals => "parent_ordinals",
        }
    }

    /// The field a corpus-document allowlist entry names, or `None` when
    /// the token is outside the closed vocabulary.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|field| field.token() == token)
    }
}

/// A canonical irreversible-marker class: one of the five detector
/// families that *destroy* what they match, leaving a typed marker as the
/// only trace. The set is closed and security-bearing — a class outside it
/// cannot be rendered, counted, or claimed, which is what makes the
/// episode's `marker_counts` census a complete statement of what fired.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MarkerClass {
    /// Pinned credential formats.
    PinnedCredential,
    /// Authorization headers.
    AuthorizationHeader,
    /// Private-key blocks.
    PrivateKeyBlock,
    /// Environment-secret assignments.
    EnvironmentSecret,
    /// High-entropy token candidates.
    HighEntropyToken,
}

impl MarkerClass {
    /// Every marker class, in registry order (the order the pinned
    /// detectors that emit them run in).
    pub const ALL: [Self; 5] = [
        crate::redaction_policy::MarkerClass::PinnedCredential,
        crate::redaction_policy::MarkerClass::AuthorizationHeader,
        crate::redaction_policy::MarkerClass::PrivateKeyBlock,
        crate::redaction_policy::MarkerClass::EnvironmentSecret,
        crate::redaction_policy::MarkerClass::HighEntropyToken,
    ];

    /// The class token the corpus document, the marker text, and the
    /// episode census all carry.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::PinnedCredential => "pinned_credential",
            Self::AuthorizationHeader => "authorization_header",
            Self::PrivateKeyBlock => "private_key_block",
            Self::EnvironmentSecret => "environment_secret",
            Self::HighEntropyToken => "high_entropy_token",
        }
    }

    /// The irreversible marker text for this class under the pinned
    /// [`MARKER_FORMAT`]: names the class, carries none of the removed
    /// bytes, and is not reversible by construction.
    #[must_use]
    pub fn marker_text(self) -> &'static str {
        match self {
            Self::PinnedCredential => "[redacted:pinned_credential]",
            Self::AuthorizationHeader => "[redacted:authorization_header]",
            Self::PrivateKeyBlock => "[redacted:private_key_block]",
            Self::EnvironmentSecret => "[redacted:environment_secret]",
            Self::HighEntropyToken => "[redacted:high_entropy_token]",
        }
    }

    /// The class a corpus-document token names, or `None` when the token is
    /// outside the closed vocabulary.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.token() == token)
    }
}

/// A canonical pseudonym class: one of the five identifier families that
/// stay analytically useful only as stable, tenant-scoped HMAC pseudonyms.
/// Distinct from [`MarkerClass`] because the treatment differs — these
/// matches are *replaced*, not destroyed, and counted in the episode's
/// `pseudonym_counts` census — and the two sets are disjoint by pin.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PseudonymClass {
    /// Absolute paths.
    AbsolutePath,
    /// Hostnames.
    Hostname,
    /// User names.
    Username,
    /// Email addresses.
    EmailAddress,
    /// IP addresses.
    IpAddress,
}

impl PseudonymClass {
    /// Every pseudonym class, in registry order.
    pub const ALL: [Self; 5] = [
        crate::redaction_policy::PseudonymClass::AbsolutePath,
        crate::redaction_policy::PseudonymClass::Hostname,
        crate::redaction_policy::PseudonymClass::Username,
        crate::redaction_policy::PseudonymClass::EmailAddress,
        crate::redaction_policy::PseudonymClass::IpAddress,
    ];

    /// The class token the corpus document and the episode census carry.
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::AbsolutePath => "absolute_path",
            Self::Hostname => "hostname",
            Self::Username => "username",
            Self::EmailAddress => "email_address",
            Self::IpAddress => "ip_address",
        }
    }

    /// The class a corpus-document token names, or `None` when the token is
    /// outside the closed vocabulary.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|class| class.token() == token)
    }
}

/// What a detector in the registry does with a match: substitute the typed
/// irreversible marker of a [`MarkerClass`], or substitute the
/// tenant-scoped HMAC pseudonym of a [`PseudonymClass`]. The emitted class
/// is pinned per detector, so a detector's output vocabulary is part of its
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DetectorEmit {
    /// The match is destroyed and replaced by the class's marker text.
    Marker(MarkerClass),
    /// The match is replaced by the class's tenant-scoped pseudonym.
    Pseudonym(PseudonymClass),
}

impl DetectorEmit {
    /// The emitted class's token (the marker or pseudonym token).
    #[must_use]
    pub fn token(self) -> &'static str {
        match self {
            Self::Marker(class) => class.token(),
            Self::Pseudonym(class) => class.token(),
        }
    }

    /// The emitted marker class, when this emit is a marker.
    #[must_use]
    pub fn marker_class(self) -> Option<MarkerClass> {
        match self {
            Self::Marker(class) => Some(class),
            Self::Pseudonym(_) => None,
        }
    }

    /// The emitted pseudonym class, when this emit is a pseudonym.
    #[must_use]
    pub fn pseudonym_class(self) -> Option<PseudonymClass> {
        match self {
            Self::Marker(_) => None,
            Self::Pseudonym(class) => Some(class),
        }
    }

    /// The emit a corpus-document `emits` token names, or `None` when the
    /// token is outside the closed vocabulary.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        MarkerClass::parse(token)
            .map(Self::Marker)
            .or_else(|| PseudonymClass::parse(token).map(Self::Pseudonym))
    }
}

/// One immutable detector-registry row: the detector's slug, the class it
/// emits, its fixed precedence `order`, and the number of synthetic leak
/// test vectors the detector is committed to. Construction is private —
/// the only rows that can exist are the pinned registry's ([`DETECTORS`]),
/// so downstream code can read the registry but never grow or reorder it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectorEntry {
    slug: &'static str,
    emits: DetectorEmit,
    order: u8,
    test_vectors: u16,
}

impl DetectorEntry {
    /// The detector's stable slug (the corpus document's `detector` token).
    #[must_use]
    pub fn slug(&self) -> &'static str {
        self.slug
    }

    /// The class this detector's matches become.
    #[must_use]
    pub fn emits(&self) -> DetectorEmit {
        self.emits
    }

    /// The detector's fixed precedence: detectors run in ascending `order`,
    /// and the first detector whose pattern matches decides the treatment —
    /// the ordering the deterministic redaction contract rests on.
    #[must_use]
    pub fn order(&self) -> u8 {
        self.order
    }

    /// The count of synthetic leak test vectors the v1 fixture suite
    /// commits to for this detector (a commitment to coverage, never the
    /// vector bytes — those live in the fixture corpus, not here).
    #[must_use]
    pub fn test_vectors(&self) -> u16 {
        self.test_vectors
    }

    /// The row's canonical document rendering.
    fn to_value(self) -> Value {
        let mut row = Object::new();
        row.set("detector", Value::Text(self.slug.to_owned()));
        row.set("emits", Value::Text(self.emits.token().to_owned()));
        row.set("order", Value::Int(i64::from(self.order)));
        row.set("test_vectors", Value::Int(i64::from(self.test_vectors)));
        Value::Object(row)
    }
}

/// The pinned v1 detector registry, in ascending `order` — secret markers
/// first (destroy what they match), pseudonym families after (replace what
/// they match). This table is the corpus: the order below is the
/// deterministic precedence every redaction-v1 stage must apply, and the
/// corpus digest below is computed over these rows and the pinned formats.
const DETECTORS: [DetectorEntry; 10] = [
    DetectorEntry {
        slug: "pinned-credential-formats",
        emits: DetectorEmit::Marker(MarkerClass::PinnedCredential),
        order: 1,
        test_vectors: 12,
    },
    DetectorEntry {
        slug: "authorization-headers",
        emits: DetectorEmit::Marker(MarkerClass::AuthorizationHeader),
        order: 2,
        test_vectors: 8,
    },
    DetectorEntry {
        slug: "private-key-blocks",
        emits: DetectorEmit::Marker(MarkerClass::PrivateKeyBlock),
        order: 3,
        test_vectors: 10,
    },
    DetectorEntry {
        slug: "environment-secret-assignments",
        emits: DetectorEmit::Marker(MarkerClass::EnvironmentSecret),
        order: 4,
        test_vectors: 14,
    },
    DetectorEntry {
        slug: "high-entropy-token-candidates",
        emits: DetectorEmit::Marker(MarkerClass::HighEntropyToken),
        order: 5,
        test_vectors: 16,
    },
    DetectorEntry {
        slug: "absolute-path-pseudonyms",
        emits: DetectorEmit::Pseudonym(PseudonymClass::AbsolutePath),
        order: 6,
        test_vectors: 9,
    },
    DetectorEntry {
        slug: "hostname-pseudonyms",
        emits: DetectorEmit::Pseudonym(PseudonymClass::Hostname),
        order: 7,
        test_vectors: 11,
    },
    DetectorEntry {
        slug: "username-pseudonyms",
        emits: DetectorEmit::Pseudonym(PseudonymClass::Username),
        order: 8,
        test_vectors: 7,
    },
    DetectorEntry {
        slug: "email-address-pseudonyms",
        emits: DetectorEmit::Pseudonym(PseudonymClass::EmailAddress),
        order: 9,
        test_vectors: 6,
    },
    DetectorEntry {
        slug: "ip-address-pseudonyms",
        emits: DetectorEmit::Pseudonym(PseudonymClass::IpAddress),
        order: 10,
        test_vectors: 13,
    },
];

/// The corpus document's closed top-level member set, in the fixed order
/// validation reports missing members in.
const MEMBERS: [&str; 8] = [
    "corpus_version",
    "detectors",
    "marker_format",
    "pipeline_id",
    "pseudonym_format",
    "pseudonym_key_id_construction",
    "structured_field_allowlist",
    "test_suite_sha256",
];

/// A detector document row's closed member set.
const DETECTOR_MEMBERS: [&str; 4] = ["detector", "emits", "order", "test_vectors"];

/// Input bound on a document's `detectors` array: validation walks at most
/// this many rows before refusing, so a hostile policy document cannot make
/// recognition unbounded. Larger than the registry, smaller than unbounded.
const MAX_INPUT_DETECTORS: usize = 64;

/// Input bound on a document's `structured_field_allowlist` array, same
/// purpose as [`MAX_INPUT_DETECTORS`].
const MAX_INPUT_ALLOWLIST: usize = 16;

/// Why a corpus document is not the v1 corpus. Every variant is
/// content-free — it names the structural fault, never the offending input
/// text, so an error can never become a channel for the very material the
/// pipeline exists to redact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorpusError {
    /// The document is not a JSON object.
    NotAnObject,
    /// The document carries a member outside the closed v1 member set.
    UnknownMember,
    /// A required v1 member is absent.
    MissingMember(&'static str),
    /// A member that must be a JSON string is not one.
    MemberNotText(&'static str),
    /// A member that must be a JSON array is not one.
    MemberNotArray(&'static str),
    /// The corpus version is well-formed but not v1's — a document from
    /// another pipeline version must not be processed under v1 rules.
    UnsupportedCorpusVersion,
    /// The pipeline id is well-formed but not `redaction`.
    UnsupportedPipelineId,
    /// A pinned format or commitment member drifted from the compiled-in
    /// value.
    PinnedTextMismatch(&'static str),
    /// The allowlist carries more entries than the input bound permits.
    AllowlistTooLong,
    /// An allowlist entry is not a JSON string.
    AllowlistEntryNotText,
    /// An allowlist entry is a string but outside the closed field
    /// vocabulary.
    UnknownAllowlistField,
    /// The allowlist is not exactly the pinned v1 field set (an entry is
    /// missing or duplicated).
    IncompleteAllowlist,
    /// The detector table carries more rows than the input bound permits.
    DetectorRowsExceeded,
    /// A detector row is not a JSON object.
    DetectorRowNotObject,
    /// A detector row is an object but its member set is not exactly the
    /// closed four (a member is missing, mistyped, or unknown).
    DetectorRowShape,
    /// A detector row's slug is not in the v1 registry.
    UnknownDetector,
    /// A detector row's `emits` token is not in the closed class
    /// vocabulary.
    UnknownDetectorClass,
    /// A known detector drifted: its `emits`, `order`, or `test_vectors`
    /// does not equal the pinned registry row.
    DetectorRowMismatch,
    /// The detector table is not exactly the pinned registry's row set — a
    /// row is missing or duplicated.
    DetectorSetIncomplete,
}

impl std::fmt::Display for CorpusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnObject => write!(f, "corpus document is not an object"),
            Self::UnknownMember => write!(f, "corpus document carries an unknown member"),
            Self::MissingMember(name) => write!(f, "corpus member `{name}` is missing"),
            Self::MemberNotText(name) => write!(f, "corpus member `{name}` must be a string"),
            Self::MemberNotArray(name) => write!(f, "corpus member `{name}` must be an array"),
            Self::UnsupportedCorpusVersion => {
                write!(f, "corpus document is not corpus version {CORPUS_VERSION}")
            }
            Self::UnsupportedPipelineId => {
                write!(f, "corpus document is not the `{PIPELINE_ID}` pipeline")
            }
            Self::PinnedTextMismatch(name) => {
                write!(f, "corpus member `{name}` drifted from the pinned value")
            }
            Self::AllowlistTooLong => {
                write!(
                    f,
                    "allowlist exceeds the input bound of {MAX_INPUT_ALLOWLIST}"
                )
            }
            Self::AllowlistEntryNotText => write!(f, "allowlist entry must be a string"),
            Self::UnknownAllowlistField => {
                write!(f, "allowlist names a field outside the closed vocabulary")
            }
            Self::IncompleteAllowlist => {
                write!(f, "allowlist is not exactly the pinned v1 field set")
            }
            Self::DetectorRowsExceeded => {
                write!(
                    f,
                    "detector table exceeds the input bound of {MAX_INPUT_DETECTORS}"
                )
            }
            Self::DetectorRowNotObject => write!(f, "detector row must be an object"),
            Self::DetectorRowShape => {
                write!(
                    f,
                    "detector row must carry exactly detector, emits, order, test_vectors"
                )
            }
            Self::UnknownDetector => {
                write!(f, "detector row names a detector outside the registry")
            }
            Self::UnknownDetectorClass => {
                write!(
                    f,
                    "detector row emits a class outside the closed vocabulary"
                )
            }
            Self::DetectorRowMismatch => {
                write!(f, "detector row drifted from its pinned registry entry")
            }
            Self::DetectorSetIncomplete => {
                write!(
                    f,
                    "detector table is not exactly the pinned registry's row set"
                )
            }
        }
    }
}

impl std::error::Error for CorpusError {}

/// A document member's text value, or the typed refusal.
fn text_member<'a>(document: &'a Object, name: &'static str) -> Result<&'a str, CorpusError> {
    match document.get(name) {
        Some(Value::Text(text)) => Ok(text),
        _ => Err(CorpusError::MemberNotText(name)),
    }
}

/// The immutable `redaction-v1` detector corpus: the policy artifact the
/// whole pipeline is frozen inside, and the thing the derived episode's
/// `detector_corpus_digest` names. The type has exactly one value — the
/// pinned corpus — so holding one *is* the proof that a corpus document
/// was recognized as v1 (or that the pinned corpus is in use directly).
///
/// Build one with [`RedactionCorpus::pinned`] (the compiled-in corpus) or
/// recognize a document with [`RedactionCorpus::from_value`]; both produce
/// the same value or an error, never a variant.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RedactionCorpus;

impl RedactionCorpus {
    /// The compiled-in v1 corpus.
    #[must_use]
    pub fn pinned() -> Self {
        Self
    }

    /// Recognize a corpus document as the v1 corpus, failing closed on
    /// anything else.
    ///
    /// The document must be an object whose member set is exactly the
    /// closed v1 set; every pinned member must equal the compiled-in value
    /// ([`CORPUS_VERSION`], [`PIPELINE_ID`], the three format strings, the
    /// test-suite commitment, the full allowlist, and the full detector
    /// table with each row's slug, emitted class, order, and test-vector
    /// count). Only the two arrays' *document order* is normalized away —
    /// the allowlist and the registry are exposed in their pinned orders
    /// regardless of the order the document lists them in, so input data
    /// cannot change what the seam exposes by rearranging itself.
    ///
    /// # Errors
    /// The first fault in a fixed order — shape, then member set, then
    /// types, then values — as a [`CorpusError`] naming the structural
    /// fault. Nothing about the document is carried into the error.
    pub fn from_value(value: &Value) -> Result<Self, CorpusError> {
        let Value::Object(document) = value else {
            return Err(CorpusError::NotAnObject);
        };

        for (name, _) in document.iter() {
            if !MEMBERS.contains(&name) {
                return Err(CorpusError::UnknownMember);
            }
        }
        for name in MEMBERS {
            if !document.contains(name) {
                return Err(CorpusError::MissingMember(name));
            }
        }

        for name in [
            "corpus_version",
            "marker_format",
            "pipeline_id",
            "pseudonym_format",
            "pseudonym_key_id_construction",
            "test_suite_sha256",
        ] {
            text_member(document, name)?;
        }
        for name in ["detectors", "structured_field_allowlist"] {
            if !matches!(document.get(name), Some(Value::Array(_))) {
                return Err(CorpusError::MemberNotArray(name));
            }
        }

        // Shape is sound; now the values, in a fixed order so a document
        // with several faults always reports the same first one.
        if text_member(document, "corpus_version")? != CORPUS_VERSION {
            return Err(CorpusError::UnsupportedCorpusVersion);
        }
        if text_member(document, "pipeline_id")? != PIPELINE_ID {
            return Err(CorpusError::UnsupportedPipelineId);
        }
        for (name, pinned) in [
            ("marker_format", MARKER_FORMAT),
            ("pseudonym_format", PSEUDONYM_FORMAT),
            (
                "pseudonym_key_id_construction",
                PSEUDONYM_KEY_ID_CONSTRUCTION,
            ),
        ] {
            if text_member(document, name)? != pinned {
                return Err(CorpusError::PinnedTextMismatch(name));
            }
        }
        if text_member(document, "test_suite_sha256")?
            != sha256::encode_hex(&sha256::digest(TEST_SUITE_CORPUS))
        {
            return Err(CorpusError::PinnedTextMismatch("test_suite_sha256"));
        }

        Self::validate_allowlist(
            document
                .get("structured_field_allowlist")
                .map_or(&Value::Null, |value| value),
        )?;
        Self::validate_detectors(
            document
                .get("detectors")
                .map_or(&Value::Null, |value| value),
        )?;

        // Every pinned member matched: the document *is* the v1 corpus.
        Ok(Self)
    }

    /// The corpus document's version ([`CORPUS_VERSION`]).
    #[must_use]
    pub fn corpus_version(&self) -> &'static str {
        CORPUS_VERSION
    }

    /// The pipeline this corpus belongs to ([`PIPELINE_ID`]).
    #[must_use]
    pub fn pipeline_id(&self) -> &'static str {
        PIPELINE_ID
    }

    /// The immutable pipeline version this corpus is frozen inside
    /// ([`PIPELINE_VERSION`]).
    #[must_use]
    pub fn pipeline_version(&self) -> &'static str {
        PIPELINE_VERSION
    }

    /// The structured-field allowlist, in pinned order: the complete,
    /// closed set of occurrence fields a redaction-v1 record retains. A
    /// field outside it survives nowhere.
    #[must_use]
    pub fn allowlist(&self) -> &'static [StructuredField] {
        &StructuredField::ALL
    }

    /// The ordered detector registry, ascending by [`DetectorEntry::order`]
    /// — the deterministic precedence the redaction transformation applies.
    #[must_use]
    pub fn detectors(&self) -> &'static [DetectorEntry] {
        &DETECTORS
    }

    /// The registry row for a detector slug, if the slug is v1's.
    #[must_use]
    pub fn detector(&self, slug: &str) -> Option<&'static DetectorEntry> {
        DETECTORS.iter().find(|entry| entry.slug == slug)
    }

    /// The irreversible marker classes, in registry order — the complete,
    /// closed set the episode's `marker_counts` census enumerates.
    #[must_use]
    pub fn marker_classes(&self) -> &'static [MarkerClass] {
        &MarkerClass::ALL
    }

    /// The pseudonym classes, in registry order — the complete, closed set
    /// the episode's `pseudonym_counts` census enumerates.
    #[must_use]
    pub fn pseudonym_classes(&self) -> &'static [PseudonymClass] {
        &PseudonymClass::ALL
    }

    /// The irreversible marker text for `class` under the pinned
    /// [`MARKER_FORMAT`].
    #[must_use]
    pub fn marker_text(&self, class: MarkerClass) -> &'static str {
        class.marker_text()
    }

    /// The test-corpus commitment the corpus document carries as its
    /// `test_suite_sha256`: SHA-256 over the pinned synthetic suite label
    /// ([`TEST_SUITE_CORPUS`]).
    #[must_use]
    pub fn test_suite_digest(&self) -> String {
        sha256::encode_hex(&sha256::digest(TEST_SUITE_CORPUS))
    }

    /// The corpus's canonical document rendering: the same member assembly
    /// the pinned example corpus file holds, with the allowlist and the
    /// detector table in their pinned orders.
    #[must_use]
    pub fn canonical_value(&self) -> Value {
        let mut corpus = Object::new();
        corpus.set("corpus_version", Value::Text(CORPUS_VERSION.to_owned()));
        corpus.set(
            "detectors",
            Value::Array(DETECTORS.iter().map(|entry| entry.to_value()).collect()),
        );
        corpus.set("marker_format", Value::Text(MARKER_FORMAT.to_owned()));
        corpus.set("pipeline_id", Value::Text(PIPELINE_ID.to_owned()));
        corpus.set("pseudonym_format", Value::Text(PSEUDONYM_FORMAT.to_owned()));
        corpus.set(
            "pseudonym_key_id_construction",
            Value::Text(PSEUDONYM_KEY_ID_CONSTRUCTION.to_owned()),
        );
        corpus.set(
            "structured_field_allowlist",
            Value::Array(
                StructuredField::ALL
                    .iter()
                    .map(|field| Value::Text(field.token().to_owned()))
                    .collect(),
            ),
        );
        corpus.set("test_suite_sha256", Value::Text(self.test_suite_digest()));
        Value::Object(corpus)
    }

    /// The corpus's RFC 8785 canonical bytes — the digest preimage, and the
    /// byte-exact rendering the pinned example corpus file holds.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_value().canonical_bytes()
    }

    /// The corpus digest: SHA-256 over [`RedactionCorpus::canonical_bytes`].
    /// This is the value the derived episode carries as
    /// `detector_corpus_digest` — the derivation's behavior, content
    /// addressed.
    #[must_use]
    pub fn digest(&self) -> String {
        sha256::encode_hex(&sha256::digest(&self.canonical_bytes()))
    }

    /// Validate the document's allowlist against the pinned field set.
    fn validate_allowlist(entries: &Value) -> Result<(), CorpusError> {
        let Value::Array(entries) = entries else {
            return Err(CorpusError::MemberNotArray("structured_field_allowlist"));
        };
        if entries.len() > MAX_INPUT_ALLOWLIST {
            return Err(CorpusError::AllowlistTooLong);
        }
        let mut seen = [false; StructuredField::ALL.len()];
        for entry in entries {
            let Value::Text(token) = entry else {
                return Err(CorpusError::AllowlistEntryNotText);
            };
            let Some(field) = StructuredField::parse(token) else {
                return Err(CorpusError::UnknownAllowlistField);
            };
            let at = StructuredField::ALL
                .iter()
                .position(|pinned| *pinned == field);
            let Some(at) = at.filter(|at| !seen[*at]) else {
                // Not reachable for a parsed field (every field has a slot)
                // unless the slot is already taken — a duplicated entry.
                return Err(CorpusError::IncompleteAllowlist);
            };
            seen[at] = true;
        }
        if seen.iter().any(|present| !present) {
            return Err(CorpusError::IncompleteAllowlist);
        }
        Ok(())
    }

    /// Validate the document's detector table against the pinned registry.
    fn validate_detectors(rows: &Value) -> Result<(), CorpusError> {
        let Value::Array(rows) = rows else {
            return Err(CorpusError::MemberNotArray("detectors"));
        };
        if rows.len() > MAX_INPUT_DETECTORS {
            return Err(CorpusError::DetectorRowsExceeded);
        }
        let mut seen = [false; DETECTORS.len()];
        for row in rows {
            let Value::Object(row) = row else {
                return Err(CorpusError::DetectorRowNotObject);
            };
            for (name, _) in row.iter() {
                if !DETECTOR_MEMBERS.contains(&name) {
                    return Err(CorpusError::DetectorRowShape);
                }
            }
            for name in DETECTOR_MEMBERS {
                if !row.contains(name) {
                    return Err(CorpusError::DetectorRowShape);
                }
            }
            let Value::Text(slug) = row.get("detector").map_or(&Value::Null, |value| value) else {
                return Err(CorpusError::DetectorRowShape);
            };
            let Some(pinned) = Self::pinned().detector(slug) else {
                return Err(CorpusError::UnknownDetector);
            };
            let Value::Text(emits) = row.get("emits").map_or(&Value::Null, |value| value) else {
                return Err(CorpusError::DetectorRowShape);
            };
            let Some(parsed_emit) = DetectorEmit::parse(emits) else {
                return Err(CorpusError::UnknownDetectorClass);
            };
            let (Value::Int(order), Value::Int(test_vectors)) = (
                row.get("order").map_or(&Value::Null, |value| value),
                row.get("test_vectors").map_or(&Value::Null, |value| value),
            ) else {
                return Err(CorpusError::DetectorRowShape);
            };
            if parsed_emit != pinned.emits()
                || *order != i64::from(pinned.order())
                || *test_vectors != i64::from(pinned.test_vectors())
            {
                return Err(CorpusError::DetectorRowMismatch);
            }
            let at = DETECTORS.iter().position(|entry| entry == pinned);
            let Some(at) = at.filter(|at| !seen[*at]) else {
                // A duplicate known row.
                return Err(CorpusError::DetectorSetIncomplete);
            };
            seen[at] = true;
        }
        if seen.iter().any(|present| !present) {
            return Err(CorpusError::DetectorSetIncomplete);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pinned example corpus document, exactly as committed —
    /// canonical bytes plus one trailing LF (the family-wide rendering).
    const PINNED_DOCUMENT: &str =
        include_str!("../../../schemas/v1/examples/episodes/pipeline/redaction-v1-corpus.json");

    /// The corpus digest the pinned example materializes (computed by
    /// `tools/episodegen.py` over the corpus document's canonical bytes;
    /// pinned here so a Rust canonicalization or registry drift cannot go
    /// unnoticed).
    const PINNED_DIGEST: &str = "b9122c5acd2db88b18277eebf40478e322db5dda8a682fc7df79f53d1327d0f8";

    /// The reversible-redaction member names the episode schema rejects by
    /// name — none of which the corpus can carry.
    const REVERSIBLE_REDACTION_NAMES: [&str; 8] = [
        "redaction_map",
        "pseudonym_map",
        "reverse_map",
        "removed_content",
        "plaintext",
        "mapping",
        "salt",
        "pseudonym_salt",
    ];

    /// The parsed pinned document.
    fn pinned_value() -> Value {
        crate::json::parse(PINNED_DOCUMENT.as_bytes()).expect("pinned corpus parses")
    }

    /// The pinned document with one mutation applied (by JSON surgery on
    /// the parsed value) and re-rendered, for the fail-closed matrix.
    fn mutated(mut edit: impl FnMut(&mut Object)) -> Value {
        let Value::Object(mut document) = pinned_value() else {
            panic!("pinned corpus is an object");
        };
        edit(&mut document);
        Value::Object(document)
    }

    fn error_of(value: &Value) -> CorpusError {
        RedactionCorpus::from_value(value).expect_err("mutated corpus must fail closed")
    }

    fn replaced_text(document: &mut Object, name: &str, text: &str) {
        document.set(name, Value::Text(text.to_owned()));
    }

    #[test]
    fn vocabularies_are_bounded_and_pinned() {
        assert_eq!(
            StructuredField::ALL.map(StructuredField::token),
            ["role", "ordinal", "source_time", "parent_ordinals"]
        );
        assert_eq!(
            MarkerClass::ALL.map(MarkerClass::token),
            [
                "pinned_credential",
                "authorization_header",
                "private_key_block",
                "environment_secret",
                "high_entropy_token",
            ]
        );
        assert_eq!(
            PseudonymClass::ALL.map(PseudonymClass::token),
            [
                "absolute_path",
                "hostname",
                "username",
                "email_address",
                "ip_address",
            ]
        );
    }

    #[test]
    fn vocabularies_are_disjoint() {
        for field in StructuredField::ALL {
            assert!(MarkerClass::parse(field.token()).is_none());
            assert!(PseudonymClass::parse(field.token()).is_none());
        }
        for marker in MarkerClass::ALL {
            assert!(PseudonymClass::parse(marker.token()).is_none());
        }
        for pseudonym in PseudonymClass::ALL {
            assert!(MarkerClass::parse(pseudonym.token()).is_none());
        }
    }

    #[test]
    fn token_parse_roundtrips_and_refuses_unknowns() {
        for field in StructuredField::ALL {
            assert_eq!(StructuredField::parse(field.token()), Some(field));
        }
        for marker in MarkerClass::ALL {
            assert_eq!(MarkerClass::parse(marker.token()), Some(marker));
        }
        for pseudonym in PseudonymClass::ALL {
            assert_eq!(PseudonymClass::parse(pseudonym.token()), Some(pseudonym));
        }
        for unknown in ["", "Role", "content", "redaction_map", "high_entropy"] {
            assert_eq!(StructuredField::parse(unknown), None);
            assert_eq!(MarkerClass::parse(unknown), None);
            assert_eq!(PseudonymClass::parse(unknown), None);
        }
    }

    #[test]
    fn marker_text_matches_the_pinned_format() {
        for marker in MarkerClass::ALL {
            assert_eq!(
                marker.marker_text(),
                MARKER_FORMAT.replace("{class_token}", marker.token()),
                "marker text must be the pinned format with the class token substituted"
            );
            let text = marker.marker_text();
            assert!(text.starts_with("[redacted:"));
            assert!(text.ends_with(']'));
            assert!(text.contains(marker.token()));
            assert_eq!(RedactionCorpus::pinned().marker_text(marker), text);
        }
    }

    #[test]
    fn detector_registry_is_ordered_total_and_pinned() {
        let corpus = RedactionCorpus::pinned();
        let detectors = corpus.detectors();
        assert_eq!(detectors.len(), 10);
        for (position, entry) in detectors.iter().enumerate() {
            assert_eq!(
                entry.order() as usize,
                position + 1,
                "orders are 1..=10 dense"
            );
        }
        let pinned: [(&str, DetectorEmit, u16); 10] = [
            (
                "pinned-credential-formats",
                DetectorEmit::Marker(MarkerClass::PinnedCredential),
                12,
            ),
            (
                "authorization-headers",
                DetectorEmit::Marker(MarkerClass::AuthorizationHeader),
                8,
            ),
            (
                "private-key-blocks",
                DetectorEmit::Marker(MarkerClass::PrivateKeyBlock),
                10,
            ),
            (
                "environment-secret-assignments",
                DetectorEmit::Marker(MarkerClass::EnvironmentSecret),
                14,
            ),
            (
                "high-entropy-token-candidates",
                DetectorEmit::Marker(MarkerClass::HighEntropyToken),
                16,
            ),
            (
                "absolute-path-pseudonyms",
                DetectorEmit::Pseudonym(PseudonymClass::AbsolutePath),
                9,
            ),
            (
                "hostname-pseudonyms",
                DetectorEmit::Pseudonym(PseudonymClass::Hostname),
                11,
            ),
            (
                "username-pseudonyms",
                DetectorEmit::Pseudonym(PseudonymClass::Username),
                7,
            ),
            (
                "email-address-pseudonyms",
                DetectorEmit::Pseudonym(PseudonymClass::EmailAddress),
                6,
            ),
            (
                "ip-address-pseudonyms",
                DetectorEmit::Pseudonym(PseudonymClass::IpAddress),
                13,
            ),
        ];
        for (entry, (slug, emits, vectors)) in detectors.iter().zip(pinned) {
            assert_eq!(entry.slug(), slug);
            assert_eq!(entry.emits(), emits);
            assert_eq!(entry.test_vectors(), vectors);
            assert!(
                entry.test_vectors() > 0,
                "every detector commits to coverage"
            );
        }
        // The registry covers each class exactly once, and the marker and
        // pseudonym families occupy disjoint order ranges (markers first).
        for marker in MarkerClass::ALL {
            let emitters: Vec<_> = detectors
                .iter()
                .filter(|entry| entry.emits() == DetectorEmit::Marker(marker))
                .collect();
            assert_eq!(emitters.len(), 1, "{marker:?} has exactly one detector");
            assert!(emitters[0].order() <= 5);
        }
        for pseudonym in PseudonymClass::ALL {
            let emitters: Vec<_> = detectors
                .iter()
                .filter(|entry| entry.emits() == DetectorEmit::Pseudonym(pseudonym))
                .collect();
            assert_eq!(emitters.len(), 1, "{pseudonym:?} has exactly one detector");
            assert!(emitters[0].order() >= 6);
        }
    }

    #[test]
    fn detector_emit_parse_roundtrips() {
        for entry in RedactionCorpus::pinned().detectors() {
            assert_eq!(
                DetectorEmit::parse(entry.emits().token()),
                Some(entry.emits())
            );
        }
        assert_eq!(DetectorEmit::parse("shrine"), None);
        assert_eq!(
            DetectorEmit::parse("hostname"),
            Some(DetectorEmit::Pseudonym(PseudonymClass::Hostname))
        );
        assert_eq!(
            DetectorEmit::parse("hostname").and_then(DetectorEmit::marker_class),
            None
        );
        assert_eq!(
            DetectorEmit::parse("hostname").and_then(DetectorEmit::pseudonym_class),
            Some(PseudonymClass::Hostname)
        );
    }

    #[test]
    fn detector_lookup_finds_only_registry_slugs() {
        let corpus = RedactionCorpus::pinned();
        for entry in corpus.detectors() {
            assert_eq!(corpus.detector(entry.slug()), Some(entry));
        }
        assert_eq!(corpus.detector("hostname-sniffer"), None);
        assert_eq!(corpus.detector(""), None);
    }

    #[test]
    fn pinned_corpus_matches_the_example_file_byte_for_byte() {
        let corpus = RedactionCorpus::pinned();
        let canonical = corpus.canonical_bytes();
        let file = PINNED_DOCUMENT.as_bytes();
        let rendered = &file[..file.len() - 1];
        assert!(
            !std::str::from_utf8(rendered)
                .expect("file is utf-8")
                .ends_with('\n'),
            "exactly one trailing LF was excluded"
        );
        assert_eq!(
            canonical, rendered,
            "the compiled-in corpus must render byte-identically to the committed example"
        );
        assert_eq!(RedactionCorpus::from_value(&pinned_value()), Ok(corpus));
    }

    #[test]
    fn corpus_digest_is_pinned_and_is_the_canonical_bytes_hash() {
        let corpus = RedactionCorpus::pinned();
        assert_eq!(corpus.digest(), PINNED_DIGEST);
        assert_eq!(
            corpus.digest(),
            sha256::encode_hex(&sha256::digest(&corpus.canonical_bytes()))
        );
    }

    #[test]
    fn identity_and_label_constants_agree() {
        assert_eq!(PIPELINE_ID, "redaction");
        assert_eq!(PIPELINE_VERSION, "1");
        assert_eq!(CORPUS_VERSION, "1");
        assert_eq!(RedactionCorpus::pinned().pipeline_id(), PIPELINE_ID);
        assert_eq!(
            RedactionCorpus::pinned().pipeline_version(),
            PIPELINE_VERSION
        );
        assert_eq!(RedactionCorpus::pinned().corpus_version(), CORPUS_VERSION);
        assert!(
            PSEUDONYM_KEY_ID_CONSTRUCTION.contains(PSEUDONYM_KEY_ID_LABEL),
            "the construction string names its own HMAC label"
        );
        assert_eq!(
            RedactionCorpus::pinned().test_suite_digest(),
            sha256::encode_hex(&sha256::digest(TEST_SUITE_CORPUS))
        );
    }

    #[test]
    fn fail_closed_matrix() {
        let corpus_value = pinned_value();
        let document = |edit: &mut dyn FnMut(&mut Object)| {
            let Value::Object(mut document) = corpus_value.clone() else {
                panic!("pinned corpus is an object");
            };
            edit(&mut document);
            Value::Object(document)
        };

        assert_eq!(error_of(&Value::Int(1)), CorpusError::NotAnObject);
        assert_eq!(
            error_of(&Value::Array(Vec::new())),
            CorpusError::NotAnObject
        );

        let with_unknown = |name: &str| {
            document(&mut |document| {
                document.set(name, Value::Text("x".to_owned()));
            })
        };
        assert_eq!(
            error_of(&with_unknown("detector_patterns")),
            CorpusError::UnknownMember
        );
        assert_eq!(
            error_of(&with_unknown("redaction_map")),
            CorpusError::UnknownMember,
            "a reversible-redaction member cannot sneak in"
        );
        assert_eq!(
            error_of(&with_unknown("plaintext")),
            CorpusError::UnknownMember
        );

        let without = |name: &str| {
            document(&mut |document| {
                document.remove(name).expect("pinned member is present");
            })
        };
        assert_eq!(
            error_of(&without("corpus_version")),
            CorpusError::MissingMember("corpus_version")
        );
        assert_eq!(
            error_of(&without("detectors")),
            CorpusError::MissingMember("detectors")
        );
        assert_eq!(
            error_of(&without("test_suite_sha256")),
            CorpusError::MissingMember("test_suite_sha256")
        );

        let text_swapped = |name: &str| {
            document(&mut |document| {
                document.set(name, Value::Int(1));
            })
        };
        assert_eq!(
            error_of(&text_swapped("corpus_version")),
            CorpusError::MemberNotText("corpus_version")
        );
        assert_eq!(
            error_of(&text_swapped("marker_format")),
            CorpusError::MemberNotText("marker_format")
        );
        assert_eq!(
            error_of(&document(&mut |document| {
                document.set("structured_field_allowlist", Value::Int(4));
            })),
            CorpusError::MemberNotArray("structured_field_allowlist")
        );
        assert_eq!(
            error_of(&document(&mut |document| {
                document.set("detectors", Value::Object(Object::new()));
            })),
            CorpusError::MemberNotArray("detectors")
        );

        let version_two = document(&mut |document| {
            replaced_text(document, "corpus_version", "2");
        });
        assert_eq!(
            error_of(&version_two),
            CorpusError::UnsupportedCorpusVersion
        );
        let other_pipeline = document(&mut |document| {
            replaced_text(document, "pipeline_id", "scrub");
        });
        assert_eq!(
            error_of(&other_pipeline),
            CorpusError::UnsupportedPipelineId
        );
        for (name, text) in [
            ("marker_format", "[redacted <{class_token}>]"),
            ("pseudonym_format", "psn-<class>"),
            ("pseudonym_key_id_construction", "SHA-256(pseudonym key)"),
            ("test_suite_sha256", &"0".repeat(64)),
        ] {
            let drifted = document(&mut |document| replaced_text(document, name, text));
            assert_eq!(error_of(&drifted), CorpusError::PinnedTextMismatch(name));
        }
    }

    #[test]
    fn fail_closed_matrix_for_the_allowlist() {
        let allowlist = |entries: Vec<Value>| {
            let Value::Object(mut document) = pinned_value() else {
                panic!("pinned corpus is an object");
            };
            document.set("structured_field_allowlist", Value::Array(entries));
            error_of(&Value::Object(document))
        };
        let field = |token: &str| Value::Text(token.to_owned());

        assert_eq!(
            allowlist(vec![field("role"), field("ordinal"), field("source_time")]),
            CorpusError::IncompleteAllowlist,
            "a subset allowlist is not the v1 policy"
        );
        assert_eq!(
            allowlist(vec![
                field("role"),
                field("ordinal"),
                field("source_time"),
                field("parent_ordinals"),
                field("role"),
            ]),
            CorpusError::IncompleteAllowlist,
            "a duplicated entry is not the v1 policy"
        );
        assert_eq!(
            allowlist(vec![
                field("role"),
                field("ordinal"),
                field("source_time"),
                field("content"),
            ]),
            CorpusError::UnknownAllowlistField,
            "the redacted content rendering is not an allowlisted structured field"
        );
        assert_eq!(
            allowlist(vec![
                field("role"),
                Value::Int(2),
                field("source_time"),
                field("parent_ordinals")
            ]),
            CorpusError::AllowlistEntryNotText
        );
        assert_eq!(
            allowlist(
                (0..17)
                    .map(|index| field(&format!("role{index}")))
                    .collect()
            ),
            CorpusError::AllowlistTooLong,
            "an over-long allowlist is refused before its entries are walked"
        );
    }

    #[test]
    fn fail_closed_matrix_for_the_detector_table() {
        let corpus_value = pinned_value();
        let detectors_edit = |edit: &mut dyn FnMut(&mut Vec<Value>)| {
            let Value::Object(mut document) = corpus_value.clone() else {
                panic!("pinned corpus is an object");
            };
            let Some(Value::Array(mut detectors)) = document.remove("detectors") else {
                panic!("detectors is an array");
            };
            edit(&mut detectors);
            document.set("detectors", Value::Array(detectors));
            error_of(&Value::Object(document))
        };
        let row_with = |slug: &str, emits: &str, order: i64, vectors: i64| {
            let mut row = Object::new();
            row.set("detector", Value::Text(slug.to_owned()));
            row.set("emits", Value::Text(emits.to_owned()));
            row.set("order", Value::Int(order));
            row.set("test_vectors", Value::Int(vectors));
            Value::Object(row)
        };
        let pinned_row = |slug: &str| {
            let corpus = RedactionCorpus::pinned();
            let entry = corpus.detector(slug).expect("registry slug");
            entry.to_value()
        };

        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = Value::Int(1);
            }),
            CorpusError::DetectorRowNotObject
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = row_with("hostname-sniffer", "hostname", 1, 3);
            }),
            CorpusError::UnknownDetector
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = row_with("pinned-credential-formats", "shrine", 1, 12);
            }),
            CorpusError::UnknownDetectorClass
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = row_with("pinned-credential-formats", "hostname", 1, 12);
            }),
            CorpusError::DetectorRowMismatch,
            "a known detector cannot change what it emits"
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = row_with("pinned-credential-formats", "pinned_credential", 2, 12);
            }),
            CorpusError::DetectorRowMismatch,
            "a known detector cannot change its precedence"
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors[0] = row_with("pinned-credential-formats", "pinned_credential", 1, 13);
            }),
            CorpusError::DetectorRowMismatch,
            "a known detector cannot change its coverage commitment"
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors.push(pinned_row("pinned-credential-formats"));
            }),
            CorpusError::DetectorSetIncomplete,
            "a duplicated row is not the v1 registry"
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                detectors.pop();
            }),
            CorpusError::DetectorSetIncomplete,
            "a missing row is not the v1 registry"
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                while detectors.len() <= MAX_INPUT_DETECTORS {
                    detectors.push(row_with("row", "hostname", 1, 1));
                }
            }),
            CorpusError::DetectorRowsExceeded
        );
        assert_eq!(
            detectors_edit(&mut |detectors| {
                let Some(Value::Object(mut row)) = detectors.first().cloned() else {
                    panic!("first row is an object");
                };
                row.set("pattern", Value::Text(".*".to_owned()));
                detectors[0] = Value::Object(row);
            }),
            CorpusError::DetectorRowShape,
            "a detector row cannot carry pattern text or any unknown member"
        );
    }

    #[test]
    fn input_array_order_cannot_change_the_seam() {
        // Reversing both arrays is the strongest reordering a document can
        // carry: the recognition must normalize it away.
        let reordered = mutated(|document| {
            let Some(Value::Array(mut detectors)) = document.remove("detectors") else {
                panic!("detectors is an array");
            };
            detectors.reverse();
            document.set("detectors", Value::Array(detectors));
            let Some(Value::Array(mut allowlist)) = document.remove("structured_field_allowlist")
            else {
                panic!("allowlist is an array");
            };
            allowlist.reverse();
            document.set("structured_field_allowlist", Value::Array(allowlist));
        });
        let corpus = RedactionCorpus::from_value(&reordered).expect("reordering is not a change");
        let pinned = RedactionCorpus::pinned();
        assert_eq!(corpus, pinned);
        assert_eq!(corpus.allowlist(), pinned.allowlist());
        let corpus_slugs: Vec<_> = corpus.detectors().iter().map(DetectorEntry::slug).collect();
        let pinned_slugs: Vec<_> = pinned.detectors().iter().map(DetectorEntry::slug).collect();
        assert_eq!(corpus_slugs, pinned_slugs);
        assert_eq!(corpus.digest(), pinned.digest());
    }

    #[test]
    fn corpus_carries_only_content_free_metadata() {
        let Value::Object(document) = pinned_value() else {
            panic!("pinned corpus is an object");
        };
        let member_names: Vec<_> = document.iter().map(|(name, _)| name).collect();
        assert_eq!(member_names.len(), MEMBERS.len());
        for name in member_names {
            assert!(
                MEMBERS.contains(&name),
                "`{name}` is outside the closed member set"
            );
            assert!(
                !REVERSIBLE_REDACTION_NAMES.contains(&name),
                "`{name}` is reversible-redaction material and must be unrepresentable"
            );
        }
        let Some(Value::Array(detectors)) = document.get("detectors") else {
            panic!("detectors is an array");
        };
        for row in detectors {
            let Value::Object(row) = row else {
                panic!("detector rows are objects");
            };
            assert_eq!(row.len(), DETECTOR_MEMBERS.len());
            for (name, value) in row.iter() {
                assert!(DETECTOR_MEMBERS.contains(&name));
                assert!(
                    !REVERSIBLE_REDACTION_NAMES.contains(&name),
                    "`{name}` is reversible-redaction material"
                );
                // A count or a pinned token: never pattern text, never a
                // test-vector byte.
                assert!(matches!(value, Value::Text(_) | Value::Int(_)));
            }
        }
    }
}
