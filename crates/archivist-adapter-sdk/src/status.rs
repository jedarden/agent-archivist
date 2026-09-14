// SPDX-License-Identifier: Apache-2.0

//! The bounded, content-free source-status contract: what one read-only
//! inventory pass observes per source ([`SourceScan`]), and the aggregate
//! adapter/account status the client exposes from it
//! ([`AdapterAccountStatus`]) (plan Section 6 client data flow step 2,
//! requirement CAP-010).
//!
//! Two rules shape every type in this module:
//!
//! - **Content-free.** A status names a source by its derived identifier
//!   and an account by a configuration-chosen label. No field can carry a
//!   filesystem path, a transcript excerpt, or a raw upstream account value:
//!   the identifier and label grammars reject path separators outright, the
//!   coverage and classification vocabularies are closed enums of fixed
//!   tokens, and every remaining field is an integer count or sum. This is
//!   the same redaction rule the client state schema enforces at the
//!   database level.
//! - **Bounded.** One [`AdapterAccountStatus`] is a fixed key set of
//!   fixed-width counters. Its canonical JSON size is independent of how
//!   many sources, sessions, or bytes an account holds — the per-source
//!   detail stays with the scheduling engine and never enters status — so a
//!   fleet with tens of thousands of sessions per host produces status
//!   documents of constant shape and size.

use std::fmt;
use std::str::FromStr;

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::{AdapterId, GrammarError, Timestamp};

/// Define a validated text identifier for the status vocabulary: parsed at
/// construction, canonical by the grammar's construction, never carrying
/// anything but its bounded token.
macro_rules! status_id {
    ($(#[$doc:meta])* $name:ident, $validate:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Adopt `text` after verifying its grammar.
            ///
            /// # Errors
            /// [`GrammarError::NotCanonical`] when the grammar fails.
            pub fn parse(text: &str) -> Result<Self, GrammarError> {
                if ($validate)(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(GrammarError::NotCanonical)
                }
            }

            /// The canonical text of this identifier.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

status_id!(
    /// The client-side identifier of one capture source: the 36-character
    /// lowercase UUID-shape the state schema pins for `sources.source_id`
    /// (plan Section 7.4). A scan and the state database join on this
    /// value, and it is derived from session and artifact hashes — never a
    /// path.
    SourceId,
    |t: &str| source_id_grammar(t)
);
status_id!(
    /// The configuration-chosen label of one account or source root within
    /// an adapter (plan Section 6, "discover configured accounts and source
    /// roots through adapters"). The label is a routing name the operator
    /// picked — never an upstream account identifier value, which the
    /// inventory must not project (the fleet inventory's sanitization
    /// contract). 1–64 characters of `[A-Za-z0-9._:-]` with an
    /// alphanumeric first character: no separators, whitespace, or path
    /// syntax can appear in one.
    AccountLabel,
    |t: &str| account_label_grammar(t)
);

fn source_id_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.len() != 36 {
        return false;
    }
    let lower_hex = |slice: &[u8]| {
        slice
            .iter()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
    };
    lower_hex(&raw[0..8])
        && raw[8] == b'-'
        && lower_hex(&raw[9..13])
        && raw[13] == b'-'
        && lower_hex(&raw[14..18])
        && raw[18] == b'-'
        && lower_hex(&raw[19..23])
        && raw[23] == b'-'
        && lower_hex(&raw[24..36])
}

fn account_label_grammar(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 64 {
        return false;
    }
    if !raw[0].is_ascii_alphanumeric() {
        return false;
    }
    raw[1..]
        .iter()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b':' | b'-'))
}

/// Define a closed status vocabulary: known tokens become variants, anything
/// else fails closed. The tokens are the wire-stable spellings the status
/// JSON and the compatibility matrix use.
macro_rules! status_enum {
    ($(#[$doc:meta])* $name:ident { $($(#[$vdoc:meta])* $variant:ident => $token:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$vdoc])* $variant,)+
        }

        impl $name {
            /// Every known token, in declaration order.
            #[must_use]
            pub fn tokens() -> &'static [&'static str] {
                &[$($token),+]
            }

            /// The canonical token for this value.
            #[must_use]
            pub fn token(self) -> &'static str {
                match self {
                    $(Self::$variant => $token,)+
                }
            }

            /// Parse one token, failing closed on anything unknown.
            ///
            /// # Errors
            /// [`GrammarError::NotCanonical`] for a token outside the
            /// closed set.
            pub fn parse(text: &str) -> Result<Self, GrammarError> {
                match text {
                    $($token => Ok(Self::$variant),)+
                    _ => Err(GrammarError::NotCanonical),
                }
            }

            /// Every value, in declaration order.
            #[must_use]
            pub fn all() -> &'static [Self] {
                &[$(Self::$variant),+]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.token())
            }
        }

        impl FromStr for $name {
            type Err = GrammarError;
            fn from_str(text: &str) -> Result<Self, Self::Err> {
                Self::parse(text)
            }
        }
    };
}

status_enum!(
    /// Which scheduling lane a source's outstanding data belongs to: the
    /// freshness lane (recently active sessions the client keeps current)
    /// or the backfill lane (historical history drained largest-first)
    /// (plan Section 7.9; requirements SCH-003 through SCH-005). The state
    /// schema stores the same two tokens for `sources.freshness_lane`.
    FreshnessLane {
        /// Recently active: capture is keeping a live session current.
        Freshness => "freshness",
        /// Historical: a source's measured backlog is drained by the
        /// backfill scheduler.
        Backfill => "backfill",
    }
);

status_enum!(
    /// The closed coverage vocabulary of requirement CAP-010: the six
    /// states a source — and, aggregated, an adapter/account — can be in,
    /// distinguishable without exposing any transcript content.
    ///
    /// The aggregate ordering ([`CoverageState::rank`]) names the condition
    /// an operator must attend to: a scope containing any failed source
    /// reports failed; an entirely caught-up historical scope reports fully
    /// backfilled; a scope with nothing observable at all reports absent.
    CoverageState {
        /// Nothing is observable at the configured root: the source kind
        /// has no data there (root absent, no database). Distinguished
        /// from an empty backlog: absence is a coverage gap the fleet
        /// inventory reports explicitly.
        Absent => "missing",
        /// The observed fingerprint is not on the adapter's allowlist; no
        /// content was read (plan `EC-08` — unknown fingerprints fail
        /// closed).
        Unsupported => "unsupported",
        /// The last inventory pass could not read the source: transport,
        /// read, or permission failure. The previous measurement, if any,
        /// is retained but stale.
        Failed => "failed",
        /// Measured outstanding data exists that capture has not yet
        /// acknowledged — the active-growth or backfill case.
        Partial => "partial",
        /// A freshness-lane source with no outstanding data: capture is
        /// keeping up with the live session.
        Current => "current",
        /// A backfill-lane source with no outstanding data: its measured
        /// history has been captured completely.
        FullyBackfilled => "backfilled",
    }
);

impl CoverageState {
    /// The attention rank of this state: higher ranks win when a scope's
    /// per-source states aggregate into one. `Absent` loses to everything
    /// because an absent source contributes no coverage evidence of its
    /// own; `Failed` beats everything because unreadable sources make every
    /// other claim stale.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Absent => 0,
            Self::FullyBackfilled => 1,
            Self::Current => 2,
            Self::Partial => 3,
            Self::Unsupported => 4,
            Self::Failed => 5,
        }
    }

    /// Aggregate two per-source states into the one an operator must attend
    /// to: the higher rank wins.
    #[must_use]
    pub fn combine(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

status_enum!(
    /// The closed classification vocabulary of one inventory pass over one
    /// source: the content-free failure classes the fleet inventory
    /// retained, plus the two non-failure outcomes. The *last* class a
    /// source was scanned with is carried in status, so a source that
    /// stopped being scannable keeps saying why.
    ScanClassification {
        /// The pass read the source and measured it.
        Ok => "ok",
        /// The source's configured root does not exist on this host (the
        /// fleet inventory's `root_absent`; declared Pi coverage gaps).
        RootAbsent => "root-absent",
        /// A database source has no database file where configured (the
        /// fleet inventory's `no_database`).
        NoDatabase => "no-database",
        /// The source lives behind a transport that was unreachable (the
        /// fleet inventory's `transport_unreachable`).
        TransportUnreachable => "transport-unreachable",
        /// The source exists but could not be read this pass.
        ReadError => "read-error",
        /// The source exists but this process lacks read permission.
        PermissionDenied => "permission-denied",
        /// The observed schema fingerprint is not on the adapter's
        /// allowlist; no content was read (plan `EC-08`).
        FingerprintUnsupported => "fingerprint-unsupported",
        /// The source is known to the client state but was not covered by
        /// this pass, so its backlog is unmeasured.
        NotObserved => "not-observed",
    }
);

impl ScanClassification {
    /// The coverage state this classification forces on its own, or `None`
    /// when the coverage decision belongs to the backlog arithmetic
    /// (`Ok`) or to the pass's visibility (`NotObserved`).
    #[must_use]
    pub fn forced_coverage(self) -> Option<CoverageState> {
        match self {
            Self::RootAbsent | Self::NoDatabase => Some(CoverageState::Absent),
            Self::FingerprintUnsupported => Some(CoverageState::Unsupported),
            Self::TransportUnreachable | Self::ReadError | Self::PermissionDenied => {
                Some(CoverageState::Failed)
            }
            Self::Ok | Self::NotObserved => None,
        }
    }
}

/// What one read-only inventory pass observed about one source (plan
/// Section 6 client data flow step 2: "inventory outstanding bytes or
/// events without copying transcript content into logs or status").
///
/// The measurement stops at complete-record boundaries: `complete_bytes`
/// and `complete_events` cover only data through the last complete record,
/// and `incomplete_tail_bytes` counts the trailing partial write the next
/// pass will re-measure (plan `EC-01`). The tail is never part of any
/// backlog figure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceScan {
    /// The client-side source identifier this observation belongs to.
    pub source: SourceId,
    /// The adapter that performed the pass.
    pub adapter: AdapterId,
    /// The configured account label the source was discovered under.
    pub account: AccountLabel,
    /// Bytes through the last complete record boundary.
    pub complete_bytes: u64,
    /// Complete records (events) through the last complete boundary.
    pub complete_events: u64,
    /// Bytes after the last complete boundary: the pending tail, measured
    /// but never captured until it completes.
    pub incomplete_tail_bytes: u64,
    /// The freshest source-side activity timestamp the pass saw, when the
    /// source exposes one. Drives the freshness lane for sources the state
    /// has not enrolled yet.
    pub last_activity: Option<Timestamp>,
    /// Whether the source showed activity inside the freshness window this
    /// pass (the fleet inventory's active-24 h idea, at the adapter's
    /// configured window).
    pub active_in_window: bool,
    /// How the pass ended — the value status retains as this source's last
    /// classification.
    pub classification: ScanClassification,
}

/// Per-state source counts for one scope: the bounded replacement for a
/// per-source listing. Every field is a count of sources in that state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoverageCounts {
    /// Sources currently in the absent state.
    pub absent: u64,
    /// Sources currently in the unsupported state.
    pub unsupported: u64,
    /// Sources currently in the failed state.
    pub failed: u64,
    /// Sources currently in the partial state.
    pub partial: u64,
    /// Sources currently in the current state.
    pub current: u64,
    /// Sources currently in the fully-backfilled state.
    pub fully_backfilled: u64,
}

impl CoverageCounts {
    /// Add one source in `state`.
    pub fn record(&mut self, state: CoverageState) {
        match state {
            CoverageState::Absent => self.absent += 1,
            CoverageState::Unsupported => self.unsupported += 1,
            CoverageState::Failed => self.failed += 1,
            CoverageState::Partial => self.partial += 1,
            CoverageState::Current => self.current += 1,
            CoverageState::FullyBackfilled => self.fully_backfilled += 1,
        }
    }

    /// The count for one state.
    #[must_use]
    pub fn get(&self, state: CoverageState) -> u64 {
        match state {
            CoverageState::Absent => self.absent,
            CoverageState::Unsupported => self.unsupported,
            CoverageState::Failed => self.failed,
            CoverageState::Partial => self.partial,
            CoverageState::Current => self.current,
            CoverageState::FullyBackfilled => self.fully_backfilled,
        }
    }

    /// The number of sources counted, across every state.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.absent
            + self.unsupported
            + self.failed
            + self.partial
            + self.current
            + self.fully_backfilled
    }

    /// The status-JSON object for these counts, keyed by coverage token.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        for state in CoverageState::all() {
            object.set(state.token(), Value::Int(bounded_i64(self.get(*state))));
        }
        Value::Object(object)
    }
}

/// Per-classification counts for one scope: how many of the scope's
/// sources last ended a pass in each classification. The set is closed, so
/// the object is bounded no matter how many sources a scope holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClassificationCounts {
    /// Sources last classified `ok`.
    pub ok: u64,
    /// Sources last classified `root-absent`.
    pub root_absent: u64,
    /// Sources last classified `no-database`.
    pub no_database: u64,
    /// Sources last classified `transport-unreachable`.
    pub transport_unreachable: u64,
    /// Sources last classified `read-error`.
    pub read_error: u64,
    /// Sources last classified `permission-denied`.
    pub permission_denied: u64,
    /// Sources last classified `fingerprint-unsupported`.
    pub fingerprint_unsupported: u64,
    /// Sources known to the client state but not covered by the last pass.
    pub not_observed: u64,
}

impl ClassificationCounts {
    /// Add one source classified `class`.
    pub fn record(&mut self, class: ScanClassification) {
        match class {
            ScanClassification::Ok => self.ok += 1,
            ScanClassification::RootAbsent => self.root_absent += 1,
            ScanClassification::NoDatabase => self.no_database += 1,
            ScanClassification::TransportUnreachable => self.transport_unreachable += 1,
            ScanClassification::ReadError => self.read_error += 1,
            ScanClassification::PermissionDenied => self.permission_denied += 1,
            ScanClassification::FingerprintUnsupported => self.fingerprint_unsupported += 1,
            ScanClassification::NotObserved => self.not_observed += 1,
        }
    }

    /// The count for one classification.
    #[must_use]
    pub fn get(&self, class: ScanClassification) -> u64 {
        match class {
            ScanClassification::Ok => self.ok,
            ScanClassification::RootAbsent => self.root_absent,
            ScanClassification::NoDatabase => self.no_database,
            ScanClassification::TransportUnreachable => self.transport_unreachable,
            ScanClassification::ReadError => self.read_error,
            ScanClassification::PermissionDenied => self.permission_denied,
            ScanClassification::FingerprintUnsupported => self.fingerprint_unsupported,
            ScanClassification::NotObserved => self.not_observed,
        }
    }

    /// The number of classifications recorded, across every class.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.ok
            + self.root_absent
            + self.no_database
            + self.transport_unreachable
            + self.read_error
            + self.permission_denied
            + self.fingerprint_unsupported
            + self.not_observed
    }

    /// The status-JSON object for these counts, keyed by classification
    /// token.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        for class in ScanClassification::all() {
            object.set(class.token(), Value::Int(bounded_i64(self.get(*class))));
        }
        Value::Object(object)
    }
}

/// The bounded adapter/account status the client exposes (requirement
/// CAP-010): everything acceptance needs about one adapter's account —
/// active and historical backlog, freshness lag, the last classifications,
/// and the coverage state — in a fixed key set whose size is independent of
/// the account's source count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdapterAccountStatus {
    /// The adapter this status is about.
    pub adapter: AdapterId,
    /// The configured account label this status is about.
    pub account: AccountLabel,
    /// The aggregate coverage state: the highest-rank per-source state in
    /// the scope.
    pub coverage: CoverageState,
    /// Outstanding bytes on freshness-lane sources: recently active
    /// sessions capture has not acknowledged yet.
    pub active_backlog_bytes: u64,
    /// Outstanding complete records (events) on freshness-lane sources.
    pub active_backlog_events: u64,
    /// Outstanding bytes on backfill-lane sources: the measured historical
    /// backlog.
    pub historical_backlog_bytes: u64,
    /// Outstanding complete records (events) on backfill-lane sources.
    pub historical_backlog_events: u64,
    /// The largest per-source freshness lag in the scope, in seconds; zero
    /// when every source is caught up or no lag basis exists.
    pub max_freshness_lag_seconds: u64,
    /// Per-state source counts across the scope.
    pub sources: CoverageCounts,
    /// Per-classification counts across the scope: the last classes its
    /// sources were scanned with.
    pub classifications: ClassificationCounts,
}

impl AdapterAccountStatus {
    /// The scope this status is about, as an `(adapter, account)` token
    /// pair.
    #[must_use]
    pub fn scope(&self) -> (&str, &str) {
        (self.adapter.as_str(), self.account.as_str())
    }

    /// The status-JSON value: a fixed key set of bounded tokens and
    /// integers, with no per-source detail and no free text.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("account", Value::Text(self.account.as_str().to_owned()));
        object.set(
            "active_backlog_bytes",
            Value::Int(bounded_i64(self.active_backlog_bytes)),
        );
        object.set(
            "active_backlog_events",
            Value::Int(bounded_i64(self.active_backlog_events)),
        );
        object.set("adapter", Value::Text(self.adapter.as_str().to_owned()));
        object.set("classifications", self.classifications.to_json());
        object.set("coverage", Value::Text(self.coverage.token().to_owned()));
        object.set("coverage_sources", self.sources.to_json());
        object.set(
            "historical_backlog_bytes",
            Value::Int(bounded_i64(self.historical_backlog_bytes)),
        );
        object.set(
            "historical_backlog_events",
            Value::Int(bounded_i64(self.historical_backlog_events)),
        );
        object.set(
            "max_freshness_lag_seconds",
            Value::Int(bounded_i64(self.max_freshness_lag_seconds)),
        );
        Value::Object(object)
    }
}

/// A counter rendered into the no-float JSON domain: saturating at
/// `i64::MAX`, because a status figure that would overflow the wire integer
/// domain is clipped, never wrapped and never a float.
fn bounded_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests;
