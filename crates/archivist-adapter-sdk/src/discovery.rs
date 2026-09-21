// SPDX-License-Identifier: Apache-2.0

//! The discovery interface (requirement CAP-001, plan client data flow
//! step 1): how an adapter enumerates the sources configured under one
//! account root, and the bounded, content-free report it hands the client
//! engine.
//!
//! Discovery is adapter-specific by requirement — the client **MUST NOT**
//! assume orchestrator records cover interactive harness sessions — so the
//! SDK pins only the shape of the answer, never where an adapter looks.
//! A filesystem adapter walks its configured roots, a database adapter
//! locates its configured database; both return the same
//! [`DiscoveryReport`].
//!
//! Two rules shape the report, inherited from the status contract:
//!
//! - **Content-free.** An account is named by its configuration-chosen
//!   [`AccountLabel`], never by an upstream account value, a path, or a
//!   hostname. Fingerprint tokens are the same content-free
//!   schema/version names the allowlist admits.
//! - **Total.** `discover` cannot fail: a root that is absent, a
//!   database that is missing, a permission denial — each is a
//!   classification in the report, not an error, because a discovery pass
//!   that observed nothing still observed *that*. Callers branch on
//!   [`ScanClassification`], the same closed vocabulary the inventory
//!   scan reports.

use archivist_protocol::json::{Object, Value};
use archivist_protocol::vocabulary::AdapterId;

use crate::fingerprint::SourceFingerprint;
use crate::status::{AccountLabel, ScanClassification};

/// One discovered source, reduced to its routing identity: the configured
/// account it was found under and the schema/version fingerprint the
/// adapter detected for it. No path, no upstream session value, no
/// hostname — the engine routes by account and admits by fingerprint; the
/// per-source measurement arrives separately as a
/// [`crate::status::SourceScan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredSource {
    /// The configured account label the source was discovered under.
    pub account: AccountLabel,
    /// The adapter-detectable schema/version fingerprint observed for the
    /// source. A token the adapter's allowlist does not admit is reported
    /// anyway — the fail-closed decision happens at admission
    /// ([`crate::fingerprint::FingerprintAllowlist::admit`]), never by
    /// hiding the observation.
    pub fingerprint: SourceFingerprint,
}

/// The bounded, content-free outcome of one discovery pass over one
/// configured account (plan client data flow step 1). Fixed key set,
/// integer counts, closed-vocabulary tokens: its canonical JSON size does
/// not depend on how many sources the account holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryReport {
    /// The adapter that performed the pass.
    pub adapter: AdapterId,
    /// The configured account the pass covered.
    pub account: AccountLabel,
    /// How the pass ended — `root-absent`, `no-database`, `ok`, a read
    /// failure, or `fingerprint-unsupported` when every source seen was
    /// off the allowlist. The same closed vocabulary the inventory scan
    /// uses.
    pub classification: ScanClassification,
    /// Distinct sources the pass discovered, whatever their state.
    pub sources: u64,
    /// Discovered sources whose fingerprint is on the adapter's
    /// allowlist: the ones capture may read.
    pub supported: u64,
    /// Discovered sources whose fingerprint is not on the allowlist. No
    /// projected content was read to count them (plan `EC-08`).
    pub unsupported: u64,
}

/// Why a discovery report could not be constructed. The counts are
/// caller-supplied, so only their consistency is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryError {
    /// A subset count exceeded the total it is a subset of.
    InconsistentCounts,
}

impl std::fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = match self {
            Self::InconsistentCounts => "discovery_report_counts_inconsistent",
        };
        f.write_str(token)
    }
}

impl std::error::Error for DiscoveryError {}

impl DiscoveryReport {
    /// Assemble a report, checking that the subset counts fit the total.
    /// The two subsets are disjoint — a source the pass could not read
    /// far enough to fingerprint is neither supported nor unsupported —
    /// so their sum must fit `sources`.
    ///
    /// # Errors
    /// [`DiscoveryError::InconsistentCounts`] when `supported` and
    /// `unsupported` together exceed `sources`.
    pub fn new(
        adapter: AdapterId,
        account: AccountLabel,
        classification: ScanClassification,
        sources: u64,
        supported: u64,
        unsupported: u64,
    ) -> Result<Self, DiscoveryError> {
        let classified = supported
            .checked_add(unsupported)
            .ok_or(DiscoveryError::InconsistentCounts)?;
        if classified > sources {
            return Err(DiscoveryError::InconsistentCounts);
        }
        Ok(Self {
            adapter,
            account,
            classification,
            sources,
            supported,
            unsupported,
        })
    }

    /// The status-JSON value: a fixed key set of bounded tokens and
    /// integers.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut object = Object::new();
        object.set("account", Value::Text(self.account.as_str().to_owned()));
        object.set("adapter", Value::Text(self.adapter.as_str().to_owned()));
        object.set(
            "classification",
            Value::Text(self.classification.token().to_owned()),
        );
        object.set("sources", Value::Int(count_to_i64(self.sources)));
        object.set("supported", Value::Int(count_to_i64(self.supported)));
        object.set("unsupported", Value::Int(count_to_i64(self.unsupported)));
        Value::Object(object)
    }
}

/// The bounded list of sources one discovery pass found, in a stable
/// order. Capped at [`crate::fingerprint::MAX_FINGERPRINTS`] — one
/// discovered source per distinct fingerprint, mirroring the allowlist
/// cap — and single-account by construction: a report's entries cannot
/// mix accounts.
///
/// The list is the adapter-to-engine routing detail; the report's
/// aggregate counts are what enters status. A source beyond the cap is a
/// configuration error at the adapter, rejected here rather than
/// truncated.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DiscoveredSources {
    entries: Vec<DiscoveredSource>,
}

impl DiscoveredSources {
    /// Assemble the list, checking the cap and the single-account rule.
    ///
    /// # Errors
    /// [`DiscoveryError::InconsistentCounts`] when the list exceeds
    /// [`crate::fingerprint::MAX_FINGERPRINTS`] entries or mixes
    /// accounts.
    pub fn new(entries: Vec<DiscoveredSource>) -> Result<Self, DiscoveryError> {
        if entries.len() > crate::fingerprint::MAX_FINGERPRINTS {
            return Err(DiscoveryError::InconsistentCounts);
        }
        let account = entries.first().map(|source| source.account.clone());
        if entries
            .iter()
            .any(|source| Some(&source.account) != account.as_ref())
        {
            return Err(DiscoveryError::InconsistentCounts);
        }
        Ok(Self { entries })
    }

    /// The discovered sources in list order.
    pub fn iter(&self) -> impl Iterator<Item = &DiscoveredSource> {
        self.entries.iter()
    }

    /// The number of discovered sources.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pass discovered nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The account every entry belongs to, when there are entries.
    #[must_use]
    pub fn account(&self) -> Option<&AccountLabel> {
        self.entries.first().map(|source| &source.account)
    }
}

/// A discovery counter rendered into the no-float JSON domain: saturating
/// at `i64::MAX`, matching the status contract's counter rule.
fn count_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// The discovery interface every source adapter implements (CAP-001):
/// enumerate the sources configured under one account.
///
/// The engine calls this once per configured account per inventory cycle,
/// before any measurement; the returned report tells it which sources
/// capture may read (`supported`) and which failed closed
/// (`unsupported`). Implementations read configuration and enumerate —
/// they never open capture streams, never touch the network, the spool,
/// or storage.
pub trait SourceDiscovery {
    /// Discover the sources configured under `account`. Total: the report
    /// carries the pass outcome as its classification.
    fn discover(&self, account: &AccountLabel) -> DiscoveryReport;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn adapter() -> AdapterId {
        AdapterId::parse("claude-code").expect("valid adapter id")
    }

    fn account() -> AccountLabel {
        AccountLabel::parse("work-laptop").expect("valid label")
    }

    fn fingerprint(token: &str) -> SourceFingerprint {
        SourceFingerprint::parse(token).expect("valid fingerprint")
    }

    #[test]
    fn reports_are_bounded_content_free_json() {
        let report = DiscoveryReport::new(adapter(), account(), ScanClassification::Ok, 12, 10, 2)
            .expect("consistent counts");
        let text = String::from_utf8(report.to_json().canonical_bytes()).expect("utf8");
        assert!(text.contains(r#""account":"work-laptop""#));
        assert!(text.contains(r#""classification":"ok""#));
        assert!(text.contains(r#""unsupported":2"#));
        // No path, hostname, or upstream account value can appear: every
        // field is a parsed content-free token or an integer.
        assert_eq!(text.matches(':').count(), 6);
    }

    #[test]
    fn subset_counts_must_fit_the_total() {
        assert_eq!(
            DiscoveryReport::new(adapter(), account(), ScanClassification::Ok, 2, 3, 0,),
            Err(DiscoveryError::InconsistentCounts)
        );
        assert_eq!(
            DiscoveryReport::new(adapter(), account(), ScanClassification::Ok, 2, 1, 2,),
            Err(DiscoveryError::InconsistentCounts)
        );
        // Zero sources with an explicit gap classification is the absent
        // root case, and it is consistent.
        assert!(
            DiscoveryReport::new(
                adapter(),
                account(),
                ScanClassification::RootAbsent,
                0,
                0,
                0,
            )
            .is_ok()
        );
    }

    #[test]
    fn discovered_source_lists_are_capped_and_single_account() {
        let entries = vec![
            DiscoveredSource {
                account: account(),
                fingerprint: fingerprint("claude-jsonl-v1"),
            },
            DiscoveredSource {
                account: account(),
                fingerprint: fingerprint("claude-jsonl-v2"),
            },
        ];
        let sources = DiscoveredSources::new(entries).expect("fits");
        assert_eq!(sources.len(), 2);
        assert_eq!(sources.account(), Some(&account()));
        assert_eq!(
            sources
                .iter()
                .map(|s| s.fingerprint.as_str())
                .collect::<Vec<_>>(),
            ["claude-jsonl-v1", "claude-jsonl-v2"]
        );
        assert!(!sources.is_empty());
        assert_eq!(
            DiscoveredSources::default(),
            DiscoveredSources::new(Vec::new()).expect("empty fits")
        );

        // A source from a different account cannot ride in one list.
        let other_account = AccountLabel::parse("other").expect("valid label");
        let mixed = vec![
            DiscoveredSource {
                account: account(),
                fingerprint: fingerprint("claude-jsonl-v1"),
            },
            DiscoveredSource {
                account: other_account,
                fingerprint: fingerprint("claude-jsonl-v1"),
            },
        ];
        assert_eq!(
            DiscoveredSources::new(mixed),
            Err(DiscoveryError::InconsistentCounts)
        );

        // The list mirrors the allowlist cap.
        let oversized: Vec<DiscoveredSource> = (0..=crate::fingerprint::MAX_FINGERPRINTS)
            .map(|i| DiscoveredSource {
                account: account(),
                fingerprint: fingerprint(&format!("kind-{i}")),
            })
            .collect();
        assert_eq!(
            DiscoveredSources::new(oversized),
            Err(DiscoveryError::InconsistentCounts)
        );
    }
}
