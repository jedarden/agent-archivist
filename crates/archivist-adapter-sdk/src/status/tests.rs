// SPDX-License-Identifier: Apache-2.0

//! Tests for the bounded status contract: identifier grammars reject path
//! syntax, the coverage and classification vocabularies fail closed, the
//! aggregate ordering is total, and the rendered status is a fixed-shape,
//! size-bounded, content-free document (requirement CAP-010).

use std::str::FromStr;

use archivist_protocol::vocabulary::AdapterId;

use super::{
    AccountLabel, AdapterAccountStatus, ClassificationCounts, CoverageCounts, CoverageState,
    ScanClassification, SourceId, SourceScan,
};

/// A distinct 36-character lowercase UUID-shape source identifier.
fn sid(seed: u8) -> SourceId {
    SourceId::parse(&format!("{seed:08x}-1111-4222-8333-{seed:012x}")).expect("source id")
}

/// A distinct adapter identifier within the short-token grammar.
fn adapter(seed: u8) -> AdapterId {
    AdapterId::parse(&format!("adapter-{seed}")).expect("adapter id")
}

/// A distinct account label within the label grammar.
fn account(seed: u8) -> AccountLabel {
    AccountLabel::parse(&format!("account-{seed}")).expect("account label")
}

/// A minimal `ok` scan for one source under one scope.
fn scan(source: &SourceId, adapter_id: &AdapterId, label: &AccountLabel) -> SourceScan {
    SourceScan {
        source: source.clone(),
        adapter: adapter_id.clone(),
        account: label.clone(),
        complete_bytes: 0,
        complete_events: 0,
        incomplete_tail_bytes: 0,
        last_activity: None,
        active_in_window: false,
        classification: ScanClassification::Ok,
    }
}

#[test]
fn source_id_grammar_accepts_uuid_shape_and_rejects_drift() {
    assert!(SourceId::parse("0a000000-1111-4222-8333-000000000000").is_ok());
    // Upper case is not the stored shape.
    assert!(SourceId::parse("0A000000-1111-4222-8333-000000000000").is_err());
    // Wrong lengths and separators.
    assert!(SourceId::parse("0a0000001111422283330000000000000").is_err());
    assert!(SourceId::parse("0a000000-1111-4222-8333-00000000000").is_err());
    // A path is not an identifier.
    assert!(SourceId::parse("../../etc/passwd-passwd-passwd-passwd").is_err());
    // Non-hex filler.
    assert!(SourceId::parse("0g000000-1111-4222-8333-000000000000").is_err());
}

#[test]
fn account_label_grammar_rejects_path_and_separator_syntax() {
    assert!(AccountLabel::parse("primary").is_ok());
    assert!(AccountLabel::parse("host-1.a_b:c").is_ok());
    assert!(AccountLabel::parse("9accounts").is_ok());
    // Empty, over-long.
    assert!(AccountLabel::parse("").is_err());
    assert!(AccountLabel::parse(&"a".repeat(65)).is_err());
    // Path separators, whitespace, and leading punctuation are all outside
    // the grammar, so a label can never smuggle a location.
    assert!(AccountLabel::parse("a/b").is_err());
    assert!(AccountLabel::parse("a\\b").is_err());
    assert!(AccountLabel::parse("a b").is_err());
    assert!(AccountLabel::parse(".hidden").is_err());
    assert!(AccountLabel::parse("/absolute").is_err());
}

#[test]
fn coverage_vocabulary_fails_closed_and_round_trips() {
    let tokens = CoverageState::tokens();
    assert_eq!(tokens.len(), 6);
    for state in CoverageState::all() {
        assert!(tokens.contains(&state.token()));
        assert_eq!(CoverageState::parse(state.token()), Ok(*state));
        assert_eq!(state.to_string(), state.token());
    }
    // The tokens are the plan Section 12 / metrics-registry spellings of
    // the CAP-010 states, so one vocabulary reads across status, labels,
    // and the plan.
    assert_eq!(CoverageState::parse("missing"), Ok(CoverageState::Absent));
    assert!(CoverageState::parse("complete").is_err());
    assert!(CoverageState::parse("").is_err());
    assert!(CoverageState::parse("Fully-Backfilled").is_err());
    // The pre-alignment spellings are gone, not aliased.
    assert!(CoverageState::parse("absent").is_err());
    assert!(CoverageState::parse("fully-backfilled").is_err());
}

#[test]
fn classification_vocabulary_fails_closed_and_matches_the_fleet_classes() {
    let tokens = ScanClassification::tokens();
    assert_eq!(tokens.len(), 8);
    // The fleet inventory's failure classes are all representable.
    for token in ["ok", "root-absent", "no-database", "transport-unreachable"] {
        assert!(tokens.contains(&token), "missing fleet class {token}");
    }
    for class in ScanClassification::all() {
        assert_eq!(ScanClassification::parse(class.token()), Ok(*class));
    }
    assert!(ScanClassification::parse("disk_full").is_err());
}

#[test]
fn coverage_rank_ordering_is_total_and_combine_picks_the_attended_state() {
    // Every pair combines to the member with the higher rank, symmetrically.
    for left in CoverageState::all() {
        for right in CoverageState::all() {
            let combined = left.combine(*right);
            let reverse = right.combine(*left);
            assert_eq!(combined, reverse, "combine must be symmetric");
            assert!(combined.rank() >= left.rank() && combined.rank() >= right.rank());
        }
    }
    // A scope with only absent sources stays absent...
    assert_eq!(
        CoverageState::Absent.combine(CoverageState::Absent),
        CoverageState::Absent
    );
    // ...but absence never masks real evidence...
    assert_eq!(
        CoverageState::Absent.combine(CoverageState::Current),
        CoverageState::Current
    );
    // ...and a single failure outranks every caught-up source.
    let fold = CoverageState::all()
        .iter()
        .fold(CoverageState::Absent, |acc, state| acc.combine(*state));
    assert_eq!(fold, CoverageState::Failed);
    assert!(CoverageState::Partial.rank() > CoverageState::Current.rank());
    assert!(CoverageState::Current.rank() > CoverageState::FullyBackfilled.rank());
}

#[test]
fn classification_forces_its_own_coverage_or_defers_to_backlog_math() {
    assert_eq!(
        ScanClassification::RootAbsent.forced_coverage(),
        Some(CoverageState::Absent)
    );
    assert_eq!(
        ScanClassification::NoDatabase.forced_coverage(),
        Some(CoverageState::Absent)
    );
    assert_eq!(
        ScanClassification::FingerprintUnsupported.forced_coverage(),
        Some(CoverageState::Unsupported)
    );
    for class in [
        ScanClassification::TransportUnreachable,
        ScanClassification::ReadError,
        ScanClassification::PermissionDenied,
    ] {
        assert_eq!(class.forced_coverage(), Some(CoverageState::Failed));
    }
    // Ok and not-observed leave the decision to the engine.
    assert_eq!(ScanClassification::Ok.forced_coverage(), None);
    assert_eq!(ScanClassification::NotObserved.forced_coverage(), None);
}

#[test]
fn coverage_counts_are_bounded_per_state_and_render_every_token() {
    let mut counts = CoverageCounts::default();
    counts.record(CoverageState::Partial);
    counts.record(CoverageState::Partial);
    counts.record(CoverageState::Absent);
    assert_eq!(counts.get(CoverageState::Partial), 2);
    assert_eq!(counts.get(CoverageState::Absent), 1);
    assert_eq!(counts.get(CoverageState::Current), 0);
    assert_eq!(counts.total(), 3);

    let rendered = counts.to_json();
    let archivist_protocol::json::Value::Object(ref object) = rendered else {
        panic!("counts render as an object");
    };
    let names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
    // Canonical JSON order: the tokens, sorted.
    let mut expected = CoverageState::tokens().to_vec();
    expected.sort_unstable();
    assert_eq!(names, expected);
}

#[test]
fn classification_counts_record_every_class() {
    let mut counts = ClassificationCounts::default();
    for class in ScanClassification::all() {
        counts.record(*class);
    }
    counts.record(ScanClassification::Ok);
    assert_eq!(counts.get(ScanClassification::Ok), 2);
    let every_class = u64::try_from(ScanClassification::all().len()).expect("small count");
    assert_eq!(counts.total(), every_class + 1);

    let rendered = counts.to_json();
    let archivist_protocol::json::Value::Object(ref object) = rendered else {
        panic!("counts render as an object");
    };
    let names: Vec<&str> = object.iter().map(|(name, _)| name).collect();
    let mut expected = ScanClassification::tokens().to_vec();
    expected.sort_unstable();
    assert_eq!(names, expected);
}

#[test]
fn status_json_is_a_fixed_key_set_independent_of_magnitude() {
    let build = |backlog: u64, lag: u64| AdapterAccountStatus {
        adapter: adapter(1),
        account: account(2),
        coverage: CoverageState::Partial,
        active_backlog_bytes: backlog,
        active_backlog_events: backlog,
        historical_backlog_bytes: backlog,
        historical_backlog_events: backlog,
        max_freshness_lag_seconds: lag,
        sources: CoverageCounts::default(),
        classifications: ClassificationCounts::default(),
    };

    let quiet = build(0, 0);
    let extreme = build(u64::MAX, u64::MAX);

    let quiet_bytes = quiet.to_json().canonical_bytes();
    let extreme_bytes = extreme.to_json().canonical_bytes();

    // The key structure is identical; only the integer widths differ...
    let keys = |bytes: &[u8]| {
        String::from_utf8(bytes.to_vec())
            .expect("canonical json is utf-8")
            .match_indices('"')
            .count()
    };
    assert_eq!(keys(&quiet_bytes), keys(&extreme_bytes));

    // ...and the extreme document is still a bounded document: every field
    // is a fixed key or a widest-possible integer, so the size ceiling is
    // independent of how much backlog the account actually holds.
    assert!(
        extreme_bytes.len() < 2048,
        "status grew to {}",
        extreme_bytes.len()
    );
}

#[test]
fn status_json_is_content_free() {
    let status = AdapterAccountStatus {
        adapter: adapter(1),
        account: account(2),
        coverage: CoverageState::Failed,
        active_backlog_bytes: 12_345,
        active_backlog_events: 42,
        historical_backlog_bytes: 9_876_543_210,
        historical_backlog_events: 7,
        max_freshness_lag_seconds: 600,
        sources: CoverageCounts::default(),
        classifications: ClassificationCounts::default(),
    };
    let rendered = String::from_utf8(status.to_json().canonical_bytes()).expect("utf-8");

    // No path syntax can survive the grammars: no separators, no escapes
    // beyond the canonical string encoder's control characters, and no
    // per-source detail — a known source identifier never appears.
    assert!(
        !rendered.contains('/'),
        "path separator in status: {rendered}"
    );
    assert!(!rendered.contains('\\'), "backslash in status: {rendered}");
    assert!(
        !rendered.contains(sid(9).as_str()),
        "source id in status: {rendered}"
    );
}

#[test]
fn scans_carry_their_scope_and_complete_boundary_measurements() {
    let source = sid(3);
    let observed = scan(&source, &adapter(4), &account(5));
    assert_eq!(observed.source, source);
    assert_eq!(observed.adapter, adapter(4));
    assert_eq!(observed.account, account(5));
    assert_eq!(observed.complete_bytes, 0);
    assert_eq!(observed.incomplete_tail_bytes, 0);
    assert_eq!(observed.classification, ScanClassification::Ok);
    // Identifiers parse back from their tokens.
    assert_eq!(SourceId::from_str(source.as_str()), Ok(source));
    assert_eq!(
        AccountLabel::from_str("backfill-a"),
        AccountLabel::parse("backfill-a")
    );
}
