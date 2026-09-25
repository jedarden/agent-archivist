// SPDX-License-Identifier: Apache-2.0

//! Tests for the archive inventory comparator: the operand parser and
//! its closed shape, the join and classification arithmetic over seeded
//! client state, provenance retention under overlap and duplication, the
//! explicit unexplained verdict, digest reproduction and binding, and
//! the content-free surface every refusal and report keeps.

use std::sync::atomic::{AtomicU64, Ordering};

use archivist_protocol::json::Value;
use archivist_protocol::vocabulary::Timestamp;
use rusqlite::params;

use super::{
    COMPARISON_DIGEST_LABEL, ComparisonReport, GapClass, LegacyInventory, LegacyInventoryErrorKind,
    Verdict, compare,
};
use crate::report::RESULT_NAMESPACE;
use crate::state::{StateErrorKind, StateStore};

const NOW: &str = "2026-09-24T12:00:00Z";
/// The legacy export instant every fixture document carries.
const EXPORTED: &str = "2026-09-24T00:00:00Z";
const NAMESPACE: &str = "archivist.pilot-legacy-inventory/v1";
/// A second export instant, so digest binding over the legacy instant is
/// observable.
const EXPORTED_LATER: &str = "2026-09-24T06:00:00Z";

/// A distinct 64-character lowercase hex fixture.
fn hex(seed: u64) -> String {
    format!("{seed:064x}")
}

/// The `(session_hash, artifact_hash)` join pair for source `seed`.
fn pair(seed: u64) -> (String, String) {
    (hex(seed * 10 + 1), hex(seed * 10 + 2))
}

/// A distinct payload digest fixture.
fn digest(seed: u64) -> String {
    hex(seed)
}

fn now() -> Timestamp {
    Timestamp::parse(NOW).expect("timestamp")
}

// --- Operand documents ------------------------------------------------------

fn occurrence_entry(kind: &str, start: u64, end: u64, blob: &str) -> String {
    format!(
        r#"{{"range_kind": "{kind}", "range_start": {start}, "range_end": {end}, "blob_digest": "{blob}"}}"#
    )
}

/// One legacy source entry, with the adapter spelled explicitly so a
/// test can exercise the adapter rendering.
fn source_entry(
    session: &str,
    artifact: &str,
    coverage: &str,
    adapter: &str,
    occurrences: &[String],
) -> String {
    format!(
        r#"{{"session_hash": "{session}", "artifact_hash": "{artifact}", "adapter": "{adapter}", "coverage": "{coverage}", "occurrences": [{}]}}"#,
        occurrences.join(", ")
    )
}

fn inventory_document(generated_at: &str, sources: &[String]) -> String {
    format!(
        r#"{{"schema": "{NAMESPACE}", "generated_at": "{generated_at}", "sources": [{}]}}"#,
        sources.join(", ")
    )
}

fn parse_ok(document: &str) -> LegacyInventory {
    LegacyInventory::parse(document.as_bytes()).expect("parse legacy inventory")
}

fn parse_err(document: &str) -> LegacyInventoryErrorKind {
    match LegacyInventory::parse(document.as_bytes()) {
        Ok(_) => panic!("document unexpectedly parsed"),
        Err(error) => error.kind(),
    }
}

/// The default well-formed source: one bytes occurrence and one events
/// occurrence, distinct payloads, the caught-up legacy coverage.
fn standard_source(seed: u64) -> String {
    let (session, artifact) = pair(seed);
    source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[
            occurrence_entry("byte", 0, 10, &digest(seed)),
            occurrence_entry("event", 0, 5, &digest(seed + 1)),
        ],
    )
}

// --- New-side state seeding -------------------------------------------------

static NEXT_ROW: AtomicU64 = AtomicU64::new(1);

fn migrated() -> StateStore {
    let mut store = StateStore::open_in_memory().expect("open in-memory");
    store.migrate().expect("migrate");
    store
}

/// A distinct 36-character identifier for one CHECK-constrained column.
fn id36(seed: u64) -> String {
    format!("{seed:036x}")
}

/// Enroll one source whose join pair is `(session, artifact)`; returns
/// the state's source identifier.
fn enroll(store: &StateStore, session: &str, artifact: &str, lane: &str) -> String {
    let seed = NEXT_ROW.fetch_add(1, Ordering::Relaxed);
    let source_id = format!("{seed:08x}-1111-4222-8333-{seed:012x}");
    store
        .connection()
        .execute(
            "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                session_hash, artifact_kind, adapter_id, adapter_projection_version,
                adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                created_at, updated_at)
             VALUES (?1, 'claude', 'upstream', 'natural', ?2, 'transcript', 'claude',
                'v1', 'artifact', ?3, ?4, NULL, ?5, ?5)",
            params![source_id, session, artifact, lane, NOW],
        )
        .expect("insert source");
    source_id
}

/// Add one generation to a source, returning its identifier.
fn generation(store: &StateStore, source_id: &str, seed: u64) -> String {
    let generation_id = format!("{seed:08x}-aaaa-7bbb-8ccc-{seed:012x}");
    let ordinal = i64::try_from(seed).expect("ordinal fits i64");
    store
        .connection()
        .execute(
            "INSERT INTO generations (generation_id, source_id, ordinal, state,
                detected_reason, tail_checksum, file_identity, detected_at)
             VALUES (?1, ?2, ?3, 'open', 'first-observed', NULL, NULL, ?4)",
            params![generation_id, source_id, ordinal, NOW],
        )
        .expect("insert generation");
    generation_id
}

/// Add one acknowledged occurrence to a generation, returning its
/// identifier.
fn occurrence(
    store: &StateStore,
    generation_id: &str,
    kind: &str,
    start: u64,
    end: u64,
    blob: &str,
) -> String {
    let seed = NEXT_ROW.fetch_add(1, Ordering::Relaxed);
    let occurrence_id = format!("{seed:064x}");
    store
        .connection()
        .execute(
            "INSERT INTO ranges (occurrence_id, generation_id, range_kind, range_start,
                range_end, sequence, blob_digest, spool_entry_id, captured_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, NULL, ?7)",
            params![
                occurrence_id,
                generation_id,
                kind,
                i64::try_from(start).expect("start fits i64"),
                i64::try_from(end).expect("end fits i64"),
                blob,
                NOW,
            ],
        )
        .expect("insert range");
    occurrence_id
}

/// Record one upload attestation for an occurrence.
fn attestation(store: &StateStore, occurrence_id: &str, relation: &str) {
    let seed = NEXT_ROW.fetch_add(1, Ordering::Relaxed);
    store
        .connection()
        .execute(
            "INSERT INTO upload_attestations (attestation_id, tenant_id, occurrence_id,
                origin_client_id, uploader_client_id, request_id, relation, recorded_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                format!("{seed:064x}"),
                id36(seed * 10 + 1),
                occurrence_id,
                id36(seed * 10 + 2),
                id36(seed * 10 + 3),
                id36(seed * 10 + 4),
                relation,
                NOW,
            ],
        )
        .expect("insert attestation");
}

/// Seed state source `seed` in the freshness lane with the standard
/// source's occurrences, so it matches [`standard_source`] exactly.
/// Returns the acknowledged occurrence identifiers, bytes occurrence
/// first.
fn standard_state_source(store: &StateStore, seed: u64) -> Vec<String> {
    let (session, artifact) = pair(seed);
    let source_id = enroll(store, &session, &artifact, "freshness");
    let gen_a = generation(store, &source_id, seed);
    let gen_b = generation(store, &source_id, seed + 100);
    vec![
        occurrence(store, &gen_a, "bytes", 0, 10, &digest(seed)),
        occurrence(store, &gen_b, "events", 0, 5, &digest(seed + 1)),
    ]
}

fn compare_ok(store: &StateStore, legacy: &LegacyInventory) -> ComparisonReport {
    compare(store.connection(), legacy, &now()).expect("compare")
}

/// The first difference row of a report's JSON, for member assertions.
fn first_difference(report: &ComparisonReport) -> Value {
    match member(&report.to_json(), "differences") {
        Value::Array(rows) => rows.as_slice()[0].clone(),
        _ => panic!("differences is an array"),
    }
}

// --- Report JSON navigation -------------------------------------------------

/// A named member of a report JSON object.
fn member<'a>(value: &'a Value, name: &str) -> &'a Value {
    match value {
        Value::Object(members) => members.get(name).expect("named member"),
        _ => panic!("report member is not an object"),
    }
}

fn text_of(value: &Value) -> &str {
    match value {
        Value::Text(text) => text.as_str(),
        _ => panic!("expected text"),
    }
}

fn int_of(value: &Value) -> i64 {
    match value {
        Value::Int(number) => *number,
        _ => panic!("expected int"),
    }
}

/// Every text leaf and every integer leaf, for the content-free sweep.
fn leaves(value: &Value, texts: &mut Vec<String>, ints: &mut Vec<i64>) {
    match value {
        Value::Object(members) => {
            for (_, member) in members.iter() {
                leaves(member, texts, ints);
            }
        }
        Value::Array(items) => {
            for item in items.as_slice() {
                leaves(item, texts, ints);
            }
        }
        Value::Text(text) => texts.push(text.as_str().to_owned()),
        Value::Int(number) => ints.push(*number),
        Value::Null | Value::Bool(_) => {}
    }
}

// --- Operand parsing --------------------------------------------------------

#[test]
fn a_well_formed_document_parses_and_exposes_its_evidence() {
    let document = inventory_document(EXPORTED, &[standard_source(1), standard_source(2)]);
    let legacy = parse_ok(&document);
    assert_eq!(legacy.generated_at().as_str(), EXPORTED);
    assert_eq!(legacy.sources().len(), 2);
    let first = &legacy.sources()[0];
    let (session, artifact) = pair(1);
    assert_eq!(first.session().to_hex(), session);
    assert_eq!(first.artifact().to_hex(), artifact);
    assert_eq!(first.coverage().token(), "current");
}

#[test]
fn not_json_refuses_with_the_closed_content_free_detail() {
    let kind = parse_err("this is not json");
    assert_eq!(kind, LegacyInventoryErrorKind::MalformedJson);
    assert_eq!(
        kind.detail(),
        "the legacy inventory document is not valid JSON"
    );
    // The refusal never quotes the bytes that exhibited the defect.
    assert!(!kind.detail().contains("this is not json"));
}

#[test]
fn a_value_outside_its_grammar_refuses_the_document() {
    let (session, artifact) = pair(1);
    let truncated_session = session[..63].to_owned();
    let cases = [
        // A 63-character session hash is outside the identity grammar.
        source_entry(&truncated_session, &artifact, "current", "claude", &[]),
        source_entry(&session, &artifact, "stale", "claude", &[]),
        source_entry(&session, &artifact, "current", "not an adapter", &[]),
        source_entry(
            &session,
            &artifact,
            "current",
            "claude",
            &[occurrence_entry("byte", 10, 5, &digest(9))],
        ),
        source_entry(
            &session,
            &artifact,
            "current",
            "claude",
            &[occurrence_entry("byte", 0, 10, "nothex")],
        ),
    ];
    for case in &cases {
        assert_eq!(
            parse_err(&inventory_document(EXPORTED, std::slice::from_ref(case))),
            LegacyInventoryErrorKind::MalformedGrammar,
            "case refused as shape or json, not grammar: {case}"
        );
    }
}

#[test]
fn a_defect_outside_the_closed_shape_refuses_the_document() {
    let (session, artifact) = pair(1);
    let wrong_namespace =
        inventory_document(EXPORTED, &[]).replace(NAMESPACE, "archivist.other/v1");
    assert_eq!(
        parse_err(&wrong_namespace),
        LegacyInventoryErrorKind::MalformedShape
    );

    let missing_generated = format!(r#"{{"schema": "{NAMESPACE}", "sources": []}}"#);
    assert_eq!(
        parse_err(&missing_generated),
        LegacyInventoryErrorKind::MalformedShape
    );

    let sources_not_array =
        format!(r#"{{"schema": "{NAMESPACE}", "generated_at": "{EXPORTED}", "sources": {{}}}}"#);
    assert_eq!(
        parse_err(&sources_not_array),
        LegacyInventoryErrorKind::MalformedShape
    );

    let not_an_occurrence = ["7".to_owned()];
    let occurrence_not_object =
        source_entry(&session, &artifact, "current", "claude", &not_an_occurrence);
    assert_eq!(
        parse_err(&inventory_document(EXPORTED, &[occurrence_not_object])),
        LegacyInventoryErrorKind::MalformedShape
    );
}

#[test]
fn an_unknown_member_on_any_level_refuses_the_document() {
    // An unknown top-level member: a field the grammar does not define,
    // carrying a path no comparison must ever see.
    let smuggled_top = format!(
        r#"{{"schema": "{NAMESPACE}", "generated_at": "{EXPORTED}", "sources": [], "upstream_path": "/home/lead"}}"#
    );
    assert_eq!(
        parse_err(&smuggled_top),
        LegacyInventoryErrorKind::MalformedShape
    );

    let (session, artifact) = pair(1);
    let smuggled_source = format!(
        r#"{{"session_hash": "{session}", "artifact_hash": "{artifact}", "adapter": "claude", "coverage": "current", "occurrences": [], "note": "x"}}"#
    );
    assert_eq!(
        parse_err(&inventory_document(EXPORTED, &[smuggled_source])),
        LegacyInventoryErrorKind::MalformedShape
    );

    let smuggled_occurrence = format!(
        r#"{{"range_kind": "bytes", "range_start": 0, "range_end": 10, "blob_digest": "{}", "label": "x"}}"#,
        digest(9)
    );
    let source = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[smuggled_occurrence],
    );
    assert_eq!(
        parse_err(&inventory_document(EXPORTED, &[source])),
        LegacyInventoryErrorKind::MalformedShape
    );
}

#[test]
fn a_duplicate_source_pair_refuses_the_document() {
    let document = inventory_document(EXPORTED, &[standard_source(1), standard_source(1)]);
    assert_eq!(
        parse_err(&document),
        LegacyInventoryErrorKind::DuplicateSource
    );
}

// --- Classification ---------------------------------------------------------

#[test]
fn matched_sources_classify_equivalent_with_empty_differences() {
    let store = migrated();
    standard_state_source(&store, 1);
    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Equivalent);
    assert_eq!(report.sources().matched, 1);
    assert_eq!(report.sources().total(), 1);
    assert!(report.differences().is_empty());
    assert_eq!(report.provenance().sources_both, 1);
    assert_eq!(report.occurrences().classes.matched, 2);
    let json = report.to_json();
    assert_eq!(int_of(member(member(&json, "sources"), "matched")), 1);
    assert_eq!(
        int_of(member(member(&json, "provenance"), "sources_both")),
        1
    );
}

#[test]
fn a_legacy_only_source_is_missing_new_and_listed() {
    let store = migrated();
    standard_state_source(&store, 1);
    let legacy = parse_ok(&inventory_document(
        EXPORTED,
        &[standard_source(1), standard_source(2)],
    ));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Differences);
    assert_eq!(report.sources().matched, 1);
    assert_eq!(report.sources().missing_new, 1);
    assert_eq!(report.differences().len(), 1);
    let difference = &report.differences()[0];
    let (session, _) = pair(2);
    assert_eq!(difference.session().to_hex(), session);
    assert_eq!(difference.gap_class(), GapClass::MissingNew);
    assert_eq!(report.occurrences().classes.missing_new, 2);
    assert_eq!(report.provenance().sources_both, 1);
    // The new archive's own coverage of an absent source is `missing`,
    // and the legacy collector's own verdict is surfaced beside it.
    let row = first_difference(&report);
    assert_eq!(text_of(member(&row, "new_coverage")), "missing");
    assert_eq!(text_of(member(&row, "legacy_coverage")), "current");
}

#[test]
fn a_state_only_source_is_missing_legacy_and_counts_its_provenance() {
    let store = migrated();
    standard_state_source(&store, 1);
    let (session, artifact) = pair(2);
    let source_id = enroll(&store, &session, &artifact, "backfill");
    let gid = generation(&store, &source_id, 2);
    let occurrence_id = occurrence(&store, &gid, "bytes", 0, 8, &digest(21));
    attestation(&store, &occurrence_id, "direct");
    attestation(&store, &occurrence_id, "relay");

    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.sources().missing_legacy, 1);
    assert_eq!(report.occurrences().classes.missing_legacy, 1);
    assert_eq!(report.provenance().attestations_direct, 1);
    assert_eq!(report.provenance().attestations_relay, 1);
    let row = first_difference(&report);
    assert_eq!(text_of(member(&row, "gap_class")), "missing_legacy");
    assert_eq!(text_of(member(&row, "new_coverage")), "backfilled");
    assert_eq!(text_of(member(&row, "adapter_new")), "claude");
    assert!(matches!(member(&row, "adapter_legacy"), Value::Null));
}

#[test]
fn a_disjoint_payload_at_one_position_is_a_digest_mismatch() {
    let store = migrated();
    let (session, artifact) = pair(1);
    let source_id = enroll(&store, &session, &artifact, "freshness");
    let gid = generation(&store, &source_id, 1);
    // Same position as the legacy fixture, disjoint payload.
    occurrence(&store, &gid, "bytes", 0, 10, &digest(99));

    let legacy_source = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[occurrence_entry("byte", 0, 10, &digest(1))],
    );
    let legacy = parse_ok(&inventory_document(EXPORTED, &[legacy_source]));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Differences);
    assert_eq!(report.sources().digest_mismatch, 1);
    assert_eq!(report.occurrences().classes.digest_mismatch, 2);
    assert_eq!(report.occurrences().classes.matched, 0);
    assert_eq!(
        report.differences()[0].gap_class(),
        GapClass::DigestMismatch
    );
}

#[test]
fn self_contradicting_legacy_evidence_is_unexplained_and_dominates() {
    let store = migrated();
    standard_state_source(&store, 1);
    let (session, artifact) = pair(2);
    let source_id = enroll(&store, &session, &artifact, "freshness");
    let gid = generation(&store, &source_id, 2);
    occurrence(&store, &gid, "bytes", 0, 10, &digest(2));

    // Source 2's legacy evidence names two payloads at one position,
    // one of which the new archive acknowledges: the difference is not
    // resolvable at this grain and must stay explicit.
    let contradicting = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[
            occurrence_entry("byte", 0, 10, &digest(2)),
            occurrence_entry("byte", 0, 10, &digest(3)),
        ],
    );
    let legacy = parse_ok(&inventory_document(
        EXPORTED,
        &[standard_source(1), contradicting],
    ));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Unexplained);
    assert_eq!(report.sources().matched, 1);
    assert_eq!(report.sources().unexplained, 1);
    assert_eq!(report.occurrences().classes.unexplained, 2);
    // The self-contradiction is the one listed difference, even though
    // the new archive acknowledged one of the two payloads.
    assert_eq!(report.differences().len(), 1);
    assert_eq!(report.differences()[0].gap_class(), GapClass::Unexplained);
}

#[test]
fn a_legacy_only_source_contradicting_itself_is_still_unexplained() {
    let store = migrated();
    // No new-side source at all: the absence is the `missing_new` gap,
    // but the export contradicts itself, and that outranks the gap.
    let (session, artifact) = pair(2);
    let contradicting = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[
            occurrence_entry("byte", 0, 10, &digest(2)),
            occurrence_entry("byte", 0, 10, &digest(3)),
        ],
    );
    let legacy = parse_ok(&inventory_document(EXPORTED, &[contradicting]));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Unexplained);
    assert_eq!(report.differences().len(), 1);
    assert_eq!(report.differences()[0].gap_class(), GapClass::Unexplained);
    assert_eq!(report.occurrences().classes.unexplained, 2);
    assert_eq!(report.occurrences().classes.missing_new, 0);
}

#[test]
fn generations_fold_into_one_payload_set_per_position() {
    let store = migrated();
    let (session, artifact) = pair(1);
    let source_id = enroll(&store, &session, &artifact, "backfill");
    let gen_a = generation(&store, &source_id, 1);
    let gen_b = generation(&store, &source_id, 2);
    // Two generations of one artifact hold the same position with
    // different payloads (plan EC-02); the new side folds them.
    occurrence(&store, &gen_a, "bytes", 0, 10, &digest(1));
    occurrence(&store, &gen_b, "bytes", 0, 10, &digest(2));

    let legacy = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[occurrence_entry("byte", 0, 10, &digest(1))],
    );
    let legacy = parse_ok(&inventory_document(EXPORTED, &[legacy]));
    let report = compare_ok(&store, &legacy);

    // The shared payload matched; the generation-only payload is
    // coverage the legacy path never established.
    assert_eq!(report.occurrences().classes.matched, 1);
    assert_eq!(report.occurrences().classes.missing_legacy, 1);
    assert_eq!(report.differences()[0].gap_class(), GapClass::MissingLegacy);
    let row = first_difference(&report);
    assert_eq!(int_of(member(&row, "bytes_new")), 20);
    assert_eq!(int_of(member(&row, "bytes_legacy")), 10);
}

#[test]
fn duplicate_identical_entries_are_counted_never_silently_dropped() {
    let store = migrated();
    let (session, artifact) = pair(1);
    let source_id = enroll(&store, &session, &artifact, "freshness");
    let gen_a = generation(&store, &source_id, 1);
    let gen_b = generation(&store, &source_id, 2);
    // The same occurrence acknowledged in two generations: convergence,
    // visible as duplication rather than erased by the fold.
    occurrence(&store, &gen_a, "bytes", 0, 10, &digest(1));
    occurrence(&store, &gen_b, "bytes", 0, 10, &digest(1));

    // The legacy export carried the same occurrence twice: two
    // overlapping legacy collectors converging on one identity.
    let repeated = occurrence_entry("byte", 0, 10, &digest(1));
    let legacy = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[repeated.clone(), repeated],
    );
    let legacy = parse_ok(&inventory_document(EXPORTED, &[legacy]));
    let report = compare_ok(&store, &legacy);

    // The sides agree on the identity, and the duplication survived.
    assert_eq!(report.verdict(), Verdict::Equivalent);
    assert_eq!(report.occurrences().classes.matched, 1);
    assert_eq!(report.occurrences().legacy_duplicates, 1);
    assert_eq!(report.occurrences().new_duplicates, 1);
    assert_eq!(report.provenance().sources_both, 1);
}

#[test]
fn relay_uploads_add_provenance_beside_the_origins() {
    let store = migrated();
    let bytes_occurrence = standard_state_source(&store, 1).remove(0);
    // A relay re-uploaded the origin's bytes occurrence: the direct
    // attestation stays, the relay adds beside it.
    attestation(&store, &bytes_occurrence, "direct");
    attestation(&store, &bytes_occurrence, "relay");

    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.verdict(), Verdict::Equivalent);
    assert_eq!(report.provenance().attestations_direct, 1);
    assert_eq!(report.provenance().attestations_relay, 1);
    assert_eq!(report.provenance().sources_both, 1);
}

#[test]
fn coverage_classification_follows_lane_and_missing_payloads() {
    // Freshness lane, fully matched: current — and equivalent overall.
    let store = migrated();
    standard_state_source(&store, 1);
    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    let report = compare_ok(&store, &legacy);
    assert!(report.differences().is_empty());
    assert_eq!(report.verdict(), Verdict::Equivalent);

    // A legacy payload the new side lacks makes the shared source
    // partial, on either lane.
    let store = migrated();
    let (session, artifact) = pair(1);
    let source_id = enroll(&store, &session, &artifact, "backfill");
    let gid = generation(&store, &source_id, 1);
    occurrence(&store, &gid, "bytes", 0, 10, &digest(1));
    let legacy_source = source_entry(
        &session,
        &artifact,
        "current",
        "claude",
        &[
            occurrence_entry("byte", 0, 10, &digest(1)),
            occurrence_entry("byte", 20, 30, &digest(4)),
        ],
    );
    let legacy = parse_ok(&inventory_document(EXPORTED, &[legacy_source]));
    let report = compare_ok(&store, &legacy);
    assert_eq!(report.occurrences().classes.missing_new, 1);
    let row = first_difference(&report);
    assert_eq!(text_of(member(&row, "new_coverage")), "partial");

    // A state source with nothing acknowledged at all reports absent.
    let store = migrated();
    let (session, artifact) = pair(1);
    enroll(&store, &session, &artifact, "freshness");
    let legacy = parse_ok(&inventory_document(EXPORTED, &[]));
    let report = compare_ok(&store, &legacy);
    assert_eq!(report.differences().len(), 1);
    let row = first_difference(&report);
    assert_eq!(text_of(member(&row, "gap_class")), "missing_legacy");
    assert_eq!(text_of(member(&row, "new_coverage")), "missing");
}

#[test]
fn fleet_counts_aggregate_across_sources() {
    let store = migrated();
    standard_state_source(&store, 1);
    standard_state_source(&store, 3);
    let legacy = parse_ok(&inventory_document(
        EXPORTED,
        &[
            standard_source(1),
            standard_source(2),
            standard_source(3),
            standard_source(4),
        ],
    ));
    let report = compare_ok(&store, &legacy);

    assert_eq!(report.sources().total(), 4);
    assert_eq!(report.sources().matched, 2);
    assert_eq!(report.sources().missing_new, 2);
    assert_eq!(report.occurrences().classes.total(), 8);
    assert_eq!(report.occurrences().classes.matched, 4);
    assert_eq!(report.occurrences().classes.missing_new, 4);
    assert_eq!(report.provenance().sources_both, 2);
    assert_eq!(report.verdict(), Verdict::Differences);
    assert_eq!(report.differences().len(), 2);
}

// --- Digest and report surface ----------------------------------------------

#[test]
fn the_digest_reproduces_and_binds_every_union_source() {
    let store = migrated();
    standard_state_source(&store, 1);
    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));

    let first = compare_ok(&store, &legacy);
    let second = compare_ok(&store, &legacy);
    assert_eq!(first.digest(), second.digest());

    // The report's own generation instant is outside the preimage.
    let later = compare(
        store.connection(),
        &legacy,
        &Timestamp::parse("2026-09-24T18:00:00Z").expect("timestamp"),
    )
    .expect("compare");
    assert_eq!(first.digest(), later.digest());

    // The legacy export instant is inside the preimage.
    let reexported_legacy = parse_ok(&inventory_document(EXPORTED_LATER, &[standard_source(1)]));
    let reexported = compare_ok(&store, &reexported_legacy);
    assert_ne!(first.digest(), reexported.digest());

    // A second matched source changes the digest while leaving the
    // differences list empty: matched sources bind the digest too.
    standard_state_source(&store, 2);
    let wider_legacy = parse_ok(&inventory_document(
        EXPORTED,
        &[standard_source(1), standard_source(2)],
    ));
    let wider = compare_ok(&store, &wider_legacy);
    assert_ne!(first.digest(), wider.digest());
    assert!(wider.differences().is_empty());
    assert_eq!(wider.verdict(), Verdict::Equivalent);
}

#[test]
fn the_digest_label_is_the_comparison_domain() {
    assert_eq!(COMPARISON_DIGEST_LABEL, "pilot-comparison-v1");
    let store = migrated();
    let legacy = parse_ok(&inventory_document(EXPORTED, &[]));
    let report = compare_ok(&store, &legacy);
    // An empty union still digests, as 64 lowercase hex characters.
    assert_eq!(report.digest().len(), 64);
    assert!(
        report
            .digest()
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    );
    assert_eq!(report.verdict(), Verdict::Equivalent);
}

#[test]
fn the_report_json_carries_only_counts_tokens_and_hashes() {
    let store = migrated();
    standard_state_source(&store, 1);
    let (session, artifact) = pair(2);
    let source_id = enroll(&store, &session, &artifact, "backfill");
    let gid = generation(&store, &source_id, 2);
    let occurrence_id = occurrence(&store, &gid, "bytes", 0, 8, &digest(21));
    attestation(&store, &occurrence_id, "relay");
    let legacy = parse_ok(&inventory_document(
        EXPORTED,
        &[standard_source(1), standard_source(2)],
    ));
    let report = compare_ok(&store, &legacy);

    let mut texts = Vec::new();
    let mut ints = Vec::new();
    leaves(&report.to_json(), &mut texts, &mut ints);
    assert!(!ints.is_empty());
    assert!(ints.iter().all(|number| *number >= 0));
    assert!(!texts.is_empty());
    for text in &texts {
        let allowed = text.len() == 64 && text.chars().all(|c| c.is_ascii_hexdigit())
            || *text == NOW
            || *text == EXPORTED
            || matches!(
                text.as_str(),
                "equivalent"
                    | "differences"
                    | "unexplained"
                    | "matched"
                    | "missing_new"
                    | "missing_legacy"
                    | "digest_mismatch"
                    | "missing"
                    | "unsupported"
                    | "failed"
                    | "partial"
                    | "current"
                    | "backfilled"
                    | "claude"
                    | "codex"
                    | "opencode"
                    | "pi"
                    | "synthetic"
            );
        assert!(
            allowed,
            "report text leaf is outside the closed surface: {text}"
        );
    }
}

#[test]
fn the_comparison_document_composes_the_cli_result_namespace() {
    let store = migrated();
    standard_state_source(&store, 1);
    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    let report = compare_ok(&store, &legacy);
    let document = super::comparison_document(&report);
    // The namespace member plus the report's eight closed members.
    match &document {
        Value::Object(members) => assert_eq!(members.len(), 9),
        _ => panic!("the comparison document is an object"),
    }
    assert_eq!(text_of(member(&document, "schema")), RESULT_NAMESPACE);
    assert_eq!(text_of(member(&document, "verdict")), "equivalent");
    assert_eq!(text_of(member(&document, "digest")), report.digest());
}

// --- Read-side failure surfaces ---------------------------------------------

#[test]
fn an_unreadable_state_refuses_content_free() {
    let conn = rusqlite::Connection::open_in_memory().expect("open bare connection");
    let legacy = parse_ok(&inventory_document(EXPORTED, &[]));
    let error = compare(&conn, &legacy, &now()).expect_err("unreadable state refuses");
    assert_eq!(error.kind(), StateErrorKind::Unavailable);
    assert_eq!(
        error.detail(),
        "the comparator could not read the state database"
    );
    // The driver's "no such table" text never reaches the diagnostic.
    assert!(!error.to_string().contains("no such table"));
    assert!(!error.to_string().contains("sources"));
}

#[test]
fn a_stored_value_outside_its_vocabulary_is_schema_corruption() {
    let store = migrated();
    let (session, artifact) = pair(1);
    let legacy = parse_ok(&inventory_document(EXPORTED, &[standard_source(1)]));
    // Simulate corruption the schema's CHECK constraints would refuse:
    // the read-side backstop must catch what the write side cannot.
    store
        .connection()
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("suspend checks");
    store
        .connection()
        .execute(
            "INSERT INTO sources (source_id, harness, upstream_session_id, id_source,
                session_hash, artifact_kind, adapter_id, adapter_projection_version,
                adapter_artifact_id, artifact_hash, freshness_lane, last_cursor,
                created_at, updated_at)
             VALUES ('11111111-1111-4222-8333-111111111111', 'claude', 'upstream',
                'natural', ?1, 'transcript', 'claude', 'v1', 'artifact', ?2,
                'stale', NULL, ?3, ?3)",
            params![session, artifact, NOW],
        )
        .expect("insert corrupting row");
    let error = compare(store.connection(), &legacy, &now())
        .expect_err("a lane outside the vocabulary refuses");
    assert_eq!(error.kind(), StateErrorKind::SchemaCorruption);
    // The stored value itself never reaches the diagnostic.
    assert!(!error.to_string().contains("stale"));
}
