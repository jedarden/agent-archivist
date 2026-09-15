// SPDX-License-Identifier: Apache-2.0

//! Offline replay of the full control-record corpus
//! (`schemas/v1/examples/control/`): every pinned record of the five
//! scenario families, both pinned acceptance tables, and the manifest's
//! own byte pins and invariants — replayed from the committed bytes
//! against `keys.json` alone, with no server and no corpus-private
//! material. The corpus emits no private half, and these tests derive
//! nothing from its seed names either: verification consumes public
//! halves and pinned expectations only.
//!
//! Each scenario file carries its own decision procedure in its
//! `generation` member; the fold here is that procedure, applied in
//! history order: the pre-signature canonical bytes against the pinned
//! digest, the signature against the `keys.json` half the record's own
//! `authority_key_id` names, then the record family's rule (strictly
//! increasing epochs for current-pointer records, write-once with
//! idempotent repair for immutable ones, and the revocation, rotation,
//! and receipt-key cross-record checks) against the fold's state. The
//! fold must land on the file's `final_state`.
//!
//! The authority-rotation chain keeps its dedicated replay — its digest
//! convention covers complete records, not pre-signature bytes — in
//! `authority_corpus.rs`; the manifest test here fails when a scenario
//! family lands without a Rust replay.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use archivist_auth::ed25519::{self, Signature};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, Timestamp};

/// The corpus directory, relative to this crate.
const CORPUS_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/v1/examples/control"
);

/// The scenario families this suite replays end to end, by manifest
/// stem — the test per family names the family so a failure points at
/// it.
const REPLAYED: [(&str, &str); 5] = [
    ("epoch-progression", "linked-client"),
    ("delegation-lifecycle", "delegation"),
    ("revocation", "revocation"),
    ("key-rotation", "rotation"),
    ("receipt-key-cohort", "receipt-key"),
];

/// The one scenario family whose replay lives in `authority_corpus.rs`.
const CHAIN_STEM: &str = "authority-rotation-chain";

/// The corpus files that are bundle plumbing rather than a scenario.
const PLUMBING_FILES: [&str; 2] = ["keys.json", "manifest.json"];

// ---------------------------------------------------------------------------
// The keys.json table and the manifest's own pins
// ---------------------------------------------------------------------------

#[test]
fn every_keys_json_key_id_is_the_pinned_derivation_of_its_own_half() {
    // The derivation is what lets a verifier bind a record's named
    // authority_key_id to the half that must verify: prove it for every
    // key in the table once.
    for entry in array(&read_corpus_object("keys.json"), "keys") {
        let entry = object_of(entry, "keys entry");
        let name = text(entry, "name");
        let public = Ed25519PublicKey::parse(text(entry, "public_key"))
            .unwrap_or_else(|error| panic!("{name}: the public half parses: {error:?}"));
        let key_id = KeyId::parse(text(entry, "key_id"))
            .unwrap_or_else(|error| panic!("{name}: the key ID parses: {error:?}"));
        assert_eq!(
            key_id,
            KeyId::from_public_key(&public),
            "{name}: the key ID is the pinned derivation of its own half"
        );
    }
}

#[test]
fn the_manifest_pins_every_corpus_byte_and_names_a_replay_for_every_scenario() {
    let manifest = manifest();

    // Every file the manifest lists exists at its pinned byte count and
    // digest — a missing or drifted committed byte fails here before any
    // record-level replay runs.
    let mut file_stems = Vec::new();
    for member in array(&manifest, "files") {
        let entry = object_of(member, "files entry");
        let path = text(entry, "path");
        let bytes = read_corpus(path);
        assert_eq!(
            bytes.len(),
            usize::try_from(int_member(entry, "bytes"))
                .unwrap_or_else(|_| panic!("{path}: the pinned byte count overflows")),
            "{path}: the pinned byte count"
        );
        assert_eq!(
            sha256_hex(&bytes),
            text(entry, "sha256"),
            "{path}: the pinned byte digest"
        );
        match path.strip_suffix(".json") {
            Some(stem) if !PLUMBING_FILES.contains(&path) => file_stems.push(stem.to_owned()),
            _ => {}
        }
    }

    // Completeness, both ways: every scenario names its own file, and
    // every non-plumbing file is a scenario — one replayed here, the
    // chain in authority_corpus.rs. A new family without a replay fails
    // this set check.
    let scenarios = array(&manifest, "scenarios");
    let mut scenario_ids = Vec::new();
    for member in &scenarios {
        let scenario = object_of(member, "scenario");
        let id = text(scenario, "id");
        let expected_file = format!("{id}.json");
        assert_eq!(
            text(scenario, "file"),
            expected_file.as_str(),
            "{id}: the manifest's scenario row names its own file"
        );
        scenario_ids.push(id.to_owned());
    }
    file_stems.sort();
    scenario_ids.sort();
    assert_eq!(file_stems, scenario_ids, "scenarios and files agree");
    for id in &scenario_ids {
        assert!(
            id == CHAIN_STEM || REPLAYED.iter().any(|(stem, _)| stem == id),
            "{id}: every scenario family must have a Rust replay"
        );
    }

    // The pinned acceptance-table sizes: the two tables replayed here
    // and the chain's, whose verdicts authority_corpus.rs replays.
    for member in &scenarios {
        let scenario = object_of(member, "scenario");
        let id = text(scenario, "id");
        let pinned_vectors = int_member(scenario, "decision_vectors");
        let file = read_corpus_object(text(scenario, "file"));
        let table_len = match id {
            CHAIN_STEM => array(&file, "acceptance").len(),
            "key-rotation" => array(&file, "attempt_acceptance").len(),
            "receipt-key-cohort" => array(&file, "signing_acceptance").len(),
            other => {
                assert_eq!(
                    pinned_vectors, 0,
                    "{other}: a family without an acceptance table pins no vectors"
                );
                continue;
            }
        };
        assert_eq!(
            table_len,
            usize::try_from(pinned_vectors)
                .unwrap_or_else(|_| panic!("{id}: the pinned vector count overflows")),
            "{id}: the manifest pins the acceptance table's size"
        );
    }
}

#[test]
fn the_manifest_invariants_replay_from_the_scenario_tables() {
    let manifest = manifest();
    let mut records = 0_usize;
    let mut accepted = 0_usize;
    let mut rejected = 0_usize;
    let mut reasons: BTreeMap<&str, usize> = BTreeMap::new();
    for member in array(&manifest, "scenarios") {
        let scenario = object_of(member, "scenario");
        for record in array(scenario, "records") {
            let record = object_of(record, "pinned record");
            records += 1;
            match text(record, "expected") {
                "accepted" => accepted += 1,
                // The chain's window verdicts (`retired`, `unreachable`)
                // are rejection-class outcomes decided by the chain walk
                // (authority_corpus.rs's replay), and alone among the
                // rejections they pin no decision-procedure reason token.
                "rejected" | "retired" | "unreachable" => {
                    rejected += 1;
                    if let Some(reason) = opt_text(record, "reason") {
                        *reasons.entry(reason).or_insert(0) += 1;
                    }
                }
                other => panic!("unknown pinned expected verdict {other}"),
            }
        }
    }
    let invariants = object(&manifest, "invariants");
    assert_eq!(
        records,
        usize::try_from(int_member(invariants, "records")).expect("the pinned record count fits"),
        "the manifest pins every record it tables"
    );
    assert_eq!(
        accepted,
        usize::try_from(int_member(invariants, "accepted"))
            .expect("the pinned acceptance count fits"),
        "the pinned acceptance total"
    );
    assert_eq!(
        rejected,
        usize::try_from(int_member(invariants, "rejected"))
            .expect("the pinned rejection count fits"),
        "the pinned rejection total"
    );
    let pinned_reasons = object(invariants, "rejections_by_reason");
    assert_eq!(
        pinned_reasons.len(),
        reasons.len(),
        "the pinned rejection-reason vocabulary is complete"
    );
    for (token, _) in pinned_reasons.iter() {
        assert_eq!(
            usize::try_from(int_member(pinned_reasons, token))
                .expect("the pinned reason count fits"),
            reasons.get(token).copied().unwrap_or(0),
            "{token}: the pinned rejection count"
        );
    }
}

// ---------------------------------------------------------------------------
// One replay per scenario family — the test name names the family
// ---------------------------------------------------------------------------

#[test]
fn linked_client_family_replays_to_the_pinned_outcomes() {
    replay_family("epoch-progression", "linked-client");
}

#[test]
fn delegation_family_replays_to_the_pinned_outcomes() {
    replay_family("delegation-lifecycle", "delegation");
}

#[test]
fn revocation_family_replays_to_the_pinned_outcomes() {
    replay_family("revocation", "revocation");
}

#[test]
fn rotation_family_replays_to_the_pinned_outcomes() {
    replay_family("key-rotation", "rotation");
}

#[test]
fn receipt_key_family_replays_to_the_pinned_outcomes() {
    replay_family("receipt-key-cohort", "receipt-key");
}

// ---------------------------------------------------------------------------
// The pinned acceptance tables (the manifest's decision vectors)
// ---------------------------------------------------------------------------

#[test]
fn rotation_attempt_acceptance_replays_the_pinned_window() {
    let stem = "key-rotation";
    let manifest = manifest();
    let scenario = scenario_of(&manifest, stem);
    let file = read_corpus_object(&format!("{stem}.json"));
    let overlap_hours = int_member(
        object(&file, "generation"),
        "rotation_verification_overlap_hours",
    );

    // The window anchors at the rotation record the pin names, and the
    // old half may sign an attempt from that instant through
    // rotationVerificationOverlapHours later, inclusive of its last
    // instant; the new half verifies from the rotation instant on.
    let rotation = history_record_named(
        &file,
        text(object(&file, "pinned"), "rotation_record"),
        stem,
    );
    assert_eq!(
        text(&rotation, "record_type"),
        "rotation",
        "{stem}: the pinned anchor is the rotation record"
    );
    let previous_half = text(&rotation, "previous_key_id");
    let new_half = text(&rotation, "key_id");
    let anchor = utc_instant(&timestamp_member(&rotation, "signed_at"));
    let window_end = (anchor.0 + overlap_hours * 3_600, anchor.1);

    let table = array(&file, "attempt_acceptance");
    assert_eq!(
        table.len(),
        usize::try_from(int_member(scenario, "decision_vectors"))
            .expect("the pinned vector count fits"),
        "{stem}: the manifest pins the table's size"
    );
    for case in table {
        let case = object_of(case, "acceptance case");
        let key = text(case, "key_id");
        let at = utc_instant(&timestamp_member(case, "signed_at"));
        let signed_at = text(case, "signed_at");
        let accepted = if key == new_half {
            true
        } else if key == previous_half {
            anchor <= at && at <= window_end
        } else {
            false
        };
        let expected = text(case, "expected");
        if accepted {
            assert_eq!(
                expected, "accepted",
                "{stem}: {key} at {signed_at} — the window accepts; the corpus pins {expected:?}"
            );
            assert_eq!(
                opt_text(case, "reason"),
                None,
                "{stem}: an acceptance pins no reason"
            );
        } else {
            assert_eq!(
                expected, "rejected",
                "{stem}: {key} at {signed_at} — the window refuses; the corpus pins {expected:?}"
            );
            assert_eq!(
                opt_text(case, "reason"),
                Some("outside-overlap"),
                "{stem}: {key} at {signed_at} — the pinned rejection class"
            );
        }
    }
}

#[test]
fn receipt_key_signing_acceptance_replays_the_pinned_windows() {
    let stem = "receipt-key-cohort";
    let manifest = manifest();
    let scenario = scenario_of(&manifest, stem);
    let file = read_corpus_object(&format!("{stem}.json"));
    let state = replay_family(stem, "receipt-key");

    // The pin's certified cohort is exactly what the fold certified, at
    // the windows the certifications signed.
    let cohort = array(object(&file, "pinned"), "certified_cohort");
    assert_eq!(
        cohort.len(),
        state.receipt_windows.len(),
        "{stem}: the pin's certified cohort is what the fold certified"
    );
    for member in cohort {
        let member = object_of(member, "cohort entry");
        let key_id = text(member, "key_id");
        let window = state
            .receipt_windows
            .get(key_id)
            .unwrap_or_else(|| panic!("{stem}: the fold never certified {key_id}"));
        assert_eq!(
            utc_instant(&timestamp_member(member, "valid_from")),
            window.valid_from,
            "{key_id}: the pinned window opens where the certification's does"
        );
        assert_eq!(
            utc_instant(&timestamp_member(member, "valid_until")),
            window.valid_until,
            "{key_id}: the pinned window closes where the certification's does"
        );
    }

    // A key signs only inside its own [valid_from, valid_until], both
    // ends inclusive: the overlap lets the cohort's two halves sign at
    // once, and a receipt a key already signed keeps verifying after.
    let table = array(&file, "signing_acceptance");
    assert_eq!(
        table.len(),
        usize::try_from(int_member(scenario, "decision_vectors"))
            .expect("the pinned vector count fits"),
        "{stem}: the manifest pins the table's size"
    );
    for case in table {
        let case = object_of(case, "acceptance case");
        let key_id = text(case, "key_id");
        let window = state
            .receipt_windows
            .get(key_id)
            .unwrap_or_else(|| panic!("{stem}: an acceptance case names uncertified key {key_id}"));
        let at = utc_instant(&timestamp_member(case, "signed_at"));
        let signed_at = text(case, "signed_at");
        let accepted = window.valid_from <= at && at <= window.valid_until;
        let expected = text(case, "expected");
        if accepted {
            assert_eq!(
                expected, "accepted",
                "{stem}: {key_id} at {signed_at} — inside the window; the corpus pins {expected:?}"
            );
            assert_eq!(
                opt_text(case, "reason"),
                None,
                "{stem}: an acceptance pins no reason"
            );
        } else {
            assert_eq!(
                expected, "rejected",
                "{stem}: {key_id} at {signed_at} — outside the window; the corpus pins {expected:?}"
            );
            assert_eq!(
                opt_text(case, "reason"),
                Some("outside-signing-window"),
                "{stem}: {key_id} at {signed_at} — the pinned rejection class"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The fold: the corpus decision procedure
// ---------------------------------------------------------------------------

/// Why the store refuses one history entry, as the corpus's closed
/// reason token.
type Reason = &'static str;

/// One history entry's computed outcome.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The write lands.
    Accepted,
    /// The store refuses the write, for the pinned reason.
    Rejected(Reason),
}

/// The receipt-key window a certification pins, as UTC instants.
#[derive(Clone, Copy)]
struct ReceiptWindow {
    valid_from: (i64, u32),
    valid_until: (i64, u32),
}

/// One object the fold landed, as `final_state` pins it: the landing
/// record's name, and the pointer epoch a current-pointer, rotation, or
/// revocation write carries, or the key ID a receipt-key certification
/// carries.
struct Landed {
    record: String,
    epoch: Option<i64>,
    key_id: Option<String>,
}

/// The store fold's state: the standing per-subject pointers, the
/// immutable objects written once at their derived keys, the certified
/// receipt-key windows, and what landed where.
#[derive(Default)]
struct ControlState {
    pointers: HashMap<String, (i64, Option<String>)>,
    immutable: HashMap<String, String>,
    receipt_windows: BTreeMap<String, ReceiptWindow>,
    last_receipt: Option<ReceiptWindow>,
    landed: BTreeMap<String, Landed>,
}

/// The pinned generation constants the fold's rules read from the
/// scenario file's own `generation` block.
struct FoldRules {
    receipt_key_rotation_days: i64,
    receipt_key_signing_overlap_days: i64,
}

impl FoldRules {
    /// The rules one scenario file pins.
    fn of(file: &Object) -> Self {
        let generation = object(file, "generation");
        Self {
            receipt_key_rotation_days: int_member(generation, "receipt_key_rotation_days"),
            receipt_key_signing_overlap_days: int_member(
                generation,
                "receipt_key_signing_overlap_days",
            ),
        }
    }
}

impl ControlState {
    /// Record an acceptance's landing.
    fn land(&mut self, key: String, record: &str, epoch: Option<i64>, key_id: Option<String>) {
        self.landed.insert(
            key,
            Landed {
                record: record.to_owned(),
                epoch,
                key_id,
            },
        );
    }
}

/// Replay one scenario family end to end: the manifest's scenario row
/// agrees with the file, every history entry's digest pin and signature
/// replay offline, the fold's verdict equals the pinned outcome per
/// entry, and the fold lands on the file's `final_state`.
fn replay_family(stem: &str, family: &str) -> ControlState {
    let manifest = manifest();
    let scenario = scenario_of(&manifest, stem);
    assert_eq!(
        text(scenario, "family"),
        family,
        "{stem}: the manifest's family token"
    );
    let file = read_corpus_object(&format!("{stem}.json"));
    assert_eq!(
        text(&file, "$schema"),
        text(scenario, "schema"),
        "{stem}: the manifest's schema URN is the file's own"
    );

    // The manifest tables every history entry, in order, with the same
    // pinned outcome — the per-entry table the manifest test tallies.
    let history = array(&file, "history");
    let pinned_records = array(scenario, "records");
    assert_eq!(
        history.len(),
        pinned_records.len(),
        "{stem}: the manifest tables every history entry"
    );
    for (entry, pinned) in history.iter().zip(pinned_records) {
        let entry = object_of(entry, "history entry");
        let pinned = object_of(pinned, "pinned record");
        let name = text(entry, "name");
        assert_eq!(name, text(pinned, "name"), "{stem}: history order");
        assert_eq!(
            text(entry, "expected"),
            text(pinned, "expected"),
            "{stem}/{name}: the pinned expected outcome"
        );
        assert_eq!(
            opt_text(entry, "reason"),
            opt_text(pinned, "reason"),
            "{stem}/{name}: the pinned reason"
        );
        assert_eq!(
            text(object(entry, "record"), "record_type"),
            text(pinned, "record_type"),
            "{stem}/{name}: the pinned record type"
        );
    }

    let keys = public_keys_by_id();
    let rules = FoldRules::of(&file);
    let mut state = ControlState::default();
    for entry in history {
        let entry = object_of(entry, "history entry");
        let verdict = fold_entry(entry, &rules, &keys, &mut state);
        assert_pinned_verdict(stem, entry, &verdict);
    }
    assert_final_state(stem, &file, &state);
    state
}

/// Replay one history entry through the corpus decision procedure: the
/// pre-signature canonical bytes against the pinned digest, the
/// signature against the `keys.json` half the record's own
/// `authority_key_id` names, then the record family's rule against the
/// fold's state. On acceptance the state moves.
fn fold_entry(
    entry: &Object,
    rules: &FoldRules,
    keys: &HashMap<String, [u8; 32]>,
    state: &mut ControlState,
) -> Verdict {
    let name = text(entry, "name");
    let record = object(entry, "record");
    let canonical = canonical_bytes_without_signature(record);

    // The pre-signature digest pin: any drifted committed byte breaks
    // this before the signature check reads it.
    assert_eq!(
        sha256_hex(&canonical),
        text(entry, "canonical_bytes_sha256"),
        "{name}: the canonical bytes must hash to the pinned digest"
    );

    // Verification precedes every rule: the signature must verify
    // against the half keys.json holds for the record's own
    // authority_key_id — never against the record's own assertion of who
    // signed it. A key the table does not hold, or a signature that
    // fails against the half it names (the relay-forged grant), is the
    // untrusted-signer rejection, and the decision ends there.
    let verified = keys
        .get(text(record, "authority_key_id"))
        .is_some_and(|public| {
            ed25519::verify(
                public,
                &canonical,
                &signature_of(text(record, "authority_signature")),
            )
        });
    if !verified {
        return Verdict::Rejected("untrusted-signer");
    }

    let record_type = text(record, "record_type");
    let key = derive_object_key(record);
    match record_type {
        // Current-pointer write class: the signed authorization_epoch
        // must strictly exceed the standing one — equal or lower is a
        // stale write, even though the signature verified.
        "linked-client" | "delegation" => {
            let epoch = int_member(record, "authorization_epoch");
            match state.pointers.get(&key) {
                Some((standing, _)) if epoch <= *standing => Verdict::Rejected("stale-epoch"),
                _ => {
                    let half = opt_text(record, "key_id").map(str::to_owned);
                    state.pointers.insert(key.clone(), (epoch, half));
                    state.land(key, name, Some(epoch), None);
                    Verdict::Accepted
                }
            }
        }
        // Immutable write classes: one object per derived key, written
        // once. A byte-identical retry lands again as an idempotent
        // repair (never overwriting the landing record's name); any
        // other bytes at the occupied key are the integrity conflict —
        // decided before the family's own cross-record checks.
        "rotation" | "revocation" | "receipt-key" => {
            fold_immutable_entry(name, record, record_type, &key, rules, state)
        }
        other => panic!("{name}: a corpus record of unknown type {other}"),
    }
}

/// The immutable write classes' fold: write-once at the derived key with
/// idempotent repair, then the family's own cross-record checks.
fn fold_immutable_entry(
    name: &str,
    record: &Object,
    record_type: &str,
    key: &str,
    rules: &FoldRules,
    state: &mut ControlState,
) -> Verdict {
    let digest = sha256_hex(&canonical_bytes_without_signature(record));
    if let Some(landed_digest) = state.immutable.get(key) {
        return if *landed_digest == digest {
            Verdict::Accepted
        } else {
            Verdict::Rejected("integrity-conflict")
        };
    }
    // The revocation and rotation cross-record checks read the subject
    // client's standing pointer — the linked-client object key — not the
    // record's own derived key, which no pointer ever occupies.
    let epoch = (record_type != "receipt-key").then(|| int_member(record, "authorization_epoch"));
    let mut certified = None;
    let reason = if record_type == "revocation" {
        let standing = state.pointers.get(&client_pointer_key(record));
        let epoch = epoch.expect("a revocation carries an epoch");
        if standing.is_none_or(|(standing_epoch, _)| epoch > *standing_epoch) {
            // One cannot pre-revoke an epoch the client has not reached:
            // no forward-dated revocation.
            Some("epoch-unreached")
        } else if standing.map(|(_, half)| half.as_deref())
            != Some(Some(text(record, "revoked_key_id")))
        {
            // The revocation must name the half the pointer holds.
            Some("key-id-mismatch")
        } else {
            None
        }
    } else if record_type == "rotation" {
        let standing = state.pointers.get(&client_pointer_key(record));
        let epoch = epoch.expect("a rotation carries an epoch");
        if standing.is_none_or(|(standing_epoch, _)| epoch > *standing_epoch) {
            // A forward-dated rotation would arm its own overlap window
            // early.
            Some("epoch-unreached")
        } else if standing.map(|(_, half)| half.as_deref()) != Some(Some(text(record, "key_id"))) {
            // The record and the pointer bump that activates it are one
            // administrative act: the standing half must be this
            // record's new half.
            Some("pointer-key-mismatch")
        } else {
            None
        }
    } else {
        // Receipt-key certification: the key_id must be the pinned
        // derivation of the record's own public half, and the window
        // must chain to the cohort's predecessor at the pinned cadence —
        // valid_from exactly receiptKeyRotationDays after the
        // predecessor's, and valid_until exactly rotation + signing
        // overlap past valid_from.
        let key_id = text(record, "key_id");
        let public = Ed25519PublicKey::parse(text(record, "public_key"))
            .expect("a receipt-key's public half parses");
        let window = ReceiptWindow {
            valid_from: utc_instant(&timestamp_member(record, "valid_from")),
            valid_until: utc_instant(&timestamp_member(record, "valid_until")),
        };
        let cadence = rules.receipt_key_rotation_days * 86_400;
        let span =
            (rules.receipt_key_rotation_days + rules.receipt_key_signing_overlap_days) * 86_400;
        let reason = if KeyId::from_public_key(&public).to_hex() != key_id {
            Some("key-id-mismatch")
        } else if let Some(last) = &state.last_receipt {
            (window.valid_from.0 != last.valid_from.0 + cadence
                || window.valid_until.0 != window.valid_from.0 + span)
                .then_some("window-discontinuity")
        } else {
            None
        };
        certified = Some((key_id.to_owned(), window));
        reason
    };
    let key = key.to_owned();
    if let Some(reason) = reason {
        return Verdict::Rejected(reason);
    }
    state.immutable.insert(key.clone(), digest);
    if let Some((key_id, window)) = certified {
        state.receipt_windows.insert(key_id.clone(), window);
        state.last_receipt = Some(window);
        state.land(key, name, None, Some(key_id));
    } else {
        state.land(key, name, epoch, None);
    }
    Verdict::Accepted
}

/// The pinned expectation one history entry carries, checked against the
/// fold's computed verdict — the failure names the family and the record.
fn assert_pinned_verdict(stem: &str, entry: &Object, verdict: &Verdict) {
    let name = text(entry, "name");
    let expected = text(entry, "expected");
    let pinned_reason = opt_text(entry, "reason");
    match verdict {
        Verdict::Accepted => {
            assert_eq!(
                expected, "accepted",
                "{stem}/{name}: the fold accepts; the corpus pins {expected:?}"
            );
            assert_eq!(
                pinned_reason, None,
                "{stem}/{name}: an acceptance pins no reason"
            );
        }
        Verdict::Rejected(reason) => {
            assert_eq!(
                expected, "rejected",
                "{stem}/{name}: the fold rejects with {reason}; the corpus pins {expected:?}"
            );
            assert_eq!(
                Some(*reason),
                pinned_reason,
                "{stem}/{name}: the pinned rejection class"
            );
        }
    }
}

/// The fold must land on the file's `final_state`: exactly the same
/// objects at the same keys with the same pinned members.
fn assert_final_state(stem: &str, file: &Object, state: &ControlState) {
    let final_state = object(file, "final_state");
    assert_eq!(
        final_state.len(),
        state.landed.len(),
        "{stem}: the fold lands exactly final_state's objects"
    );
    for (key, pinned) in final_state.iter() {
        let pinned = object_of(pinned, "final_state entry");
        let landed = state
            .landed
            .get(key)
            .unwrap_or_else(|| panic!("{stem}: the fold never lands {key}"));
        assert_eq!(
            text(pinned, "record"),
            landed.record,
            "{stem}/{key}: the landing record"
        );
        match (landed.epoch, landed.key_id.as_deref()) {
            (Some(epoch), None) => assert_eq!(
                int_member(pinned, "authorization_epoch"),
                epoch,
                "{stem}/{key}: the landing epoch"
            ),
            (None, Some(key_id)) => assert_eq!(
                text(pinned, "key_id"),
                key_id,
                "{stem}/{key}: the landing key"
            ),
            _ => panic!("{stem}/{key}: a landing pins either an epoch or a key ID"),
        }
    }
}

/// The store-derived object key for a corpus record: the envelope
/// registry's layout (`tools/control-records.toml`, ID-008) with the
/// record's own key members substituted in `key_members` order.
fn derive_object_key(record: &Object) -> String {
    let tenant = text(record, "tenant_id");
    match text(record, "record_type") {
        "linked-client" => format!(
            "tenants/{tenant}/v1/control/clients/{}.json",
            text(record, "client_id")
        ),
        "delegation" => format!(
            "tenants/{tenant}/v1/control/delegations/{}/{}.json",
            text(record, "relay_client_id"),
            text(record, "origin_client_id")
        ),
        "revocation" => format!(
            "tenants/{tenant}/v1/control/revocations/{}/{}.json",
            text(record, "client_id"),
            int_member(record, "authorization_epoch")
        ),
        "rotation" => format!(
            "tenants/{tenant}/v1/control/rotations/{}/{}.json",
            text(record, "client_id"),
            int_member(record, "authorization_epoch")
        ),
        "receipt-key" => format!(
            "tenants/{tenant}/v1/control/receipt-keys/{}.json",
            text(record, "key_id")
        ),
        other => panic!("a corpus record of unknown type {other}"),
    }
}

/// The linked-client object key a revocation or rotation addresses: the
/// standing pointer its cross-record checks read.
fn client_pointer_key(record: &Object) -> String {
    format!(
        "tenants/{}/v1/control/clients/{}.json",
        text(record, "tenant_id"),
        text(record, "client_id")
    )
}

/// The public-half table keys.json holds, keyed by key ID — the only key
/// material a replay consumes. Every entry's ID is proven to be the
/// pinned derivation of its own half.
fn public_keys_by_id() -> HashMap<String, [u8; 32]> {
    let keys = read_corpus_object("keys.json");
    let mut table = HashMap::new();
    for member in array(&keys, "keys") {
        let entry = object_of(member, "keys entry");
        let name = text(entry, "name");
        let public = Ed25519PublicKey::parse(text(entry, "public_key"))
            .unwrap_or_else(|error| panic!("{name}: the public half parses: {error:?}"));
        let key_id = KeyId::parse(text(entry, "key_id"))
            .unwrap_or_else(|error| panic!("{name}: the key ID parses: {error:?}"));
        assert_eq!(
            key_id,
            KeyId::from_public_key(&public),
            "{name}: the key ID is the pinned derivation of its own half"
        );
        table.insert(key_id.to_hex(), *public.as_raw());
    }
    assert!(!table.is_empty(), "keys.json holds at least one key");
    table
}

/// The record of the history entry `name` in a scenario file.
fn history_record_named(file: &Object, name: &str, stem: &str) -> Object {
    for entry in array(file, "history") {
        let entry = object_of(entry, "history entry");
        if text(entry, "name") == name {
            return object(entry, "record").clone();
        }
    }
    panic!("{stem}: no history entry names {name}");
}

/// The manifest's scenario row for one family stem, or a failure —
/// including for a stem no scenario names.
fn scenario_of<'a>(manifest: &'a Object, stem: &str) -> &'a Object {
    for member in array(manifest, "scenarios") {
        let scenario = object_of(member, "scenario");
        if text(scenario, "id") == stem {
            return scenario;
        }
    }
    panic!("the manifest tables no scenario {stem}");
}

/// Read and parse the corpus manifest.
fn manifest() -> Object {
    read_corpus_object("manifest.json")
}

/// The canonical bytes a control record's signature covers: RFC 8785
/// canonicalization of the complete record with the signature member
/// removed (the control-record-v1 construction).
fn canonical_bytes_without_signature(record: &Object) -> Vec<u8> {
    let mut unsigned = record.clone();
    assert!(
        unsigned.remove("authority_signature").is_some(),
        "a corpus record always carries the signature it strips"
    );
    Value::Object(unsigned).canonical_bytes()
}

/// The 64-byte Ed25519 signature a record pins, from its hex text.
fn signature_of(text: &str) -> Signature {
    let raw = decode_hex(text);
    let raw: [u8; 64] = raw.try_into().unwrap_or_else(|raw: Vec<u8>| {
        panic!(
            "a control-record signature is 128 hex characters, got {} bytes",
            raw.len()
        )
    });
    Signature::from_bytes(raw)
}

/// Decode an even-length lowercase hex string.
fn decode_hex(text: &str) -> Vec<u8> {
    let raw = text.as_bytes();
    assert!(
        raw.len().is_multiple_of(2) && raw.len() / 2 > 0,
        "hex text has a nonzero even length: {text}"
    );
    let value = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        other => panic!("a non-hex byte {other:#x} in {text}"),
    };
    raw.chunks_exact(2)
        .map(|pair| value(pair[0]) * 16 + value(pair[1]))
        .collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&sha256::digest(bytes))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A corpus instant as (UTC seconds from the epoch, nanosecond into that
/// second) — the pair the pinned windows' arithmetic compares. The
/// grammar pins the fixed `YYYY-MM-DDTHH:MM:SS[.fff…]Z` layout, so the
/// index arithmetic below is safe.
fn utc_instant(timestamp: &Timestamp) -> (i64, u32) {
    let raw = timestamp.as_str();
    let digits = |range: std::ops::Range<usize>| {
        raw[range]
            .bytes()
            .fold(0_i64, |acc, byte| acc * 10 + i64::from(byte - b'0'))
    };
    let year = digits(0..4);
    let month = digits(5..7);
    let day = digits(8..10);
    let hour = digits(11..13);
    let minute = digits(14..16);
    let second = digits(17..19);
    let nanosecond = match raw.find('.') {
        None => 0,
        Some(at) => {
            let fraction = &raw[at + 1..raw.len() - 1];
            let mut value = 0_u32;
            for digit in fraction.bytes().take(9) {
                value = value * 10 + u32::from(digit - b'0');
            }
            for _ in fraction.len()..9 {
                value *= 10;
            }
            value
        }
    };
    (
        days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second,
        nanosecond,
    )
}

/// Whole days from 1970-01-01 to a civil UTC date (Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let shifted = if month <= 2 { year - 1 } else { year };
    let era = (if shifted >= 0 { shifted } else { shifted - 399 }) / 400;
    let year_of_era = shifted - era * 400;
    let month_pattern = (month + 9) % 12;
    let day_of_year = (153 * month_pattern + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

// ---------------------------------------------------------------------------
// Member access, in the authority_corpus.rs mold: one type per member, or
// a failure naming the member
// ---------------------------------------------------------------------------

/// Read one corpus file's committed bytes.
fn read_corpus(path: &str) -> Vec<u8> {
    std::fs::read(format!("{CORPUS_DIR}/{path}"))
        .unwrap_or_else(|error| panic!("the corpus file {path} must be readable: {error}"))
}

/// Read and parse one corpus file's committed bytes.
fn read_corpus_object(path: &str) -> Object {
    let bytes = read_corpus(path);
    match json::parse(&bytes)
        .unwrap_or_else(|error| panic!("the corpus file {path} is well-formed JSON: {error:?}"))
    {
        Value::Object(object) => object,
        other => panic!("the corpus file {path} root is an object, got {other:?}"),
    }
}

/// One string member, or a failure naming the member.
fn text<'a>(object: &'a Object, member: &str) -> &'a str {
    match object.get(member) {
        Some(Value::Text(text)) => text.as_str(),
        other => panic!("the member {member} must be a string, got {other:?}"),
    }
}

/// One optional string member.
fn opt_text<'a>(object: &'a Object, member: &str) -> Option<&'a str> {
    match object.get(member) {
        None => None,
        Some(Value::Text(text)) => Some(text.as_str()),
        Some(other) => panic!("the member {member} must be a string, got {other:?}"),
    }
}

/// One integer member, or a failure naming the member.
fn int_member(object: &Object, member: &str) -> i64 {
    match object.get(member) {
        Some(Value::Int(int)) => *int,
        other => panic!("the member {member} must be an integer, got {other:?}"),
    }
}

/// One object-valued member, or a failure naming the member.
fn object<'a>(object: &'a Object, member: &str) -> &'a Object {
    match object.get(member) {
        Some(Value::Object(inner)) => inner,
        other => panic!("the member {member} must be an object, got {other:?}"),
    }
}

/// One array-valued member, or a failure naming the member.
fn array<'a>(object: &'a Object, member: &str) -> Vec<&'a Value> {
    match object.get(member) {
        Some(Value::Array(items)) => items.iter().collect(),
        other => panic!("the member {member} must be an array, got {other:?}"),
    }
}

/// One object-valued item out of an array, or a failure naming the slot.
fn object_of<'a>(value: &'a Value, what: &str) -> &'a Object {
    match value {
        Value::Object(object) => object,
        other => panic!("each {what} is an object, got {other:?}"),
    }
}

/// One instant member, parsed.
fn timestamp_member(object: &Object, member: &str) -> Timestamp {
    Timestamp::parse(text(object, member))
        .unwrap_or_else(|error| panic!("the member {member} must be an instant: {error:?}"))
}
