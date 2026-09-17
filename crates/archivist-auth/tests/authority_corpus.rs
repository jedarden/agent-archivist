// SPDX-License-Identifier: Apache-2.0

//! Offline replay of the authority-rotation chain corpus
//! (`schemas/v1/examples/control/authority-rotation-chain.json`).
//!
//! The corpus is the language-neutral half of the authority-rotation
//! contract (control-trust story item 7): byte-pinned links, control
//! records signed around a mid-window rotation, and the acceptance
//! decision for every (signer, `signed_at`) pair. These tests are the
//! Rust implementation's proof that it replays that bundle with no
//! server and no corpus-private material — the same walk, signature
//! construction, and 24-hour window any other implementation applies
//! to the same bytes.
//!
//! The replay extends to the two surfaces built on that walk: the
//! active-anchor walk lands on the corpus's newest half (and a pinned
//! root with no links served anchors itself), and the resolution seam
//! replays every corpus record decision identically to the direct
//! verifier's. Adversarial bundles the honest corpus could never carry
//! — a tampered mid-chain link, a looping succession signed by the
//! newest half the corpus's generation note documents how to
//! regenerate — fail closed through both the active walk and the seam.

use std::collections::HashMap;
use std::fmt::Write as _;

use archivist_auth::authority::{
    AuthorityChainError, AuthorityRotationLink, PinnedAuthorityRoot, ResolvedAuthority,
    resolve_active_authority, resolve_authority, verify_control_record,
    verify_control_record_resolved, verify_signing_authority,
};
use archivist_auth::ed25519;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    Ed25519PublicKey, Ed25519Signature, KeyId, TenantId, Timestamp,
};

const CORPUS_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/v1/examples/control/authority-rotation-chain.json"
);

/// Read and parse the committed corpus.
fn corpus() -> Object {
    let bytes = std::fs::read(CORPUS_PATH)
        .unwrap_or_else(|e| panic!("the corpus must be readable at {CORPUS_PATH}: {e}"));
    match json::parse(&bytes).expect("the corpus is well-formed JSON") {
        Value::Object(object) => object,
        _ => panic!("the corpus root is an object"),
    }
}

/// One string member, or a failure naming the member.
fn text<'a>(object: &'a Object, member: &str) -> &'a str {
    match object.get(member) {
        Some(Value::Text(text)) => text.as_str(),
        other => panic!("the corpus member {member} must be a string, got {other:?}"),
    }
}

/// One object-valued member, or a failure naming the member.
fn object<'a>(object: &'a Object, member: &str) -> &'a Object {
    match object.get(member) {
        Some(Value::Object(inner)) => inner,
        other => panic!("the corpus member {member} must be an object, got {other:?}"),
    }
}

/// One array-valued member, or a failure naming the member.
fn array<'a>(object: &'a Object, member: &str) -> Vec<&'a Value> {
    match object.get(member) {
        Some(Value::Array(items)) => items.iter().collect(),
        other => panic!("the corpus member {member} must be an array, got {other:?}"),
    }
}

/// The pinned root, derived from the corpus's own anchor: the public
/// half and its pinned-derivation key ID, bound to the corpus tenant.
fn pinned_root(corpus: &Object) -> PinnedAuthorityRoot {
    let pinned = object(corpus, "pinned");
    let tenant_id = TenantId::parse(text(pinned, "tenant_id")).expect("tenant grammar");
    let public =
        Ed25519PublicKey::parse(text(pinned, "root_public_key")).expect("root half grammar");
    assert_eq!(
        KeyId::parse(text(pinned, "root_key_id")).expect("root ID grammar"),
        KeyId::from_public_key(&public),
        "the pinned root's ID is the pinned derivation of its half"
    );
    PinnedAuthorityRoot::new(tenant_id, public)
}

/// The chain store the corpus's links define, after proving each link
/// byte for byte: canonical bytes hash to the pinned digest, the record
/// parses under the closed contract, its signature verifies against the
/// retiring half it carries, and it sits at that half's own address.
fn corpus_chain_store(corpus: &Object) -> HashMap<KeyId, Vec<u8>> {
    let tenant = text(object(corpus, "pinned"), "tenant_id");
    let mut store: HashMap<KeyId, Vec<u8>> = HashMap::new();
    for link in array(corpus, "links") {
        let Value::Object(link_object) = link else {
            panic!("each link is an object");
        };
        let record = object(link_object, "record");
        let canonical = Value::Object(record.clone()).canonical_bytes();
        assert_eq!(
            hex(&sha256::digest(&canonical)),
            text(link_object, "canonical_bytes_sha256"),
            "the canonical bytes must hash to the pinned digest"
        );
        let parsed = AuthorityRotationLink::parse(&canonical)
            .expect("a corpus link parses under the record contract");
        assert!(
            parsed.verify_predecessor_signature(),
            "the retiring half's own signature must verify"
        );
        // Predecessor addressing: the stored address's final segment is
        // the retiring half's own ID, so a verifier holding the half
        // fetches this link at that half's address.
        assert_eq!(
            text(link_object, "address"),
            format!(
                "tenants/{tenant}/v1/control/authority-rotations/{}.json",
                parsed.previous_key_id().to_hex()
            ),
            "links sit at the retiring key's address"
        );
        store.insert(*parsed.previous_key_id(), canonical);
    }
    store
}

/// The corpus chain's last link, as an object — the link that
/// establishes the newest half the corpus names.
fn last_corpus_link(corpus: &Object) -> &Object {
    match array(corpus, "links").last() {
        Some(Value::Object(link)) => link,
        other => panic!("the corpus chain ends with an object link, got {other:?}"),
    }
}

/// The corpus record sample signed by `signer`, as an object.
fn corpus_record_signed_by<'a>(corpus: &'a Object, signer: &KeyId) -> &'a Object {
    for sample in array(corpus, "records") {
        let Value::Object(sample_object) = sample else {
            panic!("each sample is an object");
        };
        let record = object(sample_object, "record");
        if text(record, "authority_key_id") == signer.to_hex() {
            return record;
        }
    }
    panic!("the corpus carries a record signed by {signer}");
}

/// The tenant-pinned resolver [`verify_control_record`] itself closes
/// over, over `store` — named so the seam tests compose exactly what
/// production composes: the chain has no force outside the root's
/// tenant, and the walk plus acceptance rule decide the rest.
fn pinned_resolver<'a>(
    root: &'a PinnedAuthorityRoot,
    store: &'a HashMap<KeyId, Vec<u8>>,
) -> impl Fn(&TenantId, &KeyId, &Timestamp) -> Result<ResolvedAuthority, AuthorityChainError> + 'a {
    move |record_tenant, signer, at| {
        if record_tenant != root.tenant_id() {
            return Err(AuthorityChainError::RecordDisagreement);
        }
        verify_signing_authority(root, signer, at, |key| store.get(key).cloned())
    }
}

/// The signed rotation link retiring the half `predecessor_seed`
/// regenerates and establishing `successor_public` at `signed_at` — the
/// corpus's own link construction, under the control-record-v1
/// signature rule the corpus's generation note pins.
fn signed_rotation_link(
    predecessor_seed: &[u8; 32],
    successor_public: &Ed25519PublicKey,
    signed_at: &str,
    tenant: &TenantId,
) -> Vec<u8> {
    let previous_public =
        Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(predecessor_seed));
    let previous_key_id = KeyId::from_public_key(&previous_public);
    let mut members = Object::new();
    members.set("schema", Value::Text("archivist.control/v1".to_owned()));
    members.set("record_type", Value::Text("authority-rotation".to_owned()));
    members.set("record_kind", Value::Text("immutable".to_owned()));
    members.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    members.set("previous_public_key", Value::Text(previous_public.to_hex()));
    members.set("previous_key_id", Value::Text(previous_key_id.to_hex()));
    members.set("key_algorithm", Value::Text("ed25519".to_owned()));
    members.set("public_key", Value::Text(successor_public.to_hex()));
    members.set(
        "key_id",
        Value::Text(KeyId::from_public_key(successor_public).to_hex()),
    );
    members.set("signed_at", Value::Text(signed_at.to_owned()));
    members.set("authority_key_id", Value::Text(previous_key_id.to_hex()));
    let signature = ed25519::sign(
        predecessor_seed,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    Value::Object(members).canonical_bytes()
}

/// A receipt-key control record signed by the half `signer_seed`
/// regenerates at `signed_at`, under the control-record-v1 construction
/// — modeled on the corpus's own receipt-key samples, down to the
/// payload half the generation note documents for them.
fn signed_receipt_key_record(
    signer_seed: &[u8; 32],
    signed_at: &str,
    tenant: &TenantId,
) -> Vec<u8> {
    let signer_public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(signer_seed));
    let payload_public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&[0x5c; 32]));
    let mut members = Object::new();
    members.set("schema", Value::Text("archivist.control/v1".to_owned()));
    members.set("record_type", Value::Text("receipt-key".to_owned()));
    members.set("record_kind", Value::Text("immutable".to_owned()));
    members.set("tenant_id", Value::Text(tenant.as_str().to_owned()));
    members.set("key_algorithm", Value::Text("ed25519".to_owned()));
    members.set(
        "key_id",
        Value::Text(KeyId::from_public_key(&payload_public).to_hex()),
    );
    members.set("signed_at", Value::Text(signed_at.to_owned()));
    members.set(
        "authority_key_id",
        Value::Text(KeyId::from_public_key(&signer_public).to_hex()),
    );
    let signature = ed25519::sign(
        signer_seed,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    Value::Object(members).canonical_bytes()
}

#[test]
fn the_corpus_chain_walks_from_the_pinned_root_to_its_end() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let store = corpus_chain_store(&corpus);

    // The walk from the pinned root reaches the chain's end through
    // both links; the final half is current (established, unretired).
    let mut current = *root.key_id();
    let mut hops = 0;
    while let Some(bytes) = store.get(&current) {
        let link = AuthorityRotationLink::parse(bytes).expect("stored links stay valid");
        current = *link.key_id();
        hops += 1;
        assert!(hops < 16, "the walk must terminate");
    }
    assert_eq!(hops, 2, "the corpus chain is two links long");
    let resolved = resolve_authority(&root, &current, |key| store.get(key).cloned())
        .expect("the chain's end resolves from the pinned root");
    assert!(
        resolved.established_at().is_some(),
        "the last half was established by a link"
    );
    assert!(resolved.retired_at().is_none(), "the last half is current");
}

#[test]
fn every_corpus_acceptance_decision_replays_to_the_pinned_verdict() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let store = corpus_chain_store(&corpus);

    for case in array(&corpus, "acceptance") {
        let Value::Object(case_object) = case else {
            panic!("each acceptance case is an object");
        };
        let signer = KeyId::parse(text(case_object, "signer_key_id")).expect("signer grammar");
        let at = Timestamp::parse(text(case_object, "signed_at")).expect("instant grammar");
        let decision = verify_signing_authority(&root, &signer, &at, |key| store.get(key).cloned());
        let expected = text(case_object, "expected");
        let expected_error = expected_error(expected);
        match (&decision, expected_error) {
            (Ok(_), None) => {}
            (Err(err), Some(expected)) => {
                assert_eq!(err, &expected, "{signer} at {at}");
            }
            (outcome, expected) => {
                panic!("acceptance case {signer} at {at}: expected {expected:?}, got {outcome:?}");
            }
        }
    }
}

/// The verdict token a corpus case pins, as the error class that a
/// rejection must equal — `None` for acceptance.
fn expected_error(expected: &str) -> Option<AuthorityChainError> {
    match expected {
        "accepted" => None,
        "retired" => Some(AuthorityChainError::Retired),
        "not_established" => Some(AuthorityChainError::NotEstablished),
        "unreachable" => Some(AuthorityChainError::Unreachable),
        other => panic!("unknown expected verdict {other}"),
    }
}

#[test]
fn every_corpus_control_record_replays_end_to_end() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let store = corpus_chain_store(&corpus);

    for sample in array(&corpus, "records") {
        let Value::Object(sample_object) = sample else {
            panic!("each sample is an object");
        };
        let record = object(sample_object, "record");
        let expected = text(sample_object, "expected");
        let outcome = verify_control_record(
            &root,
            &Value::Object(record.clone()).canonical_bytes(),
            |key| store.get(key).cloned(),
        );
        let expected_error = expected_error(expected);
        match (&outcome, expected_error) {
            // On acceptance the resolution is the record's own signer.
            (Ok(resolved), None) => {
                let signer =
                    KeyId::parse(text(record, "authority_key_id")).expect("signer grammar");
                assert_eq!(resolved.key_id(), &signer);
            }
            (Err(err), Some(expected)) => {
                assert_eq!(err, &expected, "record sample rejection class");
            }
            (outcome, expected) => {
                panic!("record sample expected {expected:?}, got {outcome:?}");
            }
        }
    }
}

#[test]
fn the_active_walk_anchors_the_corpus_at_its_newest_half() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let store = corpus_chain_store(&corpus);

    // The corpus's newest half, as the corpus itself states it: the key
    // its last link establishes, at that link's own instant.
    let last_record = object(last_corpus_link(&corpus), "record");
    let tip_id = KeyId::parse(text(last_record, "key_id")).expect("newest half grammar");
    let tip_public =
        Ed25519PublicKey::parse(text(last_record, "public_key")).expect("newest half grammar");
    let established = text(last_record, "signed_at");

    let anchor = resolve_active_authority(&root, |key| store.get(key).cloned())
        .expect("the corpus chain's tip resolves as the active anchor");
    assert_eq!(
        *anchor.key_id(),
        tip_id,
        "the walk lands on the corpus's newest half"
    );
    assert_eq!(*anchor.public_key(), tip_public);
    assert_eq!(
        anchor.established_at().map(Timestamp::as_str),
        Some(established),
        "the tip's establishment is the last link's own signed_at"
    );
    assert!(
        anchor.retired_at().is_none(),
        "the active anchor is retired by nothing — that absence is what active means"
    );

    // The destination walk to the newest half resolves the same anchor
    // the active walk lands on.
    let resolved = resolve_authority(&root, &tip_id, |key| store.get(key).cloned())
        .expect("the corpus's newest half resolves from the pinned root");
    assert_eq!(resolved, anchor);

    // The anchor's granular acceptance agrees with every corpus
    // acceptance case that names the newest half.
    let mut pinned_cases = 0;
    for case in array(&corpus, "acceptance") {
        let Value::Object(case_object) = case else {
            panic!("each acceptance case is an object");
        };
        if text(case_object, "signer_key_id") != tip_id.to_hex() {
            continue;
        }
        pinned_cases += 1;
        let at = Timestamp::parse(text(case_object, "signed_at")).expect("instant grammar");
        let decision = anchor.verify_signing_at(&at);
        match (decision, expected_error(text(case_object, "expected"))) {
            (Ok(()), None) => {}
            (Err(err), Some(expected)) => assert_eq!(err, expected, "{tip_id} at {at}"),
            (decision, expected) => {
                panic!(
                    "newest-half acceptance case at {at}: expected {expected:?}, got {decision:?}"
                );
            }
        }
    }
    assert!(
        pinned_cases > 0,
        "the corpus pins at least one acceptance case for its newest half"
    );
}

#[test]
fn a_pinned_root_with_no_links_served_is_the_active_anchor() {
    let corpus = corpus();
    let root = pinned_root(&corpus);

    // No link served anywhere: the walk adopts nothing, and the pinned
    // root is itself the active anchor — pinned, never established,
    // retired by nothing.
    let anchor = resolve_active_authority(&root, |_: &KeyId| None)
        .expect("a root no link retires anchors itself");
    assert_eq!(*anchor.key_id(), *root.key_id());
    assert_eq!(*anchor.public_key(), *root.public_key());
    assert!(
        anchor.established_at().is_none(),
        "the root was pinned, never established by a link"
    );
    assert!(anchor.retired_at().is_none(), "and retired by nothing");

    // It signs at an instant the corpus pins as accepted for the root:
    // before any link, the two resolutions are the same half.
    let mut root_accepts_at = None;
    for case in array(&corpus, "acceptance") {
        let Value::Object(case_object) = case else {
            panic!("each acceptance case is an object");
        };
        if text(case_object, "signer_key_id") == root.key_id().to_hex()
            && text(case_object, "expected") == "accepted"
        {
            root_accepts_at =
                Some(Timestamp::parse(text(case_object, "signed_at")).expect("instant grammar"));
            break;
        }
    }
    let at = root_accepts_at.expect("the corpus accepts at least one root-signed instant");
    assert!(
        anchor.verify_signing_at(&at).is_ok(),
        "the root-anchor signs at {at}"
    );
}

#[test]
fn the_resolution_seam_replays_every_corpus_record_decision_identically() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let store = corpus_chain_store(&corpus);

    for sample in array(&corpus, "records") {
        let Value::Object(sample_object) = sample else {
            panic!("each sample is an object");
        };
        let record = object(sample_object, "record");
        let bytes = Value::Object(record.clone()).canonical_bytes();
        let context = format!(
            "record signed by {} at {}",
            text(record, "authority_key_id"),
            text(record, "signed_at")
        );

        // The direct verifier, and the same bytes through the seam with
        // the resolver verify_control_record itself installs: the two
        // decisions must be identical, acceptance or rejection.
        let direct = verify_control_record(&root, &bytes, |key| store.get(key).cloned());
        let through_seam = verify_control_record_resolved(&bytes, pinned_resolver(&root, &store));
        assert_eq!(
            direct, through_seam,
            "{context}: the seam replays the direct decision"
        );

        // And the seam's decision is still the corpus's pinned verdict.
        let expected_error = expected_error(text(sample_object, "expected"));
        match (&through_seam, expected_error) {
            // On acceptance the resolution is the record's own signer.
            (Ok(resolved), None) => {
                let signer =
                    KeyId::parse(text(record, "authority_key_id")).expect("signer grammar");
                assert_eq!(resolved.key_id(), &signer, "{context}");
            }
            (Err(err), Some(expected)) => {
                assert_eq!(err, &expected, "{context}: rejection class");
            }
            (outcome, expected) => {
                panic!("{context}: expected {expected:?}, got {outcome:?}");
            }
        }
    }
}

#[test]
fn an_adversarial_broken_chain_fails_closed_through_both_paths() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let honest = corpus_chain_store(&corpus);
    let mut broken = corpus_chain_store(&corpus);

    // The chain's mid half: the key the first link establishes.
    let Value::Object(first_link) = array(&corpus, "links")[0] else {
        panic!("each link is an object");
    };
    let mid_id =
        KeyId::parse(text(object(first_link, "record"), "key_id")).expect("mid half grammar");

    // Break the link at the mid half's address: the corpus's own
    // last-link bytes with one member altered — well-formed, honestly
    // addressed, and no longer what the predecessor signed.
    let last_record = object(last_corpus_link(&corpus), "record");
    let Value::Object(mut tampered) =
        json::parse(&Value::Object(last_record.clone()).canonical_bytes())
            .expect("a corpus link is well-formed JSON")
    else {
        panic!("a corpus link is an object");
    };
    tampered.set("signed_at", Value::Text("2026-09-12T00:00:01Z".to_owned()));
    broken.insert(mid_id, Value::Object(tampered).canonical_bytes());

    // Active walk: adopts the first link, refuses the tampered one —
    // anchoring no chain, not even at the last good half.
    assert_eq!(
        resolve_active_authority(&root, |key| broken.get(key).cloned()).unwrap_err(),
        AuthorityChainError::Signature,
        "a mid-chain link the predecessor never signed breaks the whole walk",
    );

    // The seam path over the same broken store: the mid half's own
    // honestly signed corpus record cannot be resolved — its walk ends
    // at the mid half and probes the link at its own address, the
    // tampered bytes.
    let mid_record = corpus_record_signed_by(&corpus, &mid_id);
    let mid_bytes = Value::Object(mid_record.clone()).canonical_bytes();
    let through_seam = verify_control_record_resolved(&mid_bytes, pinned_resolver(&root, &broken));
    assert_eq!(
        through_seam.unwrap_err(),
        AuthorityChainError::Signature,
        "the seam refuses the record its resolution cannot reach",
    );
    let direct = verify_control_record(&root, &mid_bytes, |key| broken.get(key).cloned());
    assert_eq!(direct.unwrap_err(), AuthorityChainError::Signature);

    // Against the honest chain the same record is the corpus's pinned
    // acceptance: the tamper is what fails, nothing else.
    assert!(
        verify_control_record(&root, &mid_bytes, |key| honest.get(key).cloned()).is_ok(),
        "the mid half's record verifies against the honest chain"
    );
}

#[test]
fn an_adversarial_looping_chain_fails_closed_through_both_paths() {
    let corpus = corpus();
    let root = pinned_root(&corpus);
    let honest = corpus_chain_store(&corpus);
    let mut looping = corpus_chain_store(&corpus);

    // The corpus's generation note publishes its synthetic seeds — one
    // byte repeated 32 times, the newest half's being 0x03 — precisely
    // so a verifier can regenerate a half. Regenerated, it must match
    // the corpus's own newest half: that is what lets this bundle loop
    // the real corpus chain with a link the honest corpus could never
    // carry.
    let tip_seed = [0x03u8; 32];
    let tip_public = Ed25519PublicKey::from_raw(ed25519::public_key_from_seed(&tip_seed));
    let last_record = object(last_corpus_link(&corpus), "record");
    let tip_id = KeyId::parse(text(last_record, "key_id")).expect("newest half grammar");
    assert_eq!(
        tip_public,
        Ed25519PublicKey::parse(text(last_record, "public_key")).expect("newest half grammar"),
        "the regenerated half is the corpus's own newest half",
    );

    // The loop: at the newest half's own address, a link it signed that
    // retires it and re-establishes the pinned root — individually
    // admitted, jointly a succession that revisits a held key.
    let loop_bytes = signed_rotation_link(
        &tip_seed,
        root.public_key(),
        text(last_record, "signed_at"),
        root.tenant_id(),
    );
    looping.insert(tip_id, loop_bytes);

    // Active walk: adopts the honest prefix, refuses the looping link.
    assert_eq!(
        resolve_active_authority(&root, |key| looping.get(key).cloned()).unwrap_err(),
        AuthorityChainError::ChainRule,
        "a succession that revisits a held key is a loop, not a history",
    );

    // Seam path: a control record the newest half honestly signed at
    // its own establishment instant. Resolution walks the honest
    // prefix, reaches the signer, and probes the link at its own
    // address — the same loop, the same refusal.
    let tip_record =
        signed_receipt_key_record(&tip_seed, text(last_record, "signed_at"), root.tenant_id());
    let through_seam =
        verify_control_record_resolved(&tip_record, pinned_resolver(&root, &looping));
    assert_eq!(
        through_seam.unwrap_err(),
        AuthorityChainError::ChainRule,
        "the seam refuses the record whose resolution walks into the loop",
    );
    let direct = verify_control_record(&root, &tip_record, |key| looping.get(key).cloned());
    assert_eq!(direct.unwrap_err(), AuthorityChainError::ChainRule);

    // Against the honest chain the same record verifies: the loop is
    // what fails, not the newest half's signature.
    assert!(
        verify_control_record(&root, &tip_record, |key| honest.get(key).cloned()).is_ok(),
        "the newest half's record verifies against the honest chain",
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
