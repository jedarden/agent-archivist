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

use std::collections::HashMap;
use std::fmt::Write as _;

use archivist_auth::authority::{
    AuthorityChainError, AuthorityRotationLink, PinnedAuthorityRoot, resolve_authority,
    verify_control_record, verify_signing_authority,
};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{Ed25519PublicKey, KeyId, TenantId, Timestamp};

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

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}
