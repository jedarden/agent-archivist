// SPDX-License-Identifier: Apache-2.0

//! Corpus replay: every committed conformance scenario's attempt record
//! parses, frames the pinned `ingest-attempt-v1` preimage bytes exactly,
//! and replays the committed decision against trust fixtures minted from
//! the corpus's documented deterministic seeds.
//!
//! The corpus is the wire-format contract
//! (`schemas/v1/examples/conformance/`): the manifest pins each
//! scenario's signed preimage (`signing.attempt_input_hex`) and server
//! clock (`server_time`), `keys.json` carries the public halves and the
//! assumed linkage, and the scenario directories carry the attempt
//! records, envelopes, and request bodies. Private halves are never
//! committed (SEC-010, synthetic data): the authority fixture here
//! re-derives its seed from the documented rule
//! `SHA-256("archivist.conformance/v1 <key-name>")` and asserts the
//! derivation against the committed key ID before using it.
//!
//! What this test does not replay: byte-level payload digest
//! recomputation (the canonical and transport payload representations
//! are the payload pipeline's contract, and the replay carries the
//! committed covered values) and the envelope-schema stages the
//! corpus's remaining invalid scenarios exercise — their causes live
//! outside this decision, and the boundary is asserted as such: the
//! decision must not own them.

use archivist_auth::authority::PinnedAuthorityRoot;
use archivist_auth::delegation::{
    DelegationRecord, DelegationScopes, DelegationState, LinkedClientScopes, publish_delegation,
};
use archivist_auth::ed25519;
use archivist_auth::link::ScopeOperation;
use archivist_auth::request_verification::{
    AttemptAuthorization, AuthorizedAttempt, LinkedUploader, PresentedRequest, RequestRejection,
    verify_request,
};
use archivist_auth::revocation::{ClientTrustView, LinkedClientPointer};
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    ClientId, Ed25519PublicKey, Ed25519Signature, EnvelopeDigest, HarnessId, KeyId,
    PayloadCanonicalDigest, PayloadTransportDigest, RequestContentDigest, TenantId, Timestamp,
};

/// The committed corpus root, relative to this crate.
const CONFORMANCE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../schemas/v1/examples/conformance"
);

/// The deterministic seed rule the corpus documents for its synthetic
/// keys (`tools/conformancegen.py`, `KEY_SEED_PREFIX`): the SHA-256 of
/// the prefix, a space, and the key name.
fn corpus_seed(key_name: &str) -> [u8; 32] {
    sha256::digest(format!("archivist.conformance/v1 {key_name}").as_bytes())
}

fn read_corpus(name: &str) -> Vec<u8> {
    std::fs::read(format!("{CONFORMANCE_DIR}/{name}")).expect("the committed corpus file exists")
}

fn object_of(name: &str) -> Object {
    match json::parse(&read_corpus(name)).expect("the corpus file is valid JSON") {
        Value::Object(object) => object,
        _ => panic!("{name} is not a JSON object"),
    }
}

fn text_member<'a>(object: &'a Object, name: &str) -> &'a str {
    match object.get(name) {
        Some(Value::Text(value)) => value,
        _ => panic!("the corpus member {name} is missing or not text"),
    }
}

fn sub_object<'a>(object: &'a Object, name: &str) -> &'a Object {
    match object.get(name) {
        Some(Value::Object(value)) => value,
        _ => panic!("the corpus member {name} is missing or not an object"),
    }
}

/// One committed key's public entry.
struct KeyEntry {
    name: String,
    key_id: String,
    public_key: String,
    role: String,
    tenant_id: String,
}

/// One assumed-linkage entry: the client a key is linked to, the tenant
/// of that linkage, and the instant each linked epoch begins.
struct LinkEntry {
    key: String,
    client_id: String,
    linked_tenant: String,
    epochs: Vec<(u64, String)>,
}

/// The corpus key table, parsed once.
struct Corpus {
    keys: Vec<KeyEntry>,
    links: Vec<LinkEntry>,
}

impl Corpus {
    fn load() -> Self {
        let table = object_of("keys.json");
        let mut keys = Vec::new();
        let mut links = Vec::new();
        if let Some(Value::Array(items)) = table.get("keys") {
            for item in items {
                let Value::Object(record) = item else {
                    continue;
                };
                keys.push(KeyEntry {
                    name: text_member(record, "name").to_owned(),
                    key_id: text_member(record, "key_id").to_owned(),
                    public_key: text_member(record, "public_key").to_owned(),
                    role: match record.get("role") {
                        Some(Value::Text(role)) => role.clone(),
                        _ => String::new(),
                    },
                    tenant_id: match record.get("tenant_id") {
                        Some(Value::Text(tenant)) => tenant.clone(),
                        _ => String::new(),
                    },
                });
            }
        }
        if let Some(Value::Array(items)) = table.get("assumed_linkage") {
            for item in items {
                let Value::Object(record) = item else {
                    continue;
                };
                let mut epochs = Vec::new();
                for (epoch_text, from_text) in sub_object(record, "epochs").iter() {
                    let Value::Text(from) = from_text else {
                        continue;
                    };
                    if let Ok(epoch) = epoch_text.parse::<u64>() {
                        epochs.push((epoch, from.clone()));
                    }
                }
                links.push(LinkEntry {
                    key: text_member(record, "key").to_owned(),
                    client_id: text_member(record, "client_id").to_owned(),
                    linked_tenant: text_member(record, "linked_tenant").to_owned(),
                    epochs,
                });
            }
        }
        assert!(!keys.is_empty(), "keys.json carries the key array");
        assert!(!links.is_empty(), "keys.json carries the assumed linkage");
        Self { keys, links }
    }

    fn key(&self, key_name: &str) -> &KeyEntry {
        self.keys
            .iter()
            .find(|entry| entry.name == key_name)
            .unwrap_or_else(|| panic!("keys.json carries no key named {key_name}"))
    }

    /// The committed public half of one named key.
    fn half(&self, key_name: &str) -> Ed25519PublicKey {
        let hex = &self.key(key_name).public_key;
        let raw: [u8; 32] = sha256::decode_hex(hex)
            .expect("the committed half is hex")
            .try_into()
            .expect("the committed half is 32 bytes");
        Ed25519PublicKey::from_raw(raw)
    }

    /// The linkage of one named key.
    fn linkage(&self, key_name: &str) -> &LinkEntry {
        self.links
            .iter()
            .find(|entry| entry.key == key_name)
            .unwrap_or_else(|| panic!("keys.json carries no assumed linkage for {key_name}"))
    }

    /// The instant one linked epoch begins, from the linkage's
    /// `from <instant>` text.
    fn epoch_start(&self, key_name: &str, epoch: u64) -> &str {
        self.linkage(key_name)
            .epochs
            .iter()
            .find(|(linked, _)| *linked == epoch)
            .map_or_else(
                || panic!("the linkage carries no epoch {epoch} for {key_name}"),
                |(_, from)| from.as_str(),
            )
            .strip_prefix("from ")
            .expect("the linkage epoch names its start instant")
    }

    /// The tenant authority root of one tenant: the committed
    /// tenant-authority-root key, with the documented seed rule
    /// asserted against its committed key ID.
    fn authority(&self, tenant_text: &str) -> (Ed25519PublicKey, [u8; 32]) {
        let entry = self
            .keys
            .iter()
            .find(|candidate| {
                candidate.role == "tenant-authority-root" && candidate.tenant_id == tenant_text
            })
            .unwrap_or_else(|| panic!("keys.json carries no authority root for {tenant_text}"));
        let seed = corpus_seed(&entry.name);
        let raw = ed25519::public_key_from_seed(&seed);
        assert_eq!(
            sha256::encode_hex(&sha256::digest(&raw)),
            entry.key_id,
            "the documented seed rule must reproduce the committed authority key ID"
        );
        (Ed25519PublicKey::from_raw(raw), seed)
    }
}

/// The linked-client record the fixture linkage names: the corpus's
/// client at the attempt's epoch with the corpus's half, signed by the
/// corpus authority's derived seed — the record shape
/// `schemas/v1/control-linked-client.json` pins, granting the envelope's
/// harness and the one v1 operation.
fn fixture_link_record(
    corpus: &Corpus,
    key_name: &str,
    epoch: u64,
    signed_at: &str,
    harness: &HarnessId,
) -> Vec<u8> {
    let linkage = corpus.linkage(key_name);
    let tenant = linkage.linked_tenant.as_str();
    let client = linkage.client_id.as_str();
    let half = corpus.half(key_name);
    let (authority_half, authority_seed) = corpus.authority(&linkage.linked_tenant);
    let mut members = Object::new();
    members.set("schema", Value::Text("archivist.control/v1".to_owned()));
    members.set("record_type", Value::Text("linked-client".to_owned()));
    members.set("record_kind", Value::Text("current-pointer".to_owned()));
    members.set("tenant_id", Value::Text(tenant.to_owned()));
    members.set("client_id", Value::Text(client.to_owned()));
    members.set(
        "key_id",
        Value::Text(KeyId::from_public_key(&half).to_hex()),
    );
    members.set("key_algorithm", Value::Text("ed25519".to_owned()));
    members.set("public_key", Value::Text(half.to_hex()));
    let mut scopes = Object::new();
    scopes.set(
        "harnesses",
        Value::Array(vec![Value::Text(harness.as_str().to_owned())]),
    );
    scopes.set(
        "operations",
        Value::Array(vec![Value::Text("ingest".to_owned())]),
    );
    members.set("scopes", Value::Object(scopes));
    members.set(
        "authorization_epoch",
        Value::Int(i64::try_from(epoch).expect("the corpus epoch is a u63")),
    );
    members.set("signed_at", Value::Text(signed_at.to_owned()));
    members.set(
        "authority_key_id",
        Value::Text(KeyId::from_public_key(&authority_half).to_hex()),
    );
    let signature = ed25519::sign(
        &authority_seed,
        &Value::Object(members.clone()).canonical_bytes(),
    );
    members.set(
        "authority_signature",
        Value::Text(Ed25519Signature::from_raw(*signature.as_bytes()).to_hex()),
    );
    Value::Object(members).canonical_bytes()
}

/// The uploader evidence one scenario's signing key presents: the
/// linkage's client and tenant at the attempt's epoch, the corpus half,
/// and a scope granting the envelope's harness and the ingest
/// operation. The attempt's own key ID must derive from the corpus
/// half — the corpus's linkage is the fixture's warrant.
fn evidence_for(
    corpus: &Corpus,
    key_name: &str,
    epoch: u64,
    signed_at: &str,
    harness: &HarnessId,
) -> LinkedUploader {
    let linkage = corpus.linkage(key_name);
    let half = corpus.half(key_name);
    let tenant = TenantId::parse(&linkage.linked_tenant).expect("the linkage tenant parses");
    let (authority_key, _) = corpus.authority(&linkage.linked_tenant);
    let root = PinnedAuthorityRoot::new(tenant.clone(), authority_key);
    let record = fixture_link_record(corpus, key_name, epoch, signed_at, harness);
    let addressed = ClientId::parse(&linkage.client_id).expect("the linkage client parses");
    let pointer = LinkedClientPointer::verify(&root, &record, |_| None, &addressed)
        .expect("the fixture linked-client record verifies");
    let scopes = LinkedClientScopes::new(vec![harness.clone()], vec![ScopeOperation::Ingest])
        .expect("the fixture scope builds");
    LinkedUploader::new(&root, ClientTrustView::new(pointer), half, scopes)
        .expect("the fixture evidence is consistent")
}

/// The active relay grant the relay scenario needs: the corpus
/// authority delegating the origin client to the relay client at the
/// pair key, granting the envelope's harness and the ingest operation.
fn relay_delegation(corpus: &Corpus, harness: &HarnessId) -> DelegationRecord {
    let relay_link = corpus.linkage("uploader-relay-1");
    let origin_link = corpus.linkage("uploader-origin-1");
    let tenant = TenantId::parse(&relay_link.linked_tenant).expect("the linkage tenant parses");
    let relay = ClientId::parse(&relay_link.client_id).expect("the relay client parses");
    let origin = ClientId::parse(&origin_link.client_id).expect("the origin client parses");
    let (authority_key, authority_seed) = corpus.authority(&relay_link.linked_tenant);
    let scopes = DelegationScopes::new(vec![harness.clone()], vec![ScopeOperation::Ingest])
        .expect("the delegation scope builds");
    let signed_at = Timestamp::parse(corpus.epoch_start("uploader-relay-1", 1))
        .expect("the linkage start instant parses");
    let publication = publish_delegation(
        &authority_seed,
        &tenant,
        &relay,
        &origin,
        DelegationState::Active,
        &scopes,
        1,
        None,
        &signed_at,
    )
    .expect("the fixture delegation publishes");
    DelegationRecord::verify(
        &PinnedAuthorityRoot::new(tenant, authority_key),
        publication.envelope(),
        |_| None,
        &relay,
        &origin,
    )
    .expect("the fixture delegation verifies")
}

#[test]
fn corpus_replays_against_the_decision() {
    let corpus = Corpus::load();
    let manifest = object_of("manifest.json");
    let Some(Value::Array(scenarios)) = manifest.get("scenarios") else {
        panic!("the manifest carries the scenario array");
    };
    let mut seen: Vec<String> = Vec::new();
    for scenario in scenarios {
        let Value::Object(scenario) = scenario else {
            panic!("each manifest scenario is an object");
        };
        let id = text_member(scenario, "id").to_owned();
        seen.push(id.clone());
        let signing = sub_object(scenario, "signing");
        let files = sub_object(scenario, "files");
        let key_name = text_member(signing, "signing_key");

        // The committed attempt record parses and frames exactly the
        // pinned preimage bytes.
        let Value::Object(attempt_object) =
            json::parse(&read_corpus(text_member(files, "attempt")))
                .expect("the attempt record is valid JSON")
        else {
            panic!("the attempt record is an object");
        };
        let authorization = AttemptAuthorization::parse(&Value::Object(attempt_object.clone()))
            .unwrap_or_else(|rejection| {
                panic!("{id}: the committed attempt record parses: {rejection}")
            });
        assert_eq!(
            sha256::encode_hex(&authorization.signing_input()),
            text_member(signing, "attempt_input_hex"),
            "{id}: the framed preimage matches the committed bytes"
        );

        // The envelope names the presented identities; the whole-request
        // digest is recomputed from the committed body bytes — the one
        // digest this decision consumes that the replay can recompute
        // without the payload pipeline's representations.
        let presented = presented_for(files, &attempt_object);

        let epoch = authorization.authorization_epoch();
        // The corpus attempt must present the linked half's own key ID:
        // the linkage is the fixture's warrant, and a valid scenario
        // whose record names some other key is a corpus defect.
        assert_eq!(
            KeyId::from_public_key(&corpus.half(key_name)),
            *authorization.uploader_key_id(),
            "{id}: the attempt presents the linked half's own key ID"
        );
        let evidence = evidence_for(
            &corpus,
            key_name,
            epoch,
            corpus.epoch_start(key_name, epoch),
            &presented.harness,
        );
        let now = Timestamp::parse(text_member(scenario, "server_time"))
            .expect("the server clock parses");
        let decision = if id == "valid-relay-upload" {
            let grant = relay_delegation(&corpus, &presented.harness);
            verify_request(
                &authorization,
                &presented,
                Some(&evidence),
                Some(&grant),
                &now,
            )
        } else {
            verify_request(&authorization, &presented, Some(&evidence), None, &now)
        };
        assert_outcome(
            &id,
            text_member(scenario, "kind"),
            &decision,
            &authorization,
            &presented,
        );
    }
    assert_required_scenarios(&seen);
}

/// What the pipeline presents for one scenario: the envelope's declared
/// identities and the covered digests, with the whole-request digest
/// recomputed from the committed body bytes — the one digest this
/// decision consumes that the replay can recompute without the payload
/// pipeline's representations.
fn presented_for(files: &Object, attempt_object: &Object) -> PresentedRequest {
    let envelope = object_of(text_member(files, "envelope"));
    let tenant =
        TenantId::parse(text_member(&envelope, "tenant_id")).expect("the envelope tenant parses");
    let uploader = ClientId::parse(text_member(&envelope, "uploader_client_id"))
        .expect("the envelope uploader parses");
    let origin = ClientId::parse(text_member(&envelope, "origin_client_id"))
        .expect("the envelope origin parses");
    let harness =
        HarnessId::parse(text_member(&envelope, "harness")).expect("the envelope harness parses");
    let body = read_corpus(text_member(files, "request_body"));
    let computed_request = RequestContentDigest::parse(&sha256::encode_hex(&sha256::digest(&body)))
        .expect("the computed digest parses");
    PresentedRequest {
        tenant_id: tenant,
        uploader_client_id: uploader,
        origin_client_id: origin,
        harness,
        request_content_digest: computed_request,
        envelope_digest: EnvelopeDigest::parse(text_member(attempt_object, "envelope_digest"))
            .expect("the covered envelope digest parses"),
        payload_canonical_digest: PayloadCanonicalDigest::parse(text_member(
            attempt_object,
            "payload_canonical_digest",
        ))
        .expect("the covered canonical digest parses"),
        payload_transport_digest: PayloadTransportDigest::parse(text_member(
            attempt_object,
            "payload_transport_digest",
        ))
        .expect("the covered transport digest parses"),
    }
}

/// The outcome one committed scenario pins, asserted against the
/// rendered decision: the valid scenarios authorize with the anchor the
/// data flow names, the scenarios this decision owns reject with their
/// class, and the rest must pass through — the boundary being that this
/// decision owns none of their causes.
fn assert_outcome(
    id: &str,
    kind: &str,
    decision: &Result<AuthorizedAttempt, RequestRejection>,
    authorization: &AttemptAuthorization,
    presented: &PresentedRequest,
) {
    match kind {
        "valid" => {
            let authorized = decision
                .as_ref()
                .unwrap_or_else(|rejection| panic!("{id}: expected acceptance, got {rejection}"));
            assert_eq!(
                authorized.uploader_client_id(),
                &presented.uploader_client_id,
                "{id}: the attempt presents its uploader"
            );
            assert_eq!(
                authorized.anchor_client_id(),
                &presented.origin_client_id,
                "{id}: the occurrence anchors at the origin"
            );
        }
        _ => match id {
            "invalid-stale-authorization" => assert_eq!(
                *decision,
                Err(RequestRejection::ExpiredAuthorization),
                "{id}: an attempt past the window plus skew is expired"
            ),
            "invalid-cross-tenant-forbidden" => assert_eq!(
                *decision,
                Err(RequestRejection::CrossTenant),
                "{id}: linkage does not cross tenants"
            ),
            "invalid-altered-payload-byte" | "invalid-altered-framing-boundary" => {
                assert_ne!(
                    presented.request_content_digest.as_raw(),
                    authorization.request_content_digest().as_raw(),
                    "{id}: the corpus altered the body the record covers"
                );
                assert_eq!(
                    *decision,
                    Err(RequestRejection::AlteredRequest),
                    "{id}: an altered request is refused before anything else"
                );
            }
            _ => {
                // The corpus's remaining invalid scenarios are
                // rejected by the envelope-schema and storage
                // stages, not by this decision: the boundary is
                // that the signature decision owns none of them.
                assert!(
                    decision.is_ok(),
                    "{id}: this decision must not own the rejection, got {decision:?}"
                );
            }
        },
    }
}

/// Every acceptance clause names its committed scenario: a corpus
/// change that drops one must fail here, not silently narrow what
/// this replay proves.
fn assert_required_scenarios(seen: &[String]) {
    for required in [
        "valid-relay-upload",
        "invalid-stale-authorization",
        "invalid-cross-tenant-forbidden",
        "invalid-altered-payload-byte",
        "invalid-altered-framing-boundary",
    ] {
        assert!(
            seen.iter().any(|seen_id| seen_id == required),
            "the corpus carries the {required} acceptance scenario"
        );
    }
}
