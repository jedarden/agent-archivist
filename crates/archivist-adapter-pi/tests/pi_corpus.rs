// SPDX-License-Identifier: Apache-2.0

//! Positive conformance against the durable Pi JSONL corpus.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use archivist_adapter_pi::{ConfiguredRoot, PiAdapter, PiFormat};
use archivist_adapter_sdk::status::AccountLabel;

const CORPUS_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/contributed/pi-jsonl"
);

fn account() -> AccountLabel {
    AccountLabel::parse("pi-corpus-fixture").expect("fixture account is valid")
}

#[test]
fn discovers_and_captures_both_jsonl_header_versions_read_only() {
    let root = PathBuf::from(CORPUS_ROOT);
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account(), root.clone())])
        .expect("corpus root configures");
    let inventory = adapter.inventory(&account());

    assert_eq!(inventory.report.supported, 2);
    assert_eq!(inventory.report.unsupported, 2);

    let mut versions = BTreeSet::new();
    for source in inventory.supported() {
        let version = match source.format() {
            PiFormat::Jsonl { version } => version,
            format => panic!("corpus source is not JSONL: {format:?}"),
        };
        versions.insert(version);

        let before = fs::read(source.path()).expect("read corpus source");
        let mut capture = adapter.open(source).expect("open admitted source");
        let chunk = capture
            .next_chunk()
            .expect("capture pass succeeds")
            .expect("complete JSONL records are captured");
        assert_eq!(chunk.bytes, before);
        assert_eq!(chunk.fingerprint, *source.fingerprint());
        assert_eq!(capture.next_chunk().expect("repeat pass succeeds"), None);
        assert_eq!(
            fs::read(source.path()).expect("re-read corpus source"),
            before
        );
    }

    assert_eq!(versions, BTreeSet::from([1, 2]));
}
