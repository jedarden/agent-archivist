// SPDX-License-Identifier: Apache-2.0

//! AC-11 pre-claim evidence for the Pi real-source adapter.
//!
//! The durable corpus owns positive v1/v2 evidence. This suite owns every
//! adapter-specific negative or fault vector from the adapter-capture gate:
//! record tails, generation rewrites, discovery, permissions, fingerprint
//! admission, content-free surfaces, and hostile source records.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use archivist_adapter_pi::{
    ConfiguredRoot, CoverageGap, MAX_RECORD_BYTES, PiAdapter, PiCapture, PiCaptureError, PiFormat,
};
use archivist_adapter_sdk::artifact::GenerationCause;
use archivist_adapter_sdk::status::{AccountLabel, ScanClassification};

fn account(name: &str) -> AccountLabel {
    AccountLabel::parse(name).expect("test account is valid")
}

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("archivist-pi-ac11-{label}-{nanos}"))
}

fn write(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture root");
    }
    fs::write(path, bytes).expect("write fixture");
}

fn append(path: &Path, bytes: &[u8]) {
    OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open append")
        .write_all(bytes)
        .expect("append fixture");
}

fn source(
    adapter: &PiAdapter,
    root: &Path,
    account: &AccountLabel,
) -> archivist_adapter_pi::PiSource {
    adapter
        .inventory(account)
        .supported()
        .find(|source| source.path() == root.join("session.jsonl"))
        .cloned()
        .expect("supported source")
}

fn rewrite_in_place(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .expect("open in-place rewrite");
    file.write_all(bytes).expect("rewrite source");
}

fn v1_header() -> &'static [u8] {
    b"{\"type\":\"session\"}\n"
}

fn message(label: &str) -> String {
    format!("{{\"type\":\"message\",\"value\":\"{label}\"}}\n")
}

#[test]
fn ac11_partial_record_faults_keep_cursor_and_capture_later_completion_whole() {
    let root = temp_root("partial");
    let path = root.join("session.jsonl");
    write(&path, v1_header());
    let account = account("partial");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let mut capture = adapter
        .open(&source(&adapter, &root, &account))
        .expect("open source");

    let first = capture.next_chunk().expect("initial pass").expect("header");
    let generation = first.generation.clone();
    append(&path, b"{\"type\":\"message\",\"value\":\"torn\"");
    assert_eq!(capture.next_chunk().expect("always-torn pass"), None);
    let cursor = match &capture {
        PiCapture::Jsonl(capture) => capture.cursor_position(),
        PiCapture::Immutable(_) => panic!("JSONL source opened as immutable"),
    };
    assert_eq!(cursor, first.bytes.len() as u64);
    assert_eq!(capture.next_chunk().expect("re-measure torn pass"), None);

    append(&path, b"}\n{\"type\":\"message\",\"value\":\"complete\"}\n");
    let second = capture
        .next_chunk()
        .expect("completion pass")
        .expect("completed records");
    assert_eq!(second.generation, generation);
    assert_eq!(
        second.bytes,
        b"{\"type\":\"message\",\"value\":\"torn\"}\n{\"type\":\"message\",\"value\":\"complete\"}\n"
    );
    assert_eq!(capture.next_chunk().expect("settled pass"), None);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn ac11_rewrite_generation_faults_name_each_required_cause() {
    let root = temp_root("rewrite");
    let path = root.join("session.jsonl");
    let header = v1_header();
    let first = message("a");
    let second = message("b");
    let third = message("c");
    let rewound = message("x");
    let restored = message("y");
    let replaced = message("z");
    write(
        &path,
        [header, first.as_bytes(), second.as_bytes()]
            .concat()
            .as_slice(),
    );
    let account = account("rewrite");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let mut capture = adapter
        .open(&source(&adapter, &root, &account))
        .expect("open source");
    capture.next_chunk().expect("initial pass");

    rewrite_in_place(&path, [header, first.as_bytes()].concat().as_slice());
    capture
        .next_chunk()
        .expect("truncation pass")
        .expect("truncated generation");
    assert_eq!(capture.generation().cause, GenerationCause::Truncation);

    append(&path, second.as_bytes());
    capture
        .next_chunk()
        .expect("restore second")
        .expect("second growth");
    append(&path, third.as_bytes());
    capture
        .next_chunk()
        .expect("append third")
        .expect("third growth");

    rewrite_in_place(
        &path,
        [header, first.as_bytes(), rewound.as_bytes()]
            .concat()
            .as_slice(),
    );
    capture
        .next_chunk()
        .expect("rewind pass")
        .expect("rewound generation");
    assert_eq!(capture.generation().cause, GenerationCause::Rewind);

    append(&path, restored.as_bytes());
    capture
        .next_chunk()
        .expect("append restored")
        .expect("restored growth");
    rewrite_in_place(
        &path,
        [
            header,
            first.as_bytes(),
            rewound.as_bytes(),
            replaced.as_bytes(),
        ]
        .concat()
        .as_slice(),
    );
    capture
        .next_chunk()
        .expect("tail mismatch pass")
        .expect("tail-mismatch generation");
    assert_eq!(capture.generation().cause, GenerationCause::TailMismatch);

    let q = message("q");
    rewrite_in_place(
        &path,
        [
            header,
            q.as_bytes(),
            rewound.as_bytes(),
            replaced.as_bytes(),
        ]
        .concat()
        .as_slice(),
    );
    capture
        .next_chunk()
        .expect("incompatible rewrite pass")
        .expect("incompatible generation");
    assert_eq!(
        capture.generation().cause,
        GenerationCause::IncompatibleRewrite
    );
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn ac11_immutable_rewrite_fault_is_digest_generation_not_overwrite() {
    let root = temp_root("immutable-rewrite");
    let path = root.join("session.json");
    write(&path, b"{\"type\":\"session\",\"id\":\"one\"}");
    let account = account("immutable");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let source = adapter
        .inventory(&account)
        .supported()
        .next()
        .cloned()
        .unwrap();
    assert_eq!(source.format(), PiFormat::Immutable { version: 1 });
    let mut capture = adapter.open(&source).expect("open immutable source");
    capture
        .next_chunk()
        .expect("initial object")
        .expect("object");
    rewrite_in_place(&path, b"{\"type\":\"session\",\"id\":\"two\"}");
    capture
        .next_chunk()
        .expect("digest rewrite")
        .expect("object");
    assert_ne!(capture.generation().cause, GenerationCause::Initial);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn ac11_discovery_fault_negatives_bound_sources_and_report_vanishing_files() {
    let root = temp_root("discovery");
    let outside = temp_root("outside");
    let session = root.join("session.jsonl");
    write(&session, v1_header());
    write(
        &root.join("future.jsonl"),
        b"{\"type\":\"session\",\"version\":99}\n",
    );
    write(&root.join("planted.txt"), b"not a Pi source");
    write(&outside.join("outside.jsonl"), v1_header());
    let account = account("discovery");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let inventory = adapter.inventory(&account);
    assert_eq!(inventory.report.classification, ScanClassification::Ok);
    assert_eq!(inventory.report.sources, 3);
    assert_eq!(inventory.report.supported, 1);
    assert_eq!(inventory.report.unsupported, 2);
    assert!(inventory.gaps.is_empty());
    assert!(
        !inventory
            .sources
            .iter()
            .any(|source| source.path().starts_with(&outside))
    );

    let admitted = inventory.supported().next().cloned().unwrap();
    fs::remove_file(&session).expect("vanish configured source");
    let mut capture = adapter.open(&admitted).expect("open vanished source");
    assert_eq!(
        capture
            .next_chunk()
            .expect_err("vanished source must classify"),
        PiCaptureError::RootAbsent
    );
    let missing = temp_root("missing-root");
    let absent = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &missing)])
        .unwrap()
        .inventory(&account);
    assert_eq!(absent.report.classification, ScanClassification::RootAbsent);
    assert_eq!(absent.gaps, [CoverageGap::RootAbsent]);
    fs::remove_dir_all(root).expect("remove fixture");
    fs::remove_dir_all(outside).expect("remove outside fixture");
}

#[cfg(unix)]
#[test]
fn ac11_permission_faults_retain_denial_and_do_not_fabricate_content() {
    use std::os::unix::fs::PermissionsExt;

    let root = temp_root("permissions");
    let readable = root.join("readable.jsonl");
    let denied = root.join("denied.jsonl");
    write(&readable, v1_header());
    write(&denied, v1_header());
    let probe = root.join("probe");
    write(&probe, b"probe");
    let account = account("permissions");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let baseline = adapter.inventory(&account);
    assert_eq!(baseline.report.classification, ScanClassification::Ok);
    assert_eq!(baseline.report.supported, 2);
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&probe).is_ok() {
        eprintln!("permission-faults: not applicable; test process bypasses mode bits");
        fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).unwrap();
        fs::remove_dir_all(root).unwrap();
        return;
    }

    fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o000)).unwrap();
    let inventory = adapter.inventory(&account);
    assert_eq!(
        inventory.report.classification,
        ScanClassification::PermissionDenied
    );
    assert!(inventory.report.sources >= 1);
    assert!(inventory.report.supported <= baseline.report.supported);
    let denied_source = inventory
        .sources
        .iter()
        .find(|source| source.path() == denied)
        .cloned()
        .expect("denied source remains visible");
    assert_eq!(
        adapter
            .open(&denied_source)
            .expect_err("denial must fail closed")
            .classification(),
        ScanClassification::PermissionDenied
    );
    fs::set_permissions(&denied, fs::Permissions::from_mode(0o644)).unwrap();
    fs::set_permissions(&probe, fs::Permissions::from_mode(0o644)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ac11_unknown_fingerprint_negatives_reject_header_and_divergent_body() {
    let root = temp_root("fingerprints");
    let unknown = root.join("unknown.jsonl");
    let divergent = root.join("divergent.jsonl");
    let unknown_body = b"{\"type\":\"session\",\"version\":99}\n{\"type\":\"message\",\"secret\":\"fixture-only\"}\n";
    let divergent_body = b"{\"type\":\"session\"}\n{\"type\":\"future_record\",\"value\":1}\n";
    write(&unknown, unknown_body);
    write(&divergent, divergent_body);
    let account = account("fingerprints");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let inventory = adapter.inventory(&account);
    assert_eq!(inventory.report.classification, ScanClassification::Ok);
    assert_eq!(inventory.report.supported, 1);
    assert_eq!(inventory.report.unsupported, 1);
    for source in inventory.unsupported() {
        assert_eq!(
            adapter
                .open(source)
                .expect_err("unsupported source")
                .classification(),
            ScanClassification::FingerprintUnsupported
        );
    }

    let supported = root.join("supported.jsonl");
    write(&supported, divergent_body);
    let source = adapter
        .inventory(&account)
        .supported()
        .find(|source| source.path() == supported)
        .cloned()
        .expect("supported header source");
    let mut capture = adapter.open(&source).expect("header admission");
    assert_eq!(
        capture
            .next_chunk()
            .expect_err("body fingerprint must fail")
            .classification(),
        ScanClassification::FingerprintUnsupported
    );
    assert_eq!(fs::read(&supported).unwrap(), divergent_body);
    assert_eq!(fs::read(&unknown).unwrap(), unknown_body);
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn ac11_content_freedom_negatives_keep_hostile_paths_and_records_out_of_surfaces() {
    let root = temp_root("hostile-path-marker");
    let path = root.join("record-secret-marker.jsonl");
    let body = b"{\"type\":\"session\",\"cwd\":\"record-secret-marker\"}\n";
    write(&path, body);
    let account = account("content-free");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(account.clone(), &root)]).unwrap();
    let inventory = adapter.inventory(&account);
    let report = String::from_utf8(inventory.report.to_json().canonical_bytes()).unwrap();
    assert!(!report.contains("record-secret-marker"));
    let routed = inventory.discovered_sources().unwrap();
    assert_eq!(routed.len(), 1);
    assert_eq!(format!("{}", PiCaptureError::ReadError), "pi_read_error");
    fs::remove_dir_all(root).expect("remove fixture");
}

#[test]
fn ac11_hostile_source_negatives_classify_malformed_deep_and_oversized_records() {
    let malformed_root = temp_root("malformed");
    let malformed = malformed_root.join("session.jsonl");
    write(&malformed, b"{\"type\":\"session\"}\nnot-json\n");
    let malformed_account = account("malformed");
    let adapter = PiAdapter::new([ConfiguredRoot::durable(
        malformed_account.clone(),
        &malformed_root,
    )])
    .unwrap();
    let malformed_source = source(&adapter, &malformed_root, &malformed_account);
    let mut capture = adapter.open(&malformed_source).unwrap();
    assert_eq!(
        capture
            .next_chunk()
            .expect_err("malformed record")
            .classification(),
        ScanClassification::FingerprintUnsupported
    );
    fs::remove_dir_all(malformed_root).unwrap();

    let deep_root = temp_root("deep");
    let deep = deep_root.join("session.jsonl");
    let mut deep_record = b"{\"type\":\"message\",\"nested\":".to_vec();
    deep_record.extend(std::iter::repeat_n(b'[', 65));
    deep_record.push(b'0');
    deep_record.extend(std::iter::repeat_n(b']', 65));
    deep_record.extend_from_slice(b"}\n");
    write(
        &deep,
        [v1_header(), deep_record.as_slice()].concat().as_slice(),
    );
    let deep_account = account("deep");
    let adapter =
        PiAdapter::new([ConfiguredRoot::durable(deep_account.clone(), &deep_root)]).unwrap();
    let deep_source = source(&adapter, &deep_root, &deep_account);
    let mut capture = adapter.open(&deep_source).unwrap();
    assert_eq!(
        capture
            .next_chunk()
            .expect_err("deep record")
            .classification(),
        ScanClassification::FingerprintUnsupported
    );
    fs::remove_dir_all(deep_root).unwrap();

    let large_root = temp_root("large");
    let large = large_root.join("session.jsonl");
    fs::create_dir_all(&large_root).unwrap();
    let mut file = File::create(&large).unwrap();
    file.write_all(v1_header()).unwrap();
    file.set_len(u64::try_from(v1_header().len() + MAX_RECORD_BYTES + 1).unwrap())
        .unwrap();
    let large_account = account("large");
    let adapter =
        PiAdapter::new([ConfiguredRoot::durable(large_account.clone(), &large_root)]).unwrap();
    let large_source = source(&adapter, &large_root, &large_account);
    let mut capture = adapter.open(&large_source).unwrap();
    assert_eq!(
        capture.next_chunk().expect_err("oversized record"),
        PiCaptureError::RecordTooLarge
    );
    fs::remove_dir_all(large_root).unwrap();
}
