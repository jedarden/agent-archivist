// SPDX-License-Identifier: Apache-2.0

//! The synthetic append-only adapter: a community-facing reference example
//! that walks one synthetic JSONL source root through the complete adapter
//! pipeline — discovery, fingerprint admission, generation detection,
//! complete-record capture, and bounded status — using nothing but the
//! published SDK surface, `archivist-protocol`, and `std`.
//!
//! This is the Phase 6D companion to the checked-in synthetic corpus at
//! `fixtures/synthetic/append-only/`. Every byte the example reads comes
//! from that corpus; nothing is embedded here, and every line it prints is
//! a closed-vocabulary token, an integer, or a content-derived digest —
//! never a path, a record, or a transcript excerpt. It is the executable
//! shape a community adapter author starts from, not a conformance suite:
//! the corpus README describes what a full suite is expected to cover.
//!
//! # Running it
//!
//! ```text
//! cargo run -p archivist-adapter-sdk --example synthetic_append_only
//! cargo run -p archivist-adapter-sdk --example synthetic_append_only -- growth
//! ```
//!
//! The corpus is located relative to this crate's manifest, so the example
//! runs from any working directory; `--corpus DIR` overrides it.
//!
//! # Scenes
//!
//! | Scene             | Demonstrates                                              |
//! |-------------------|-----------------------------------------------------------|
//! | `complete-records`| The golden path: every record captured, zero tail          |
//! | `partial-tail`    | A torn final line measured and never captured (`EC-01`)    |
//! | `growth`          | An append across two snapshots: the generation continues   |
//! | `replacement`     | A swapped root: `file-identity-change` rotation (`SID-003`)|
//! | `permissions`     | The fail-closed path when the source cannot be read        |
//! | `missing-root`    | A coverage gap: the configured root is absent              |
//!
//! # Modeling rules
//!
//! A real adapter presents the file-identity tuple its own `stat` call
//! reports. The corpus models time as directory pairs, so this example
//! pins one modeled identity per scene: a scene observing one file twice
//! (`growth`) pins the *same* identity across both snapshots, and the
//! swap scene (`replacement`) pins distinct identities, which is exactly
//! what the tuple has to distinguish. Source identifiers are derived from
//! the adapter, the account label, and the source's first complete record
//! — the synthetic `session_start` — never from a path, so appends leave
//! the identifier stable and a swapped root is honestly a new source.

use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use archivist_adapter_sdk::artifact::{CapturedChunk, SourceGeneration};
use archivist_adapter_sdk::capability::{AdapterCapability, CapabilitySet};
use archivist_adapter_sdk::descriptor::AdapterDescriptor;
use archivist_adapter_sdk::discovery::{
    DiscoveredSource, DiscoveredSources, DiscoveryReport, SourceDiscovery,
};
use archivist_adapter_sdk::file_capture::{CaptureCursor, CaptureCursorError, RecordBoundary};
use archivist_adapter_sdk::file_generation::{
    AcknowledgedSource, FileIdentity, GenerationDecision, SourceObservation, detect_generation,
};
use archivist_adapter_sdk::fingerprint::{
    FingerprintAllowlist, SourceFingerprint, unsupported_report,
};
use archivist_adapter_sdk::lifecycle::{AdapterLifecycle, LifecycleState};
use archivist_adapter_sdk::status::{
    AccountLabel, AdapterAccountStatus, ClassificationCounts, CoverageCounts, CoverageState,
    ScanClassification, SourceId, SourceScan,
};
use archivist_protocol::correlation::mint_generation_id;
use archivist_protocol::json::{self, Object, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{
    AdapterId, ArtifactKind, BlobDigest, GenerationId, RangeKind, Timestamp, VersionToken,
};

/// The adapter identity this example publishes. A real adapter keeps its
/// own token stable across releases: it names the adapter, not a version.
const ADAPTER_TOKEN: &str = "synthetic-append-only";

/// The projection version stamped on every captured chunk (CAP-004): a
/// projection change is a different artifact, not a rewrite of this one.
const PROJECTION_TOKEN: &str = "1.0.0";

/// The one schema/version fingerprint this adapter detects. An unknown
/// layout fails closed as `fingerprint-unsupported` (plan `EC-08`).
const FINGERPRINT_TOKEN: &str = "synthetic-append-only-jsonl-v1";

/// The source file every scene root carries.
const SOURCE_FILE_NAME: &str = "source.jsonl";

/// The corpus location relative to the workspace root, used to resolve the
/// default corpus directory and named verbatim in the misconfiguration
/// message (the message stays content-free; it names a layout, not a path
/// that was observed).
const CORPUS_RELATIVE: &str = "fixtures/synthetic/append-only";

/// Domain-separation label for the derived source identifier: the status
/// contract's `source_id` joins the scan to the state database, so it is
/// derived once from stable inputs — adapter, account, first record — and
/// never from a path that could move.
const SOURCE_ID_LABEL: &[u8] = b"archivist.synthetic-append-only.source-id.v1";

/// The scene to run. Each scene is one configured source root, and the
/// pair scenes model one source observed at two times.
#[derive(Clone, Copy, Debug)]
struct Scene {
    /// The account label this scene is configured under: the routing name
    /// discovery reports, never an upstream value.
    account: &'static str,
    /// The first snapshot's directory, relative to the corpus root.
    directory: &'static str,
    /// The modeled file identity of the source at the first observation.
    identity: FileIdentity,
    /// The second observation: another snapshot directory and the identity
    /// the modeled source presents there.
    second: Option<(&'static str, FileIdentity)>,
}

/// The six scenes the corpus ships, in corpus order.
const SCENES: [Scene; 6] = [
    Scene {
        account: "complete-records",
        directory: "complete-records/root",
        identity: FileIdentity {
            device: 0,
            inode: 1,
        },
        second: None,
    },
    Scene {
        account: "partial-tail",
        directory: "partial-tail/root",
        identity: FileIdentity {
            device: 0,
            inode: 2,
        },
        second: None,
    },
    Scene {
        account: "growth",
        directory: "growth/before",
        // One source observed twice: the identity is held across both
        // snapshots, because appends do not change the file's identity.
        identity: FileIdentity {
            device: 0,
            inode: 3,
        },
        second: Some((
            "growth/after",
            FileIdentity {
                device: 0,
                inode: 3,
            },
        )),
    },
    Scene {
        account: "replacement",
        directory: "replacement/old",
        // A swapped root: the second observation presents a different
        // identity, which is what a replacement *is*.
        identity: FileIdentity {
            device: 0,
            inode: 4,
        },
        second: Some((
            "replacement/new",
            FileIdentity {
                device: 0,
                inode: 5,
            },
        )),
    },
    Scene {
        account: "permissions",
        directory: "permissions/root",
        identity: FileIdentity {
            device: 0,
            inode: 6,
        },
        second: None,
    },
    Scene {
        account: "missing-root",
        directory: "missing-root/root",
        identity: FileIdentity {
            device: 0,
            inode: 7,
        },
        second: None,
    },
];

impl Scene {
    /// Parse one scene name, failing closed on anything unknown.
    fn parse(name: &str) -> Option<Self> {
        SCENES.iter().copied().find(|scene| scene.account == name)
    }

    /// The source file of one snapshot directory.
    fn source_path(&self, corpus: &Path, directory: &str) -> PathBuf {
        corpus.join(directory).join(SOURCE_FILE_NAME)
    }
}

/// The synthetic append-only adapter: the SDK's interfaces implemented
/// over one configured source root.
struct SyntheticAppendOnlyAdapter {
    /// The published self-description (CAP-002): identity, capabilities,
    /// fingerprint allowlist, projection version.
    descriptor: AdapterDescriptor,
    /// The configured account this instance covers.
    account: AccountLabel,
    /// The configured source root.
    root: PathBuf,
    /// The observable lifecycle state.
    state: LifecycleState,
}

impl SyntheticAppendOnlyAdapter {
    /// Construct the adapter over one scene: the descriptor publishes from
    /// compile-time constants, so construction cannot fail.
    fn mount(corpus: &Path, scene: &Scene) -> Self {
        let account = AccountLabel::parse(scene.account).expect("scene names are valid labels");
        let capabilities = CapabilitySet::parse([
            AdapterCapability::FileSliceCapture.token(),
            AdapterCapability::CompleteRecordBoundaries.token(),
            AdapterCapability::GenerationDetection.token(),
            AdapterCapability::CoverageGapReporting.token(),
        ])
        .expect("declared capabilities are members of the closed set");
        let fingerprints =
            FingerprintAllowlist::parse([FINGERPRINT_TOKEN]).expect("one valid fingerprint");
        let descriptor = AdapterDescriptor::publish(
            AdapterId::parse(ADAPTER_TOKEN).expect("a valid adapter token"),
            VersionToken::parse(PROJECTION_TOKEN).expect("a valid projection version"),
            capabilities,
            fingerprints,
        )
        .expect("the example declares capabilities");
        Self {
            descriptor,
            account,
            root: corpus.join(scene.directory),
            state: LifecycleState::Constructed,
        }
    }

    /// Validate configuration against the sources and enter [`LifecycleState::Ready`].
    /// The descriptor's own invariants are the validation; a real adapter
    /// would also probe its configured roots here.
    fn activate(&mut self) {
        self.state = LifecycleState::Ready;
    }

    /// The configured source file's path.
    fn source_path(&self) -> PathBuf {
        self.root.join(SOURCE_FILE_NAME)
    }

    /// One discovery pass over the configured account: the report for the
    /// engine plus the discovered sources' routing identities.
    fn inventory(&self) -> (DiscoveryReport, DiscoveredSources) {
        let (classification, fingerprint) = match read_snapshot(&self.source_path()) {
            Err(classification) => {
                // An absent source is a coverage gap; an unreadable one was
                // discovered but could not be fingerprinted, so it counts
                // as neither supported nor unsupported.
                (classification, None)
            }
            Ok(bytes) => match detect_fingerprint(&bytes) {
                Some(fingerprint) => (ScanClassification::Ok, Some(fingerprint)),
                None => (ScanClassification::FingerprintUnsupported, None),
            },
        };
        let (sources, supported, unsupported) = match &fingerprint {
            Some(_) => (1, 1, 0),
            None if classification == ScanClassification::RootAbsent => (0, 0, 0),
            None if classification == ScanClassification::FingerprintUnsupported => (1, 0, 1),
            None => (1, 0, 0),
        };
        let report = DiscoveryReport::new(
            self.descriptor.adapter.clone(),
            self.account.clone(),
            classification,
            sources,
            supported,
            unsupported,
        )
        .expect("the counts are consistent by construction");
        let entries = fingerprint
            .map(|fingerprint| {
                vec![DiscoveredSource {
                    account: self.account.clone(),
                    fingerprint,
                }]
            })
            .unwrap_or_default();
        let discovered = DiscoveredSources::new(entries)
            .expect("one discovered source never exceeds the cap or mixes accounts");
        (report, discovered)
    }
}

impl AdapterLifecycle for SyntheticAppendOnlyAdapter {
    fn state(&self) -> LifecycleState {
        self.state
    }

    fn close(&mut self) {
        // Idempotent: two shutdown paths racing each other release the
        // source-adjacent resources exactly once.
        if self.state != LifecycleState::Closed {
            self.state = LifecycleState::Closed;
        }
    }
}

impl SourceDiscovery for SyntheticAppendOnlyAdapter {
    fn discover(&self, account: &AccountLabel) -> DiscoveryReport {
        // The example configures one account; any other label is a scope
        // this pass did not cover, not a failure.
        if *account != self.account {
            return DiscoveryReport::new(
                self.descriptor.adapter.clone(),
                account.clone(),
                ScanClassification::NotObserved,
                0,
                0,
                0,
            )
            .expect("zero counts are consistent");
        }
        self.inventory().0
    }
}

/// Why the demo stopped before its final status line: only usage errors,
/// which are configuration, not source observations.
fn usage_error(message: &str) -> ! {
    eprintln!("{message}");
    eprintln!(
        "usage: synthetic_append_only [SCENE] [--scene NAME] [--corpus DIR]\n\
         scenes: complete-records (default), partial-tail, growth, replacement,\n\
         \x20       permissions, missing-root\n\
         --corpus DIR  corpus directory (default: {CORPUS_RELATIVE} beside this crate)"
    );
    std::process::exit(2);
}

fn main() -> ExitCode {
    let mut scene_name = String::from("complete-records");
    let mut corpus_override = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "The synthetic append-only adapter example: run one corpus scene\n\
                     through discovery, fingerprint admission, generation detection,\n\
                     complete-record capture, and bounded status.\n\
                     \n\
                     usage: synthetic_append_only [SCENE] [--scene NAME] [--corpus DIR]\n\
                     scenes: complete-records (default), partial-tail, growth,\n\
                     \x20       replacement, permissions, missing-root"
                );
                return ExitCode::SUCCESS;
            }
            "--scene" => {
                scene_name = args
                    .next()
                    .unwrap_or_else(|| usage_error("--scene needs a scene name"));
            }
            "--corpus" => {
                corpus_override =
                    Some(PathBuf::from(args.next().unwrap_or_else(|| {
                        usage_error("--corpus needs a directory")
                    })));
            }
            other if other.starts_with('-') => usage_error(&format!("unknown option: {other}")),
            other => {
                if scene_name != "complete-records" {
                    usage_error("only one scene may be given");
                }
                scene_name = other.to_owned();
            }
        }
    }
    let scene = Scene::parse(&scene_name)
        .unwrap_or_else(|| usage_error(&format!("unknown scene: {scene_name}")));
    let corpus = corpus_override.unwrap_or_else(default_corpus);
    if !corpus.is_dir() {
        eprintln!(
            "the synthetic corpus is missing: expected {CORPUS_RELATIVE} beside this crate's \
             workspace (or pass --corpus DIR)"
        );
        return ExitCode::FAILURE;
    }
    run(&scene, &corpus)
}

/// Run one scene end to end: every observation outcome — including a
/// coverage gap or a fail-closed denial — ends in printed status and exit
/// code 0, because a pass that observed the gap observed *that*.
fn run(scene: &Scene, corpus: &Path) -> ExitCode {
    let mut adapter = SyntheticAppendOnlyAdapter::mount(corpus, scene);
    emit_json("descriptor", &adapter.descriptor.to_json());
    adapter.activate();
    println!("event=lifecycle state={}", adapter.state());

    let (report, discovered) = adapter.inventory();
    emit_json("discovery", &report.to_json());
    for source in discovered.iter() {
        println!(
            "event=source account={} fingerprint={}",
            source.account, source.fingerprint
        );
    }

    // The classifications capture never reads past: the status contract
    // carries the gap, and the demo's contract-total posture ends in
    // success, because reporting the gap *is* the adapter working.
    if let Some(coverage) = report.classification.forced_coverage() {
        if coverage != CoverageState::Unsupported {
            emit_status(
                &adapter.descriptor.adapter,
                &adapter.account,
                report.classification,
            );
            finish(&mut adapter);
            return ExitCode::SUCCESS;
        }
    }

    // The source exists; run the capture passes over it.
    match capture_phase(
        scene,
        corpus,
        &adapter.descriptor.projection,
        &adapter.descriptor.fingerprints,
    ) {
        Ok(summary) => report_measurement(&adapter, &summary),
        Err(classification) => {
            emit_status(
                &adapter.descriptor.adapter,
                &adapter.account,
                classification,
            );
        }
    }
    finish(&mut adapter);
    ExitCode::SUCCESS
}

/// One capture phase: the fail-closed admission gate, the initial
/// generation, every complete record as an immutable chunk, and the second
/// observation's generation decision over the scene's snapshots.
fn capture_phase(
    scene: &Scene,
    corpus: &Path,
    projection: &VersionToken,
    allowlist: &FingerprintAllowlist,
) -> Result<CaptureSummary, ScanClassification> {
    let bytes = read_snapshot(&scene.source_path(corpus, scene.directory))?;
    let fingerprint =
        detect_fingerprint(&bytes).ok_or(ScanClassification::FingerprintUnsupported)?;
    println!("event=fingerprint detected={fingerprint}");
    // The fail-closed gate every read of projected content passes first.
    // Detection yields only allowlisted tokens, so this is the demonstrated
    // contract rather than a live denial.
    allowlist
        .admit(&fingerprint)
        .map_err(|denial| emit_denial(&denial))?;

    let mut generation = SourceGeneration::initial(mint_generation_id());
    println!(
        "event=generation-opened cause={} generation={}",
        generation.cause, generation.generation
    );
    let mut sequence = 0;
    let mut cursor = CaptureCursor::new();
    let mut boundary = capture_pass(&mut cursor, &bytes, &generation, projection, &mut sequence);
    let mut acknowledged = AcknowledgedSource::acknowledge(scene.identity, &bytes);
    let mut final_bytes = bytes;

    match scene.second {
        // The scene models two observations of one source: the decision is
        // continue-or-rotate exactly as a live adapter's would be.
        Some((second_directory, second_identity)) => {
            let second = read_snapshot(&scene.source_path(corpus, second_directory))?;
            let fingerprint =
                detect_fingerprint(&second).ok_or(ScanClassification::FingerprintUnsupported)?;
            allowlist
                .admit(&fingerprint)
                .map_err(|denial| emit_denial(&denial))?;
            let observation = SourceObservation::observe(second_identity, &second);
            match detect_generation(&acknowledged, &observation) {
                GenerationDecision::Continue => {
                    println!(
                        "event=generation-continued generation={}",
                        generation.generation
                    );
                }
                GenerationDecision::Rotated(opened) => {
                    println!(
                        "event=generation-opened cause={} generation={}",
                        opened.cause, opened.generation
                    );
                    // Both histories are preserved; capture restarts at the
                    // new generation's first complete record (AC-03). The
                    // rotated acknowledgement lives inside the decision, so
                    // nothing here re-acknowledges by hand.
                    generation = opened;
                    cursor = CaptureCursor::new();
                    sequence = 0;
                }
            }
            boundary = capture_pass(&mut cursor, &second, &generation, projection, &mut sequence);
            final_bytes = second;
        }
        // One snapshot: re-observing it must continue the generation. A
        // snapshot cannot rotate against its own acknowledgement.
        None => {
            let observation = SourceObservation::observe(scene.identity, &final_bytes);
            match detect_generation(&acknowledged, &observation) {
                GenerationDecision::Continue => {
                    println!(
                        "event=generation-continued generation={}",
                        generation.generation
                    );
                }
                GenerationDecision::Rotated(_) => {
                    return Err(ScanClassification::ReadError);
                }
            }
        }
    }
    Ok(CaptureSummary {
        boundary,
        final_bytes,
    })
}

/// What one capture phase measured, for the scan and status lines.
struct CaptureSummary {
    /// The boundary after the final pass: the figures the scan reports.
    boundary: RecordBoundary,
    /// The final snapshot's bytes: the source-identifier and
    /// last-activity derivation inputs.
    final_bytes: Vec<u8>,
}

/// Capture one pass: everything that completed since the cursor's last
/// boundary becomes immutable chunks; the tail is only ever measured.
fn capture_pass(
    cursor: &mut CaptureCursor,
    snapshot: &[u8],
    generation: &SourceGeneration,
    projection: &VersionToken,
    sequence: &mut u64,
) -> RecordBoundary {
    let first_byte = cursor.position();
    match cursor.observe(snapshot) {
        Ok(outcome) => {
            emit_chunks(
                outcome.captured,
                first_byte,
                &generation.generation,
                projection,
                sequence,
            );
            outcome.boundary
        }
        // The demo only ever re-observes a snapshot at least as long as the
        // cursor's boundary: the same bytes, an appended snapshot, or a
        // fresh cursor after a rotation.
        Err(CaptureCursorError::SourceShrank) => {
            panic!("the demo never re-observes a shrunken snapshot");
        }
    }
}

/// Emit every complete record of one pass as an immutable chunk carrying
/// `SID-004`'s identification: byte range, sequence, payload digest, and
/// the projection version.
fn emit_chunks(
    captured: &[u8],
    first_byte: u64,
    generation: &GenerationId,
    projection: &VersionToken,
    sequence: &mut u64,
) {
    let mut offset = first_byte;
    for record in RecordBoundary::records(captured) {
        let payload_bytes = measured(record.len());
        let chunk = CapturedChunk::new(
            ArtifactKind::FileSlice,
            generation.clone(),
            RangeKind::Byte,
            offset,
            // Every yielded record includes its terminating newline, so the
            // inclusive range is never empty and this never underflows.
            offset + payload_bytes - 1,
            *sequence,
            BlobDigest::from_raw(sha256::digest(record)),
            payload_bytes,
            projection.clone(),
        )
        .expect("non-empty record ranges are well-formed");
        emit_json("chunk", &chunk.to_json());
        *sequence += 1;
        offset += payload_bytes;
    }
}

/// The scan and status lines for a capture phase that measured the source:
/// the scan carries the boundary split, the status aggregates the account.
fn report_measurement(adapter: &SyntheticAppendOnlyAdapter, summary: &CaptureSummary) {
    let source = derive_source_id(
        &adapter.descriptor.adapter,
        &adapter.account,
        &summary.final_bytes,
    )
    .expect("fingerprint detection required a complete first record");
    let scan = SourceScan {
        source,
        adapter: adapter.descriptor.adapter.clone(),
        account: adapter.account.clone(),
        complete_bytes: summary.boundary.complete_bytes,
        complete_events: summary.boundary.complete_records,
        incomplete_tail_bytes: summary.boundary.incomplete_tail_bytes,
        last_activity: last_activity(&summary.final_bytes),
        active_in_window: false,
        classification: ScanClassification::Ok,
    };
    emit_scan(&scan);
    emit_status(
        &adapter.descriptor.adapter,
        &adapter.account,
        ScanClassification::Ok,
    );
}

/// Close the adapter and print the lifecycle epilogue: close is idempotent
/// and a closed adapter's reads are non-observations, never errors.
fn finish(adapter: &mut SyntheticAppendOnlyAdapter) {
    adapter.close();
    adapter.close();
    println!(
        "event=capture-classification-after-close classification={}",
        adapter.capture_classification()
    );
    println!("event=lifecycle state={}", adapter.state());
}

/// Emit the account status for one pass outcome: a fixed key set whose
/// size never depends on the source's content. Every complete record the
/// passes captured is acknowledged, and the measured tail is never part of
/// any backlog figure, so a drained synthetic store is fully backfilled.
fn emit_status(adapter: &AdapterId, account: &AccountLabel, classification: ScanClassification) {
    let coverage = classification
        .forced_coverage()
        .unwrap_or(CoverageState::FullyBackfilled);
    let mut sources = CoverageCounts::default();
    sources.record(coverage);
    let mut classifications = ClassificationCounts::default();
    classifications.record(classification);
    let status = AdapterAccountStatus {
        adapter: adapter.clone(),
        account: account.clone(),
        coverage,
        active_backlog_bytes: 0,
        active_backlog_events: 0,
        historical_backlog_bytes: 0,
        historical_backlog_events: 0,
        max_freshness_lag_seconds: 0,
        sources,
        classifications,
    };
    emit_json("status", &status.to_json());
}

/// Emit one scan as a fixed key set: the state-schema split of a pass —
/// identifiers, the boundary figures, the freshness inputs, and the last
/// classification — with no per-record detail and no free text.
fn emit_scan(scan: &SourceScan) {
    let mut object = Object::new();
    object.set("account", Value::Text(scan.account.as_str().to_owned()));
    object.set("active_in_window", Value::Bool(scan.active_in_window));
    object.set("adapter", Value::Text(scan.adapter.as_str().to_owned()));
    object.set(
        "classification",
        Value::Text(scan.classification.token().to_owned()),
    );
    object.set(
        "complete_bytes",
        Value::Int(i64::try_from(scan.complete_bytes).unwrap_or(i64::MAX)),
    );
    object.set(
        "complete_events",
        Value::Int(i64::try_from(scan.complete_events).unwrap_or(i64::MAX)),
    );
    object.set(
        "incomplete_tail_bytes",
        Value::Int(i64::try_from(scan.incomplete_tail_bytes).unwrap_or(i64::MAX)),
    );
    object.set(
        "last_activity",
        match &scan.last_activity {
            Some(timestamp) => Value::Text(timestamp.as_str().to_owned()),
            None => Value::Null,
        },
    );
    object.set("source", Value::Text(scan.source.as_str().to_owned()));
    emit_json("scan", &Value::Object(object));
}

/// Emit the fail-closed denial for an off-allowlist fingerprint: the token
/// and the classification, nothing else (plan `EC-08`).
fn emit_denial(
    denial: &archivist_adapter_sdk::fingerprint::UnsupportedFingerprint,
) -> ScanClassification {
    emit_json("fingerprint-unsupported", &unsupported_report(denial));
    denial.classification()
}

/// Print one canonical JSON document as a tagged status line.
fn emit_json(event: &str, value: &Value) {
    let canonical = String::from_utf8(value.canonical_bytes()).expect("canonical JSON is UTF-8");
    println!("event={event} {canonical}");
}

/// Read one snapshot, mapping the IO error kinds onto the closed
/// classification vocabulary. A missing source is the corpus's absent-root
/// shape: the configured root has no data to observe.
fn read_snapshot(path: &Path) -> Result<Vec<u8>, ScanClassification> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == ErrorKind::NotFound => Err(ScanClassification::RootAbsent),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            Err(ScanClassification::PermissionDenied)
        }
        Err(_) => Err(ScanClassification::ReadError),
    }
}

/// Detect the source fingerprint from the first complete record: a JSON
/// object carrying the synthetic corpus's `schema: 1` marker plus the
/// record identity, kind, and timestamp members. Anything else fails
/// closed as undetectable, which discovery reports as unsupported.
fn detect_fingerprint(bytes: &[u8]) -> Option<SourceFingerprint> {
    let first = RecordBoundary::records(bytes).next()?;
    let value = json::parse(first).ok()?;
    let object = match value {
        Value::Object(object) => object,
        _ => return None,
    };
    if object.get("schema") != Some(&Value::Int(1)) {
        return None;
    }
    let member = |key: &str| matches!(object.get(key), Some(Value::Text(_)));
    if !member("id") || !member("type") || !member("ts") {
        return None;
    }
    SourceFingerprint::parse(FINGERPRINT_TOKEN).ok()
}

/// The freshest source-side activity timestamp the snapshot exposes: the
/// final complete record's `ts`. Absent or unparseable timestamps leave
/// the field empty rather than guessing.
fn last_activity(bytes: &[u8]) -> Option<Timestamp> {
    let prefix = RecordBoundary::complete_prefix(bytes);
    let last_record_start = prefix[..prefix.len().checked_sub(1)?]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |position| position + 1);
    let value = json::parse(&prefix[last_record_start..]).ok()?;
    match value {
        Value::Object(object) => match object.get("ts") {
            Some(Value::Text(timestamp)) => Timestamp::parse(timestamp).ok(),
            _ => None,
        },
        _ => None,
    }
}

/// Derive the status contract's source identifier from stable inputs —
/// the adapter, the account label, and the source's first complete record
/// — never from a path. The zero-byte separators are unambiguous because
/// every framed token is grammar-bounded away from them, and appends
/// never touch the first record, so the identifier survives growth.
fn derive_source_id(adapter: &AdapterId, account: &AccountLabel, bytes: &[u8]) -> Option<SourceId> {
    let first = RecordBoundary::records(bytes).next()?;
    let mut framed = SOURCE_ID_LABEL.to_vec();
    for part in [
        adapter.as_str().as_bytes(),
        account.as_str().as_bytes(),
        first,
    ] {
        framed.push(0);
        framed.extend_from_slice(part);
    }
    let hex = sha256::encode_hex(&sha256::digest(&framed));
    let text = format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    );
    SourceId::parse(&text).ok()
}

/// The default corpus directory: the workspace checkout that contains this
/// crate, resolved from the manifest path baked in at compile time, so the
/// example runs from any working directory.
fn default_corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|workspace| workspace.join(CORPUS_RELATIVE))
        .unwrap_or_else(|| PathBuf::from(CORPUS_RELATIVE))
}

/// A slice measurement widened into the byte-count domain, saturating.
fn measured(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}
