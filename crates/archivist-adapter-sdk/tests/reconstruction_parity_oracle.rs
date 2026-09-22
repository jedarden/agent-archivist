// SPDX-License-Identifier: Apache-2.0

//! The file-source capture core's reconstruction parity oracle (plan
//! Phase 6A, the File-adapter parity decision): drive the boundary,
//! cursor, and generation-detection core through the conformance
//! scenarios and hold it to the one sentence the plan requires —
//! *reconstructing each captured generation from its ordered occurrence
//! manifests yields exactly the complete-record byte prefix of the
//! source snapshot*.
//!
//! An occurrence manifest here is what capture hands the engine for one
//! pass: the generation it captured into, its sequence within that
//! generation, and the ordered per-record SHA-256 digests plus the whole
//! capture's blob digest. The oracle never compares live capture bytes
//! to the source directly for its verdict — it reassembles each
//! generation from the recorded manifests, verifies every digest, and
//! requires the reassembly to equal the complete-record prefix of the
//! snapshot that generation last observed, byte-for-byte. Any deviation
//! (a torn tail folded in, a record lost, one generation's bytes leaking
//! into another) breaks the equality.
//!
//! # The conformance scenarios
//!
//! - **partial-tail** (`fixtures/synthetic/malformed/truncated-tail.jsonl`):
//!   a torn tail waits, is re-measured on later passes without ever
//!   advancing the cursor, completes, and is then captured whole.
//! - **growth** (`fixtures/synthetic/sessions/…`): concurrent appends
//!   land several records between passes while one record completes
//!   across passes and is captured whole; an always-torn store never
//!   moves the cursor off the last complete boundary.
//! - **replacement** (`fixtures/synthetic/rewritten/…`): each `gen-NNNN`
//!   snapshot arrives under a fresh file identity, so every transition
//!   is a detected `file-identity-change` and opens its own generation.
//! - **rewrite** (same trees, same file identity throughout): the
//!   transition causes are pinned to what the detection table owes for
//!   the pinned bytes — `truncation` for the shrink, `digest-change` for
//!   the in-place rewrite that also grew.
//!
//! # The fault injections
//!
//! The oracle is only an oracle if it can fail. Three wrappers around
//! the real core each inject exactly one fault — advancing past a
//! partial boundary, merging generation histories, dropping a complete
//! record — and one test per fault observes the oracle name it.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use archivist_adapter_sdk::artifact::{GenerationCause, SourceGeneration};
use archivist_adapter_sdk::file_capture::{CaptureCursor, RecordBoundary};
use archivist_adapter_sdk::file_generation::{
    FileGenerationTracker, FileIdentity, GenerationDecision,
};
use archivist_protocol::json::{self, Value};
use archivist_protocol::sha256;
use archivist_protocol::vocabulary::{BlobDigest, GenerationId};

/// The committed synthetic corpus, relative to this crate's manifest
/// directory (`crates/archivist-adapter-sdk` → workspace root →
/// `fixtures/synthetic`).
fn synthetic_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("fixtures").join("synthetic"))
        .expect("the SDK lives at crates/archivist-adapter-sdk")
}

/// The fixture digests pinned by `fixtures/synthetic/manifest.json`,
/// keyed by corpus-relative path. The oracle parity-checks pinned bytes,
/// so it first pins them: a fixture that drifted from the corpus
/// generator fails here instead of producing a vacuous pass.
fn pinned_digests() -> BTreeMap<String, String> {
    let manifest = fs::read(synthetic_root().join("manifest.json"))
        .unwrap_or_else(|error| panic!("fixtures/synthetic/manifest.json is readable: {error}"));
    let Value::Object(parsed) =
        json::parse(&manifest).expect("the fixture manifest is canonical JSON")
    else {
        panic!("the fixture manifest is a JSON object");
    };
    let Value::Array(files) = parsed
        .get("files")
        .expect("the fixture manifest lists its files")
    else {
        panic!("the fixture manifest's files member is an array");
    };
    let mut digests = BTreeMap::new();
    for file in files {
        let Value::Object(file) = file else {
            panic!("every manifest file entry is an object");
        };
        let Value::Text(path) = file.get("path").expect("a file entry names its path") else {
            panic!("a file entry's path is text");
        };
        let Value::Text(digest) = file.get("sha256").expect("a file entry pins its digest") else {
            panic!("a file entry's sha256 is text");
        };
        digests.insert(path.clone(), digest.clone());
    }
    assert!(!digests.is_empty(), "the manifest pins the whole corpus");
    digests
}

/// One fixture's bytes, verified against the pinned corpus digest.
fn load_fixture(path: &str) -> Vec<u8> {
    let bytes = fs::read(synthetic_root().join(path))
        .unwrap_or_else(|error| panic!("fixture {path} is readable: {error}"));
    let pinned = pinned_digests();
    let digest = pinned
        .get(path)
        .unwrap_or_else(|| panic!("fixture {path} is pinned in the manifest"));
    assert_eq!(
        sha256::encode_hex(&sha256::digest(&bytes)),
        *digest,
        "fixture {path} drifted from its pinned digest"
    );
    bytes
}

/// The complete, newline-terminated records of one fixture, in order.
fn records_of(bytes: &[u8]) -> Vec<&[u8]> {
    RecordBoundary::records(bytes).collect()
}

/// A slice measurement widened into the byte-count domain.
fn widened(bytes: usize) -> u64 {
    u64::try_from(bytes).expect("test sizes are small")
}

// ---------------------------------------------------------------------------
// Occurrence manifests
// ---------------------------------------------------------------------------

/// The manifest entry for one complete record: its byte length and its
/// plain SHA-256 digest (`STO-001`).
#[derive(Clone, Debug, PartialEq, Eq)]
struct RecordDigest {
    bytes: u64,
    digest: BlobDigest,
}

/// What one capture pass hands the engine: the generation it captured
/// into, the occurrence's sequence within that generation, and the
/// ordered record digests plus the capture's blob digest. The payload
/// bytes live beside the manifests, exactly as blobs live beside the
/// stored occurrence manifests in the archive; reconstruction reads the
/// manifests and verifies the payloads against them.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OccurrenceManifest {
    generation: GenerationId,
    sequence: u64,
    records: Vec<RecordDigest>,
    blob: BlobDigest,
}

impl OccurrenceManifest {
    /// Open the generation's next occurrence manifest.
    fn new(generation: GenerationId, sequence: u64) -> Self {
        Self {
            generation,
            sequence,
            records: Vec::new(),
            blob: BlobDigest::from_raw([0; 32]),
        }
    }

    /// Record one complete record of this occurrence.
    fn record(&mut self, record: &[u8]) {
        self.records.push(RecordDigest {
            bytes: widened(record.len()),
            digest: BlobDigest::from_raw(sha256::digest(record)),
        });
    }

    /// Seal the occurrence with the digest of its whole captured payload.
    fn seal(&mut self, captured: &[u8]) {
        self.blob = BlobDigest::from_raw(sha256::digest(captured));
    }
}

// ---------------------------------------------------------------------------
// The capture implementation surface the oracle drives
// ---------------------------------------------------------------------------

/// What one implementation claims a pass did: the bytes it captured, the
/// whole-source boundary it measured, its cursor's position and record
/// count, the generation now open, the generation this pass closed (if
/// any), and the implementation's closed-generation history.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CorePass {
    captured: Vec<u8>,
    boundary: RecordBoundary,
    position: u64,
    complete_records: u64,
    generation: SourceGeneration,
    rotated_from: Option<SourceGeneration>,
    history: Vec<SourceGeneration>,
}

/// A capture implementation, at the altitude the oracle sees it: one
/// pass over one file-source snapshot. The real core implements this,
/// and so does every fault injection — which is what makes the oracle an
/// oracle rather than a suite of assertions about one implementation.
trait CaptureCore {
    /// Observe one pass over the snapshot under this file identity.
    fn pass(&mut self, identity: FileIdentity, snapshot: &[u8]) -> CorePass;
}

/// The real file-source capture core: the boundary module's cursor and
/// the generation tracker in lockstep. The tracker decides first — it
/// compares against the previous acknowledgment — and on a rotation the
/// cursor restarts at zero, because the bytes it counted belonged to the
/// closed generation; the new generation captures from its own first
/// complete record (AC-03's restart mitigation). The two components
/// always agree on the acknowledged complete-byte length, so the cursor
/// can never observe a snapshot shorter than its own boundary.
struct CaptureEngine {
    cursor: CaptureCursor,
    tracker: FileGenerationTracker,
}

impl CaptureEngine {
    /// Begin capturing a source at its first observation.
    fn new(identity: FileIdentity, snapshot: &[u8]) -> Self {
        Self {
            cursor: CaptureCursor::new(),
            tracker: FileGenerationTracker::begin(identity, snapshot),
        }
    }
}

impl CaptureCore for CaptureEngine {
    fn pass(&mut self, identity: FileIdentity, snapshot: &[u8]) -> CorePass {
        let decision = self.tracker.observe(identity, snapshot);
        let rotated_from = match &decision {
            GenerationDecision::Continue => None,
            GenerationDecision::Rotated(_) => self.tracker.history().last().cloned(),
        };
        if decision.opened().is_some() {
            self.cursor = CaptureCursor::new();
        }
        let outcome = self.cursor.observe(snapshot).expect(
            "the cursor and the acknowledgment advance in lockstep, so the \
                     snapshot is never shorter than the cursor's boundary",
        );
        CorePass {
            captured: outcome.captured.to_vec(),
            boundary: outcome.boundary,
            position: self.cursor.position(),
            complete_records: self.cursor.complete_records(),
            generation: self.tracker.current().clone(),
            rotated_from,
            history: self.tracker.history().to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// The oracle
// ---------------------------------------------------------------------------

/// One pass of a scenario: the file identity the source presents and the
/// snapshot's own bytes — the whole file as a reader would stat and read
/// it on that pass.
struct PassInput {
    label: &'static str,
    identity: FileIdentity,
    snapshot: Vec<u8>,
}

/// A conformance scenario: the ordered observations of one file source.
/// The first pass is the source's initial observation.
struct Scenario {
    passes: Vec<PassInput>,
}

/// Why the oracle failed an implementation. Every variant names the
/// clause of the parity decision the implementation broke.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ParityFault {
    /// The cursor claimed bytes the complete-record boundary never
    /// covered: it advanced past a partial boundary.
    PastPartialBoundary {
        pass: usize,
        position: u64,
        complete_bytes: u64,
    },
    /// The generation histories merged: an open generation is also
    /// closed, an identifier repeats, or a rotation was not carried
    /// through the history the contract requires.
    MergedGenerationHistories { pass: usize, reason: &'static str },
    /// A capture carried bytes that are not newline-terminated records —
    /// the torn tail inside a capture.
    TornCapture {
        pass: usize,
        generation: GenerationId,
    },
    /// The generation's running capture stopped matching the source's
    /// complete-record prefix: a complete record was dropped, duplicated,
    /// or rewritten.
    CaptureParityBreak {
        pass: usize,
        generation: GenerationId,
    },
    /// An occurrence manifest does not describe its payload — a record
    /// entry or the blob digest disagrees with the bytes.
    ManifestMismatch {
        generation: GenerationId,
        sequence: u64,
        reason: &'static str,
    },
    /// The manifests' reconstruction did not reproduce the generation's
    /// expected complete-record prefix byte-for-byte.
    ReconstructionMismatch {
        generation: GenerationId,
        expected_bytes: u64,
        reconstructed_bytes: u64,
    },
}

/// One verified pass, as the scenario tests read it back.
#[derive(Clone, Debug)]
struct PassEvidence {
    label: &'static str,
    generation: GenerationId,
    rotation: Option<GenerationCause>,
    position: u64,
    boundary: RecordBoundary,
    captured_bytes: u64,
}

/// One verified generation: the reconstruction from its ordered
/// occurrence manifests, and the prefix it was required to equal.
#[derive(Clone, Debug)]
struct GenerationEvidence {
    generation: GenerationId,
    cause: GenerationCause,
    occurrences: u64,
    reconstructed: Vec<u8>,
    expected: Vec<u8>,
}

/// What a scenario's run established, per pass and per generation.
#[derive(Clone, Debug)]
struct ScenarioEvidence {
    passes: Vec<PassEvidence>,
    generations: Vec<GenerationEvidence>,
}

/// Drive one capture implementation through one scenario, holding it to
/// the parity decision after every pass and to the manifest-based
/// reconstruction at the end.
fn run_oracle(
    scenario: &Scenario,
    core: &mut dyn CaptureCore,
) -> Result<ScenarioEvidence, ParityFault> {
    let mut occurrences: Vec<OccurrenceManifest> = Vec::new();
    let mut payloads: Vec<Vec<u8>> = Vec::new();
    let mut sequences: BTreeMap<GenerationId, u64> = BTreeMap::new();
    let mut running: BTreeMap<GenerationId, Vec<u8>> = BTreeMap::new();
    let mut last_pass_of: BTreeMap<GenerationId, usize> = BTreeMap::new();
    let mut transcript: Vec<PassEvidence> = Vec::new();
    let mut previous: Option<CorePass> = None;

    for (index, input) in scenario.passes.iter().enumerate() {
        let pass = core.pass(input.identity, &input.snapshot);
        let generation_id = pass.generation.generation.clone();
        let real = RecordBoundary::select(&input.snapshot);

        // The cursor never advances past the partial boundary: it sits
        // exactly on the complete boundary it claims, and that claim
        // covers no byte the snapshot has not completed.
        if pass.position != pass.boundary.complete_bytes || pass.position > real.complete_bytes {
            return Err(ParityFault::PastPartialBoundary {
                pass: index,
                position: pass.position,
                complete_bytes: real.complete_bytes,
            });
        }

        check_generation_discipline(&pass, previous.as_ref(), index)?;

        // A capture is records, never a fragment: the torn tail appears
        // in no capture, on any pass.
        if RecordBoundary::select(&pass.captured).incomplete_tail_bytes != 0 {
            return Err(ParityFault::TornCapture {
                pass: index,
                generation: generation_id,
            });
        }

        // The incremental parity statement: after every pass, the bytes
        // captured into the open generation so far are exactly the
        // complete-record prefix of the snapshot just observed.
        let expected = RecordBoundary::complete_prefix(&input.snapshot);
        let captured_so_far = running.entry(generation_id.clone()).or_default();
        captured_so_far.extend_from_slice(&pass.captured);
        if captured_so_far.as_slice() != expected {
            return Err(ParityFault::CaptureParityBreak {
                pass: index,
                generation: generation_id,
            });
        }

        // Record the occurrence the pass produced, if it produced one —
        // a pass whose torn tail is still waiting captures nothing and
        // files no manifest.
        if !pass.captured.is_empty() {
            let sequence = sequences.entry(generation_id.clone()).or_default();
            let mut manifest = OccurrenceManifest::new(generation_id.clone(), *sequence);
            *sequence += 1;
            for record in RecordBoundary::records(&pass.captured) {
                manifest.record(record);
            }
            manifest.seal(&pass.captured);
            payloads.push(pass.captured.clone());
            occurrences.push(manifest);
        }
        last_pass_of.insert(generation_id.clone(), index);
        transcript.push(PassEvidence {
            label: input.label,
            generation: generation_id,
            // A rotation happened exactly when a generation was closed;
            // its cause is the one detection froze onto the generation
            // it opened, never the closed generation's own cause.
            rotation: pass
                .rotated_from
                .as_ref()
                .map(|_closed| pass.generation.cause),
            position: pass.position,
            boundary: pass.boundary,
            captured_bytes: widened(pass.captured.len()),
        });
        previous = Some(pass);
    }

    let last = previous.expect("a scenario runs at least one pass");
    let mut order = last.history.clone();
    order.push(last.generation.clone());

    let mut generations = Vec::new();
    for generation in &order {
        let reconstructed =
            reconstruct_generation(generation.generation.clone(), &occurrences, &payloads)?;
        let at = last_pass_of
            .get(&generation.generation)
            .copied()
            .expect("every generation observed at least one pass");
        let expected = RecordBoundary::complete_prefix(&scenario.passes[at].snapshot).to_vec();
        if reconstructed != expected {
            return Err(ParityFault::ReconstructionMismatch {
                generation: generation.generation.clone(),
                expected_bytes: widened(expected.len()),
                reconstructed_bytes: widened(reconstructed.len()),
            });
        }
        let occurrence_count = occurrences
            .iter()
            .filter(|manifest| manifest.generation == generation.generation)
            .count();
        generations.push(GenerationEvidence {
            generation: generation.generation.clone(),
            cause: generation.cause,
            occurrences: widened(occurrence_count),
            reconstructed,
            expected,
        });
    }

    Ok(ScenarioEvidence {
        passes: transcript,
        generations,
    })
}

/// Hold one pass's generation bookkeeping to the history contract: the
/// open generation is never a closed one, identifiers never repeat, and
/// a rotation is carried through exactly — the closed generation is the
/// one the previous pass held open, it becomes the newest history entry,
/// and a pass without a rotation changes neither the open generation nor
/// the history.
fn check_generation_discipline(
    pass: &CorePass,
    previous: Option<&CorePass>,
    index: usize,
) -> Result<(), ParityFault> {
    if pass.history.iter().any(|closed| closed == &pass.generation) {
        return Err(ParityFault::MergedGenerationHistories {
            pass: index,
            reason: "the open generation is also a closed history entry",
        });
    }
    for (at, closed) in pass.history.iter().enumerate() {
        if pass.history[..at].iter().any(|earlier| earlier == closed) {
            return Err(ParityFault::MergedGenerationHistories {
                pass: index,
                reason: "a generation identifier repeats in the closed history",
            });
        }
    }
    match (&pass.rotated_from, previous) {
        (Some(closed), Some(before)) => {
            if closed != &before.generation {
                return Err(ParityFault::MergedGenerationHistories {
                    pass: index,
                    reason: "the pass closed a generation other than the one the \
                             previous pass held open",
                });
            }
            if pass.history.len() != before.history.len() + 1 || pass.history.last() != Some(closed)
            {
                return Err(ParityFault::MergedGenerationHistories {
                    pass: index,
                    reason: "the closed generation did not become the newest history \
                             entry",
                });
            }
            if pass.generation == before.generation {
                return Err(ParityFault::MergedGenerationHistories {
                    pass: index,
                    reason: "the successor generation kept its predecessor's identifier",
                });
            }
        }
        (None, Some(before)) => {
            if pass.generation != before.generation {
                return Err(ParityFault::MergedGenerationHistories {
                    pass: index,
                    reason: "the generation changed without closing its predecessor",
                });
            }
            if pass.history.len() != before.history.len() {
                return Err(ParityFault::MergedGenerationHistories {
                    pass: index,
                    reason: "the closed history changed without a rotation",
                });
            }
        }
        (Some(_), None) => {
            return Err(ParityFault::MergedGenerationHistories {
                pass: index,
                reason: "the first pass closed a generation nothing held open",
            });
        }
        (None, None) => {}
    }
    Ok(())
}

/// Reassemble one generation from its ordered occurrence manifests,
/// verifying every record entry and every blob digest along the way.
fn reconstruct_generation(
    generation: GenerationId,
    occurrences: &[OccurrenceManifest],
    payloads: &[Vec<u8>],
) -> Result<Vec<u8>, ParityFault> {
    assert_eq!(
        occurrences.len(),
        payloads.len(),
        "every manifest has exactly one payload"
    );
    let mut reconstructed = Vec::new();
    for (manifest, payload) in occurrences.iter().zip(payloads) {
        if manifest.generation != generation {
            continue;
        }
        let records: Vec<&[u8]> = RecordBoundary::records(payload).collect();
        if records.len() != manifest.records.len() {
            return Err(ParityFault::ManifestMismatch {
                generation,
                sequence: manifest.sequence,
                reason: "the manifest's record count does not match its payload",
            });
        }
        for (record, entry) in records.into_iter().zip(&manifest.records) {
            if entry.bytes != widened(record.len())
                || entry.digest != BlobDigest::from_raw(sha256::digest(record))
            {
                return Err(ParityFault::ManifestMismatch {
                    generation,
                    sequence: manifest.sequence,
                    reason: "a record entry does not describe its record",
                });
            }
        }
        if manifest.blob != BlobDigest::from_raw(sha256::digest(payload)) {
            return Err(ParityFault::ManifestMismatch {
                generation,
                sequence: manifest.sequence,
                reason: "the blob digest does not describe the payload",
            });
        }
        reconstructed.extend_from_slice(payload);
    }
    Ok(reconstructed)
}

// ---------------------------------------------------------------------------
// The conformance scenarios
// ---------------------------------------------------------------------------

/// The torn-tail fixture: three complete records and a 170-byte tail
/// that never terminated.
const TAIL_FIXTURE: &str = "malformed/truncated-tail.jsonl";

/// The growth fixture: twenty-two complete records, newline-terminated.
const GROWTH_FIXTURE: &str = "sessions/session-719e5512-b617-4efb-89ca-83fd587bfe43.jsonl";

/// The committed rewrite vectors: two sessions, three full snapshots
/// each, keyed by the session the generations belong to.
const REWRITTEN_TREES: [&str; 2] = [
    "rewritten/428685d5-f27a-4b68-b919-b46084bdf890",
    "rewritten/f6ea05b0-8347-4f25-b49c-3fe540d6df47",
];

/// One file identity per generation under test, all on the same device:
/// a replacement re-creates the file, so the inode changes under the
/// same name.
fn identity(inode: u64) -> FileIdentity {
    FileIdentity::new(0xC0FF_EE00, inode)
}

/// The first `count` records as one snapshot.
fn record_prefix(records: &[&[u8]], count: usize) -> Vec<u8> {
    let mut snapshot = Vec::new();
    for record in &records[..count] {
        snapshot.extend_from_slice(record);
    }
    snapshot
}

/// The first `count` records plus a torn fragment of the next one: the
/// snapshot a reader racing a harness observes.
fn torn_snapshot(records: &[&[u8]], count: usize, fragment_bytes: usize) -> Vec<u8> {
    let mut snapshot = record_prefix(records, count);
    let fragment = &records[count][..fragment_bytes];
    snapshot.extend_from_slice(fragment);
    snapshot
}

/// The partial-tail scenario: the fixture's tail waits through two
/// re-measured passes, completes, is captured whole, and a fresh torn
/// tail grows behind it without ever being captured.
fn partial_tail_scenario() -> Scenario {
    let file = load_fixture(TAIL_FIXTURE);
    let identity = identity(1);
    // The tail ends mid-JSON-text; these three bytes lexically complete
    // the record (and happen to close it as valid JSON).
    let completion = b"\"}\n";
    let completed = {
        let mut snapshot = file.clone();
        snapshot.extend_from_slice(completion);
        snapshot
    };
    let fresh_torn = {
        let mut snapshot = completed.clone();
        snapshot.extend_from_slice(b"{\"type\": \"system\"");
        snapshot
    };
    let torn_grown = {
        let mut snapshot = fresh_torn.clone();
        snapshot.extend_from_slice(b", \"ts\": \"2026-03-19T09:39:12Z\"");
        snapshot
    };
    Scenario {
        passes: vec![
            PassInput {
                label: "initial-pass",
                identity,
                snapshot: file.clone(),
            },
            PassInput {
                label: "tail-waits",
                identity,
                snapshot: file.clone(),
            },
            PassInput {
                label: "tail-re-measured",
                identity,
                snapshot: file.clone(),
            },
            PassInput {
                label: "tail-completes",
                identity,
                snapshot: completed,
            },
            PassInput {
                label: "fresh-torn-tail",
                identity,
                snapshot: fresh_torn.clone(),
            },
            PassInput {
                label: "torn-tail-waits",
                identity,
                snapshot: fresh_torn,
            },
            PassInput {
                label: "torn-tail-grown",
                identity,
                snapshot: torn_grown,
            },
        ],
    }
}

/// The growth scenario: a harness appending under a concurrent reader —
/// several records land between passes, one record completes across
/// passes and is captured whole, and a torn tail grows behind the last
/// complete boundary without ever being captured.
fn growth_scenario() -> Scenario {
    let file = load_fixture(GROWTH_FIXTURE);
    let records = records_of(&file);
    let identity = identity(2);
    let early = torn_snapshot(&records, 6, records[6].len() / 3);
    let appended = torn_snapshot(&records, 11, records[11].len() / 2);
    let whole = record_prefix(&records, records.len());
    Scenario {
        passes: vec![
            PassInput {
                label: "early-snapshot",
                identity,
                snapshot: early.clone(),
            },
            PassInput {
                label: "torn-tail-waits",
                identity,
                snapshot: early,
            },
            PassInput {
                label: "concurrent-appends",
                identity,
                snapshot: appended.clone(),
            },
            PassInput {
                label: "torn-tail-waits-again",
                identity,
                snapshot: appended,
            },
            PassInput {
                label: "appends-complete",
                identity,
                snapshot: whole.clone(),
            },
            PassInput {
                label: "fresh-torn-tail",
                identity,
                snapshot: {
                    let mut snapshot = whole.clone();
                    snapshot.extend_from_slice(b"{\"type\": \"system\", \"text\": \"torn\"");
                    snapshot
                },
            },
        ],
    }
}

/// The always-torn scenario: a store whose every pass ends mid-record —
/// the tail keeps growing and never terminates, so the cursor stays at
/// the last complete boundary forever.
fn always_torn_scenario() -> Scenario {
    let file = load_fixture(GROWTH_FIXTURE);
    let records = records_of(&file);
    let identity = identity(3);
    let complete_records = 5;
    let boundary = record_prefix(&records, complete_records);
    let tail = records[complete_records];
    let torn = |tail_bytes: usize| {
        let mut snapshot = boundary.clone();
        snapshot.extend_from_slice(&tail[..tail_bytes]);
        snapshot
    };
    // The torn tail grows across passes and never gains its newline —
    // even the record's last byte stays absent.
    Scenario {
        passes: vec![
            PassInput {
                label: "first-torn-pass",
                identity,
                snapshot: torn(tail.len() / 4),
            },
            PassInput {
                label: "tail-grew",
                identity,
                snapshot: torn(tail.len() / 2),
            },
            PassInput {
                label: "tail-all-but-newline",
                identity,
                snapshot: torn(tail.len() - 1),
            },
            PassInput {
                label: "still-no-newline",
                identity,
                snapshot: torn(tail.len() - 1),
            },
        ],
    }
}

/// One rewrite vector as a scenario. `replaced` decides whether each
/// successive snapshot arrives under a fresh file identity (the
/// replacement vector) or under the same identity (the rewrite vector).
fn rewritten_scenario(tree: &str, replaced: bool) -> Scenario {
    let generation_file = |number: &str| load_fixture(&format!("{tree}/gen-{number}.jsonl"));
    let identity_for = |step: u64| {
        if replaced {
            identity(10 + step)
        } else {
            identity(10)
        }
    };
    Scenario {
        passes: vec![
            PassInput {
                label: "generation-1",
                identity: identity_for(0),
                snapshot: generation_file("0001"),
            },
            PassInput {
                label: "generation-2",
                identity: identity_for(1),
                snapshot: generation_file("0002"),
            },
            PassInput {
                label: "generation-3",
                identity: identity_for(2),
                snapshot: generation_file("0003"),
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Fault injections
// ---------------------------------------------------------------------------

/// The fault of AC-02's shape: the implementation treats the torn tail as
/// if it had completed — folding it into the capture and advancing the
/// cursor over bytes no boundary ever covered.
struct AdvancesPastPartial {
    inner: CaptureEngine,
}

impl CaptureCore for AdvancesPastPartial {
    fn pass(&mut self, identity: FileIdentity, snapshot: &[u8]) -> CorePass {
        let mut pass = self.inner.pass(identity, snapshot);
        let tail = RecordBoundary::incomplete_tail(snapshot);
        if !tail.is_empty() {
            pass.captured.extend_from_slice(tail);
            pass.position = widened(snapshot.len());
            pass.complete_records += 1;
        }
        pass
    }
}

/// The fault of AC-03's shape: the implementation detects the rotation
/// but keeps the first generation open — the closed history carries it
/// while new occurrences still accumulate under its identifier, so the
/// two histories merge into one.
struct MergesHistories {
    inner: CaptureEngine,
    first: Option<SourceGeneration>,
}

impl CaptureCore for MergesHistories {
    fn pass(&mut self, identity: FileIdentity, snapshot: &[u8]) -> CorePass {
        let mut pass = self.inner.pass(identity, snapshot);
        let first = self.first.get_or_insert_with(|| pass.generation.clone());
        if pass.generation != *first {
            // A rotation was detected and recorded — but the
            // implementation keeps reporting the first generation as
            // the one still capturing.
            pass.generation = first.clone();
        }
        pass
    }
}

/// The record-loss fault: on the third pass, the first complete record
/// of the capture is lost between selection and capture — the cursor and
/// boundary claims follow the reduced stream, so the implementation is
/// internally consistent and simply missing a record.
struct DropsARecord {
    inner: CaptureEngine,
    passes: usize,
}

impl CaptureCore for DropsARecord {
    fn pass(&mut self, identity: FileIdentity, snapshot: &[u8]) -> CorePass {
        let mut pass = self.inner.pass(identity, snapshot);
        if self.passes == 2 {
            let first_length = RecordBoundary::records(&pass.captured)
                .next()
                .map(<[u8]>::len);
            if let Some(length) = first_length {
                let dropped = widened(length);
                pass.captured.drain(..length);
                pass.position -= dropped;
                pass.boundary.complete_bytes -= dropped;
                pass.boundary.complete_records -= 1;
                pass.complete_records -= 1;
            }
        }
        self.passes += 1;
        pass
    }
}

// ---------------------------------------------------------------------------
// The oracle's verdicts
// ---------------------------------------------------------------------------

#[test]
fn a_torn_tail_waits_and_is_never_captured_or_advanced_past() {
    let evidence = run_oracle(
        &partial_tail_scenario(),
        &mut CaptureEngine::new(identity(1), &load_fixture(TAIL_FIXTURE)),
    )
    .expect("the real core passes its own oracle");

    // One generation: the torn tail is not a discontinuity.
    assert_eq!(evidence.generations.len(), 1);
    let generation = &evidence.generations[0];
    assert_eq!(generation.cause, GenerationCause::Initial);
    assert_eq!(
        generation.occurrences, 2,
        "only the two passes with complete bytes filed manifests"
    );

    let passes = &evidence.passes;
    assert!(
        passes
            .iter()
            .all(|pass| pass.generation == passes[0].generation),
        "a torn tail is never a generation discontinuity"
    );
    let file = load_fixture(TAIL_FIXTURE);
    let boundary = RecordBoundary::select(&file);
    // The initial pass captures the complete prefix and measures the tail.
    assert_eq!(passes[0].label, "initial-pass");
    assert_eq!(passes[0].position, boundary.complete_bytes);
    assert_eq!(passes[0].captured_bytes, boundary.complete_bytes);
    assert_eq!(passes[0].boundary.incomplete_tail_bytes, 170);
    // Two passes over the unchanged source: the tail is re-measured,
    // captures nothing, and the cursor never moves.
    assert_eq!(passes[1].label, "tail-waits");
    assert_eq!(passes[1].captured_bytes, 0);
    assert_eq!(passes[1].position, boundary.complete_bytes);
    assert_eq!(passes[2].label, "tail-re-measured");
    assert_eq!(passes[2].captured_bytes, 0);
    assert_eq!(passes[2].position, boundary.complete_bytes);
    // The completed record is captured whole — the whole 173-byte record,
    // tail included, never a fragment.
    assert_eq!(passes[3].label, "tail-completes");
    assert_eq!(passes[3].captured_bytes, 173);
    assert_eq!(passes[3].position, boundary.complete_bytes + 173);
    // The fresh torn tail: measured, never captured, never advanced past.
    for pass in &passes[4..] {
        assert_eq!(
            pass.captured_bytes, 0,
            "{} captured the torn tail",
            pass.label
        );
        assert_eq!(pass.position, boundary.complete_bytes + 173);
        assert!(pass.boundary.incomplete_tail_bytes > 0);
    }
    // The reconstruction is the final snapshot's complete prefix.
    let final_snapshot = &partial_tail_scenario().passes[6].snapshot;
    assert_eq!(
        generation.reconstructed,
        RecordBoundary::complete_prefix(final_snapshot)
    );
    assert_eq!(
        widened(generation.reconstructed.len()),
        boundary.complete_bytes + 173
    );
}

#[test]
fn growth_under_concurrent_appends_captures_every_record_whole() {
    let file = load_fixture(GROWTH_FIXTURE);
    let records = records_of(&file);
    let mut engine = CaptureEngine::new(
        identity(2),
        &torn_snapshot(&records, 6, records[6].len() / 3),
    );
    let evidence =
        run_oracle(&growth_scenario(), &mut engine).expect("the real core passes its own oracle");

    // Concurrent appends are growth, not a discontinuity: one generation.
    assert_eq!(evidence.generations.len(), 1);
    let generation = &evidence.generations[0];
    assert_eq!(generation.cause, GenerationCause::Initial);
    assert_eq!(generation.occurrences, 3);

    let passes = &evidence.passes;
    assert!(
        passes
            .iter()
            .all(|pass| pass.generation == passes[0].generation),
        "concurrent appends are growth, never a discontinuity"
    );
    let through = |count: usize| widened(record_prefix(&records, count).len());
    // The early snapshot captures its five complete records and measures
    // the fragment.
    assert_eq!(passes[0].position, through(6));
    assert_eq!(passes[0].captured_bytes, through(6));
    // The waiting pass: nothing captured, cursor held.
    assert_eq!(passes[1].captured_bytes, 0);
    assert_eq!(passes[1].position, through(6));
    // The concurrent appends land five more records; the cursor takes
    // them all at the boundary and re-measures the new fragment.
    assert_eq!(passes[2].captured_bytes, through(11) - through(6));
    assert_eq!(passes[2].position, through(11));
    assert_eq!(passes[3].captured_bytes, 0);
    assert_eq!(passes[3].position, through(11));
    // The record that completed across passes is captured whole: the
    // whole record appears inside one capture, never as fragments.
    assert_eq!(passes[4].captured_bytes, widened(file.len()) - through(11));
    assert_eq!(passes[4].position, widened(file.len()));
    let completed_record = records[11];
    let completed_capture = {
        let start = usize::try_from(through(11)).expect("test sizes are small");
        &file[start..]
    };
    assert!(
        completed_capture.starts_with(completed_record),
        "the record that completed across passes was captured whole"
    );
    // The fresh torn tail after growth is measured and never captured.
    assert_eq!(passes[5].captured_bytes, 0);
    assert_eq!(passes[5].position, widened(file.len()));
    assert!(passes[5].boundary.incomplete_tail_bytes > 0);

    // The reconstruction is the whole source: every record, in order.
    assert_eq!(generation.reconstructed, file);
}

#[test]
fn an_always_torn_store_holds_the_cursor_at_the_last_complete_boundary() {
    let file = load_fixture(GROWTH_FIXTURE);
    let records = records_of(&file);
    let mut engine = CaptureEngine::new(
        identity(3),
        &torn_snapshot(&records, 5, records[5].len() / 4),
    );
    let evidence = run_oracle(&always_torn_scenario(), &mut engine)
        .expect("the real core passes its own oracle");

    assert_eq!(evidence.generations.len(), 1);
    let generation = &evidence.generations[0];
    // The first pass captured the five complete records; every pass after
    // measured a growing torn tail and captured none of it.
    assert_eq!(generation.occurrences, 1);
    let passes = &evidence.passes;
    let boundary = widened(record_prefix(&records, 5).len());
    assert_eq!(passes[0].captured_bytes, boundary);
    for pass in &passes[1..] {
        assert_eq!(
            pass.captured_bytes, 0,
            "{} captured a torn tail",
            pass.label
        );
        assert_eq!(pass.position, boundary, "{} moved the cursor", pass.label);
        assert!(pass.boundary.incomplete_tail_bytes > 0);
    }
    // The reconstruction is the last complete boundary — not one byte of
    // the never-terminating tail.
    let final_snapshot = &always_torn_scenario().passes[3].snapshot;
    assert_eq!(
        generation.reconstructed,
        RecordBoundary::complete_prefix(final_snapshot)
    );
    assert_eq!(widened(generation.reconstructed.len()), boundary);
}

#[test]
fn replacement_vectors_reconstruct_each_generation_separately() {
    for tree in REWRITTEN_TREES {
        let mut engine = {
            let first = rewritten_scenario(tree, true).passes.remove(0);
            CaptureEngine::new(first.identity, &first.snapshot)
        };
        let scenario = rewritten_scenario(tree, true);
        let evidence = run_oracle(&scenario, &mut engine)
            .unwrap_or_else(|fault| panic!("{tree}: the real core fails its oracle: {fault:?}"));

        // Every transition detected the replaced file and opened its own
        // generation; three snapshots, three generations, two closures.
        assert_eq!(evidence.generations.len(), 3, "{tree}");
        assert_eq!(
            evidence.passes[1].rotation,
            Some(GenerationCause::FileIdentityChange)
        );
        assert_eq!(
            evidence.passes[2].rotation,
            Some(GenerationCause::FileIdentityChange)
        );

        // Each generation reconstructed its own snapshot, byte-for-byte —
        // the histories never merged.
        let identifiers: Vec<_> = evidence
            .generations
            .iter()
            .map(|generation| generation.generation.clone())
            .collect();
        for (at, identifier) in identifiers.iter().enumerate() {
            assert!(
                !identifiers[..at].contains(identifier),
                "{tree}: generations never merge, {identifier} repeated"
            );
        }
        for (step, generation) in evidence.generations.iter().enumerate() {
            let number = format!("000{}", step + 1);
            let expected = load_fixture(&format!("{tree}/gen-{number}.jsonl"));
            assert_eq!(generation.occurrences, 1, "{tree} gen-{number}");
            assert_eq!(generation.expected, expected, "{tree} gen-{number}");
            assert_eq!(generation.reconstructed, expected, "{tree} gen-{number}");
        }
    }
}

#[test]
fn rewrite_vectors_reconstruct_each_generation_separately() {
    for tree in REWRITTEN_TREES {
        let scenario = rewritten_scenario(tree, false);
        let mut engine = {
            let first = scenario.passes.first().expect("a scenario has passes");
            CaptureEngine::new(first.identity, &first.snapshot)
        };
        let evidence = run_oracle(&scenario, &mut engine)
            .unwrap_or_else(|fault| panic!("{tree}: the real core fails its oracle: {fault:?}"));

        // Same identity, content rewritten: the shrink is a truncation,
        // and the later in-place rewrite that also grew is a digest
        // change — the pinned bytes decide, and the oracle holds the core
        // to exactly those causes.
        assert_eq!(evidence.generations.len(), 3, "{tree}");
        assert_eq!(
            evidence.passes[1].rotation,
            Some(GenerationCause::Truncation),
            "{tree}"
        );
        assert_eq!(
            evidence.passes[2].rotation,
            Some(GenerationCause::DigestChange),
            "{tree}"
        );

        // Each generation reconstructed its own snapshot — including the
        // generation whose snapshot was *shorter* than its predecessor's.
        for (step, generation) in evidence.generations.iter().enumerate() {
            let number = format!("000{}", step + 1);
            let expected = load_fixture(&format!("{tree}/gen-{number}.jsonl"));
            assert_eq!(generation.expected, expected, "{tree} gen-{number}");
            assert_eq!(generation.reconstructed, expected, "{tree} gen-{number}");
        }
        let generations = &evidence.generations;
        assert_ne!(
            generations[0].reconstructed, generations[1].reconstructed,
            "{tree}: the truncation generation must not inherit its predecessor's bytes"
        );
    }
}

// ---------------------------------------------------------------------------
// The fault demonstrations
// ---------------------------------------------------------------------------

#[test]
fn the_oracle_fails_an_implementation_that_advances_past_a_partial_boundary() {
    let engine = CaptureEngine::new(identity(1), &load_fixture(TAIL_FIXTURE));
    let mut faulty = AdvancesPastPartial { inner: engine };
    let fault = run_oracle(&partial_tail_scenario(), &mut faulty)
        .expect_err("an implementation that captures the torn tail must fail");

    match fault {
        ParityFault::PastPartialBoundary {
            pass,
            position,
            complete_bytes,
        } => {
            assert_eq!(pass, 0, "the very first pass already carries the torn tail");
            assert!(
                position > complete_bytes,
                "the cursor claimed past the boundary"
            );
        }
        other => panic!("the oracle named the wrong fault: {other:?}"),
    }
}

#[test]
fn the_oracle_fails_an_implementation_that_merges_generation_histories() {
    let tree = REWRITTEN_TREES[0];
    let scenario = rewritten_scenario(tree, true);
    let first = scenario.passes.first().expect("a scenario has passes");
    let engine = CaptureEngine::new(first.identity, &first.snapshot);
    let mut faulty = MergesHistories {
        inner: engine,
        first: None,
    };
    let fault = run_oracle(&scenario, &mut faulty)
        .expect_err("an implementation that keeps capturing into a closed generation must fail");

    match fault {
        ParityFault::MergedGenerationHistories { pass, reason } => {
            assert_eq!(pass, 1, "the first rotation already exposes the merge");
            assert!(reason.contains("history"), "the merge is named: {reason}");
        }
        other => panic!("the oracle named the wrong fault: {other:?}"),
    }
}

#[test]
fn the_oracle_fails_an_implementation_that_drops_a_complete_record() {
    let scenario = growth_scenario();
    let first = scenario.passes.first().expect("a scenario has passes");
    let engine = CaptureEngine::new(first.identity, &first.snapshot);
    let initial_generation = engine.tracker.current().generation.clone();
    let mut faulty = DropsARecord {
        inner: engine,
        passes: 0,
    };
    let fault = run_oracle(&growth_scenario(), &mut faulty)
        .expect_err("an implementation that loses a complete record must fail");

    match fault {
        ParityFault::CaptureParityBreak { pass, generation } => {
            assert_eq!(pass, 2, "the third pass is where the record was dropped");
            assert_eq!(
                generation, initial_generation,
                "the drop surfaced inside the one growth generation"
            );
        }
        other => panic!("the oracle named the wrong fault: {other:?}"),
    }
}
