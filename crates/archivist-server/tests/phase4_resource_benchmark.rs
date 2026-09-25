// SPDX-License-Identifier: Apache-2.0

//! The Phase 4 resource benchmark: one reproducible run of the plan's
//! Section 10 server profile — a four-vCPU runner at a 512 MiB RSS ceiling,
//! sixteen concurrent ingest streams admitted four-per-client, 8 MiB
//! multipart parts, 16 MiB target chunks, adversarial near-100:1 input, and
//! the 15-minute request deadline (plan Phase 4 exit gate; bead
//! `aa-feadbc99`).
//!
//! The profile's floors:
//!
//! - **Aggregate canonicalization** across the sixteen lawful streams
//!   stays at or above 50 MiB/s.
//! - **Peak RSS** (`VmHWM`, the kernel-maintained high-water mark the
//!   limits suite also measures) never exceeds 512 MiB — and the
//!   invocation's `MemoryMax=512M` cgroup is the ceiling's teeth: a run
//!   that crosses it is killed rather than failed by assertion.
//! - Every stream's attempt — lawful or refused — completes far inside the
//!   **15-minute deadline**, wrapped in the real
//!   [`archivist_server::guard::within_deadline`] at the configuration's
//!   default value.
//! - **Failures publish no invalid object**: the refused streams end in
//!   the ratio guard's closed error, every one of their sessions is
//!   aborted, and the recording store shows zero committed objects for
//!   them — the abort-before-commit contract the store-level transport
//!   tests pin, exercised at profile scale.
//!
//! # The profile population
//!
//! Two sixteen-wide populations run against the same pipeline shape the
//! route wiring inherits ([`TransportDecoder`] chunks flowing straight
//! into a live [`MultipartWriter`]):
//!
//! 1. **Sixteen lawful streams** at the caps' edge: each carries a zstd
//!    frame tuned to sit just inside both hard payload limits at once —
//!    canonical extent just under the 256 MiB record cap, cumulative
//!    expansion just under the 100:1 ratio cap. This is the worst case the
//!    exit gate names: both guards loaded, sixteen wide.
//! 2. **Sixteen refused streams** one step past the lawful edge: the same
//!    construction with a larger zeros tail, so a hard payload limit
//!    refuses each stream mid-flight. Which of the two guards fires is a
//!    measured property of the tuned frame — at record-cap scale the two
//!    caps nearly coincide (the ratio can only cross 100:1 before the
//!    record cap if the lawful frame sits within a fraction of a percent
//!    of exactly 100:1), so the benchmark pins the refusal to the closed
//!    limit classes rather than to one variant: either
//!    `request.record_too_large` at the 256 MiB record cap or
//!    `request.expansion_ratio_exceeded` at the 100:1 ratio cap. Either
//!    way the caller's abort — not a commit — closes every session, and
//!    the store shows zero published objects for the population.
//!
//! Admission is real: every stream holds a process permit and a per-client
//! share from the live [`AdmissionGate`] for its whole run, and the
//! sixteen-held gate refuses the seventeenth process slot and each
//! client's fifth stream before the decode phase starts.
//!
//! # Memory shape (why the payload never exists)
//!
//! Memory use is bounded by configured concurrency and multipart buffers,
//! not total payload size (plan Phase 4) — so the harness never holds
//! payload scale either. The canonical payload is pure soup-plus-zeros, so
//! both frames are encoded piecewise through the profile encoder's
//! streaming `update` while the same pieces stream through an incremental
//! SHA-256 for the blob key: no 256 MiB buffer exists on the client side
//! or the server side. Per stream the pipeline holds exactly the server's
//! own buffers — the chunk accumulator (16 MiB target), the ≤8 MiB
//! multipart part buffer, and the frame's decoder window under the 8 MiB
//! cap.
//!
//! # Invocation (the reproducible profile)
//!
//! The run is meaningful only under the profile's CPU and memory shape, so
//! it is `#[ignore]`d from the ordinary lanes and run explicitly inside a
//! four-vCPU, 512 MiB cgroup:
//!
//! ```text
//! D=$(mktemp -d) && git archive HEAD | tar -x -C "$D"
//! systemd-run --scope --quiet -p CPUQuota=400% -p MemoryMax=512M \
//!   cargo test -p archivist-server --test phase4_resource_benchmark \
//!   -- --ignored --nocapture
//! ```
//!
//! The toolchain, lockfile, and inputs the run digests are the committed
//! ones, so the run's verification-manifest entry keys to the evaluated
//! commit.

use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use archivist_protocol::object_key::BlobObjectKey;
use archivist_protocol::sha256::Sha256;
use archivist_protocol::vocabulary::{
    BlobDigest, ClientId, StorageOutcome, StorageProfile, TenantId, TransportEncoding,
};
use archivist_server::config::{DEFAULT_RECORD_MAX_BYTES, ServerConfig};
use archivist_server::guard::{self, AdmissionGate, GuardRejection};
use archivist_server::metrics::ServerMetrics;
use archivist_server::transport::{DecodeLimits, TransportDecodeError, TransportDecoder};
use archivist_storage::blob::BlobEncoder;
use archivist_storage::capability::StoreCapabilities;
use archivist_storage::error::StorageError;
use archivist_storage::metadata::ObjectTag;
use archivist_storage::multipart::{MultipartWriter, OpenUploads};
use archivist_storage::raw_write::{
    ManifestKey, MultipartUploadId, PartCommitment, PartNumber, RawWriteStore,
};
use archivist_storage::zstd_v1::ZstdV1Encoder;
use tokio::task::JoinSet;

// ---------------------------------------------------------------------------
// The profile's constants
// ---------------------------------------------------------------------------

/// The aggregate canonicalization floor: 50 MiB/s across all sixteen
/// streams (plan Section 10, the pre-1.0 floor).
const AGGREGATE_FLOOR_MIB_PER_S: f64 = 50.0;

/// The RSS ceiling: 512 MiB of peak resident set, kernel-measured.
const RSS_CEILING_KIB: u64 = 512 * 1024;

/// The incompressible soup prefix of every frame. Its length is what
/// forces the frame to be large enough that the payload's cumulative
/// expansion sits just inside 100:1 — the soup bytes are the frame's bulk,
/// and the zeros tail behind them is nearly free to encode.
const SOUP_PREFIX_BYTES: usize = 2_700_000;

/// The lawful streams' canonical extent: just under the 256 MiB record
/// cap, so each lawful stream is a worst-case record — one step inside the
/// unsplittable ceiling and, via the frame tuning, one step inside the
/// ratio ceiling at the same time.
const LAWFUL_CANONICAL_BYTES: u64 = 268_000_000;

/// The refused streams' extra zeros tail: enough canonical bytes past the
/// lawful extent that a hard payload limit refuses the stream mid-flight
/// even if the codec's zeros-tail encoding drifts by an order of
/// magnitude. The refused frame's bracket assert pins the final cumulative
/// ratio past 100:1, so the attempt cannot complete lawfully whichever
/// guard fires first.
const REFUSED_EXTRA_BYTES: u64 = 64 * 1024 * 1024;

/// The piece every zeros tail streams through — reused, so the encoder
/// side never holds payload scale either.
const ZERO_PIECE_BYTES: usize = 1024 * 1024;

/// The four clients the sixteen streams belong to: four streams each, the
/// per-client share exactly full.
const CLIENT_SEEDS: [&str; 4] = [
    "aaaaaaaa-bbbb-4ccc-8ddd-111111111111",
    "aaaaaaaa-bbbb-4ccc-8ddd-222222222222",
    "aaaaaaaa-bbbb-4ccc-8ddd-333333333333",
    "aaaaaaaa-bbbb-4ccc-8ddd-444444444444",
];

const TENANT: &str = "0f1e2d3c-4b5a-4978-8a9b-0c1d2e3f4a5b";

// ---------------------------------------------------------------------------
// Deterministic input generation
// ---------------------------------------------------------------------------

/// One step of the seeded xorshift64 stream the limits suite fuzzes with.
fn xorshift_byte(state: &mut u64) -> u8 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    state.to_le_bytes()[0]
}

/// The incompressible frame prefix: no structure a decoder or an encoder
/// could lean on, identical for every run at a pinned toolchain.
fn soup(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len).map(|_| xorshift_byte(&mut state)).collect()
}

/// Encode the profile's frame for `canonical_total` canonical bytes:
/// the soup prefix followed by a zeros tail, streamed through the profile
/// encoder piecewise while the same pieces stream through `hash` — so the
/// frame and its payload digest exist without the payload ever being held.
///
/// The achieved expansion is decided by the tail's length and the codec's
/// zeros encoding; the caller's bracket asserts pin the result to the
/// lawful or refused side of the ratio cap.
fn encode_frame(canonical_total: u64, hash: &mut Sha256) -> Vec<u8> {
    let prefix = soup(SOUP_PREFIX_BYTES);
    let mut encoder = ZstdV1Encoder::new(canonical_total).expect("profile encoder");
    let mut frame = Vec::new();
    BlobEncoder::update(&mut encoder, &prefix, &mut frame).expect("the prefix encodes");
    hash.update(&prefix);
    let mut written = u64::try_from(prefix.len()).expect("prefix size fits u64");
    assert!(
        written < canonical_total,
        "the soup prefix alone exceeds the frame's canonical extent"
    );
    let zero_piece = vec![0u8; ZERO_PIECE_BYTES];
    while written < canonical_total {
        let remaining = canonical_total - written;
        let take = usize::min(
            zero_piece.len(),
            usize::try_from(remaining).unwrap_or(usize::MAX),
        );
        let piece = &zero_piece[..take];
        BlobEncoder::update(&mut encoder, piece, &mut frame).expect("the tail encodes");
        hash.update(piece);
        written += u64::try_from(take).expect("piece size fits u64");
    }
    assert_eq!(written, canonical_total, "the tail must land exactly");
    BlobEncoder::finish(&mut encoder, &mut frame).expect("the frame terminates");
    frame
}

/// The payload digest of the frame's canonical bytes, taken incrementally
/// alongside the encode.
fn hashed_digest(hash: Sha256) -> BlobDigest {
    BlobDigest::from_raw(hash.finalize())
}

// ---------------------------------------------------------------------------
// The recording store double
// ---------------------------------------------------------------------------

/// The store double the pipeline streams into: the counters are the
/// assertion surface, and the manifest-write path panics — a decode
/// attempt has no route to a manifest, so reaching one would mean the
/// composition grew a second payload path.
struct RecordingStore {
    parts: AtomicUsize,
    commits: AtomicUsize,
    aborts: AtomicUsize,
}

impl RecordingStore {
    fn new() -> Self {
        Self {
            parts: AtomicUsize::new(0),
            commits: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
        }
    }

    fn parts(&self) -> usize {
        self.parts.load(Ordering::SeqCst)
    }

    fn commits(&self) -> usize {
        self.commits.load(Ordering::SeqCst)
    }

    fn aborts(&self) -> usize {
        self.aborts.load(Ordering::SeqCst)
    }
}

impl RawWriteStore for RecordingStore {
    fn capabilities(&self) -> StoreCapabilities {
        StoreCapabilities::unprobed()
    }

    async fn write_manifest(
        &self,
        _key: &ManifestKey,
        _bytes: &[u8],
    ) -> Result<StorageOutcome, StorageError> {
        panic!("the benchmark's decode path reached a manifest write");
    }

    async fn begin_multipart(
        &self,
        _blob: &BlobObjectKey,
    ) -> Result<MultipartUploadId, StorageError> {
        Ok(MultipartUploadId::parse("phase4-profile-stream").expect("session grammar"))
    }

    async fn write_part(
        &self,
        _upload: &MultipartUploadId,
        part: PartNumber,
        _bytes: &[u8],
    ) -> Result<PartCommitment, StorageError> {
        self.parts.fetch_add(1, Ordering::SeqCst);
        let tag = ObjectTag::parse("phase4-profile-stream").expect("tag grammar");
        Ok(PartCommitment::new(part, tag))
    }

    async fn commit_multipart(
        &self,
        _upload: &MultipartUploadId,
        _parts: &[PartCommitment],
    ) -> Result<StorageOutcome, StorageError> {
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(StorageOutcome::Created)
    }

    async fn abort_multipart(&self, _upload: &MultipartUploadId) -> Result<(), StorageError> {
        self.aborts.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The profile phases
// ---------------------------------------------------------------------------

/// What one stream's attempt ended with.
#[derive(Debug)]
enum StreamOutcome {
    /// The stream completed: canonical and transport totals from the
    /// decoder, as the commit path would validate them.
    Completed {
        /// The canonical bytes the attempt produced.
        canonical: u64,
        /// The transport bytes the attempt consumed.
        transport: u64,
    },
    /// The ratio guard refused the stream mid-flight.
    Refused(TransportDecodeError),
}

/// Admit sixteen streams four-per-client and hold the admissions: the
/// returned pairs are the live gate state the streams run under, and the
/// assertions pin the refused shapes — the seventeenth process slot and
/// each client's fifth stream — while all sixteen are held.
fn admit_sixteen(gate: &AdmissionGate) -> Vec<(guard::ProcessAdmission, guard::ClientAdmission)> {
    let clients: Vec<ClientId> = CLIENT_SEEDS
        .iter()
        .map(|seed| seed.parse().expect("profile client id validates"))
        .collect();
    let mut admissions = Vec::new();
    for _ in 0..4 {
        for client in &clients {
            let process = gate
                .try_admit_process()
                .expect("the process has a slot for stream admission");
            let share = gate
                .admit_client(client, Instant::now())
                .expect("the client share admits its fourth stream");
            admissions.push((process, share));
        }
    }
    assert_eq!(admissions.len(), 16, "sixteen streams hold sixteen slots");
    assert_eq!(
        gate.try_admit_process().map(|_| ()),
        Err(GuardRejection::ProcessAtCapacity),
        "the seventeenth in-flight stream is refused while sixteen run"
    );
    for client in &clients {
        assert_eq!(
            gate.admit_client(client, Instant::now()).map(|_| ()),
            Err(GuardRejection::ClientAtCapacity),
            "a client's fifth in-flight stream is refused while its four run"
        );
    }
    admissions
}

/// Run one sixteen-wide population: the frame streams through the bounded
/// decode stage into a live multipart session per stream, every attempt
/// inside `deadline`. A stream that decodes fully finishes its session and
/// commits; a refused stream's caller aborts its session — the caller
/// contract the route wiring inherits. Returns each stream's outcome and
/// the phase's wall time.
async fn run_population(
    frame: Arc<Vec<u8>>,
    blob: BlobObjectKey,
    deadline: Duration,
    admissions: Vec<(guard::ProcessAdmission, guard::ClientAdmission)>,
    store: Arc<RecordingStore>,
    open: OpenUploads,
) -> (Vec<StreamOutcome>, Duration) {
    let started = Instant::now();
    let mut tasks: JoinSet<StreamOutcome> = JoinSet::new();
    for (process, share) in admissions {
        let frame = Arc::clone(&frame);
        let blob = blob.clone();
        let open = open.clone();
        let store = Arc::clone(&store);
        tasks.spawn(async move {
            // The admissions are held for the stream's whole life: their
            // permits drop only when this future ends.
            let _held = (process, share);
            let attempt = guard::within_deadline(deadline, async {
                let mut decoder = TransportDecoder::new(
                    TransportEncoding::Zstd,
                    Cursor::new(frame.as_slice()),
                    DecodeLimits::registry_defaults(),
                )
                .expect("the profile decoder constructs");
                let mut writer = MultipartWriter::begin(store.as_ref(), &blob, &open)
                    .await
                    .expect("the session begins");
                let mut refusal = None;
                loop {
                    match decoder.next_chunk() {
                        Ok(Some(chunk)) => {
                            writer
                                .write_chunk(chunk)
                                .await
                                .expect("the recording store never refuses a part");
                        }
                        Ok(None) => break,
                        Err(error) => {
                            refusal = Some(error);
                            break;
                        }
                    }
                }
                if let Some(error) = refusal {
                    // The caller's abort-on-error contract: the session is
                    // still live, and the abort — not a commit — closes it.
                    writer.abort().await.expect("the refusal aborts");
                    return StreamOutcome::Refused(error);
                }
                writer.finish().await.expect("the tail part flushes");
                writer.commit().await.expect("the attempt commits");
                StreamOutcome::Completed {
                    canonical: decoder.canonical_bytes(),
                    transport: decoder.transport_bytes(),
                }
            });
            attempt
                .await
                .expect("no stream may outlive the 15-minute deadline")
        });
    }
    let mut outcomes = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        outcomes.push(joined.expect("the stream task never panics"));
    }
    (outcomes, started.elapsed())
}

/// The kernel-maintained peak resident set of this process, in KiB — the
/// same `/proc/self/status` `VmHWM` the limits suite measures.
fn peak_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("status reads");
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            return rest
                .split_whitespace()
                .next()
                .and_then(|value| value.parse::<u64>().ok())
                .expect("VmHWM carries a KiB count");
        }
    }
    panic!("VmHWM is a /proc/self/status field on Linux");
}

/// One population's frame and everything the pipeline needs to stream it.
struct ProfileFrame {
    /// The encoded zstd frame, shared behind an `Arc` so each stream
    /// consumes its own cursor without a second payload-scale copy.
    bytes: Arc<Vec<u8>>,
    /// The canonical bytes the frame decodes to.
    canonical: u64,
    /// The encoded extent every stream consumes.
    transport: u64,
    /// The content-addressed key the streams commit toward.
    blob: BlobObjectKey,
}

/// Encode the lawful and refused frames, with the brackets asserted
/// against the frames the encoder actually produced: the lawful extent
/// sits inside both the ratio cap and the record cap; the refused extent
/// crosses the ratio cap mid-stream.
fn build_profile_frames() -> (ProfileFrame, ProfileFrame) {
    const {
        assert!(
            LAWFUL_CANONICAL_BYTES < DEFAULT_RECORD_MAX_BYTES,
            "the lawful extent must sit under the record cap",
        );
    }
    let mut lawful_hash = Sha256::new();
    let lawful_frame = encode_frame(LAWFUL_CANONICAL_BYTES, &mut lawful_hash);
    let lawful_transport = u64::try_from(lawful_frame.len()).expect("frame size fits u64");
    assert!(
        LAWFUL_CANONICAL_BYTES <= 100 * lawful_transport,
        "bracket setup drifted: the lawful frame is {lawful_transport} bytes \
         against {LAWFUL_CANONICAL_BYTES} canonical — ratio past 100:1"
    );

    let refused_canonical = LAWFUL_CANONICAL_BYTES + REFUSED_EXTRA_BYTES;
    let mut refused_hash = Sha256::new();
    let refused_frame = encode_frame(refused_canonical, &mut refused_hash);
    let refused_transport = u64::try_from(refused_frame.len()).expect("frame size fits u64");
    assert!(
        refused_canonical > 100 * refused_transport,
        "bracket setup drifted: the refused frame is {refused_transport} bytes \
         against {refused_canonical} canonical — the ratio never crossed 100:1"
    );

    let tenant = TenantId::parse(TENANT).expect("tenant grammar");
    (
        ProfileFrame {
            transport: lawful_transport,
            canonical: LAWFUL_CANONICAL_BYTES,
            bytes: Arc::new(lawful_frame),
            blob: BlobObjectKey::new(&tenant, StorageProfile::ZstdV1, &hashed_digest(lawful_hash)),
        },
        ProfileFrame {
            transport: refused_transport,
            canonical: refused_canonical,
            bytes: Arc::new(refused_frame),
            blob: BlobObjectKey::new(
                &tenant,
                StorageProfile::ZstdV1,
                &hashed_digest(refused_hash),
            ),
        },
    )
}

/// Phase 1: the lawful population — sixteen worst-case records, the record
/// cap and the ratio cap both just inside. Every stream commits exactly
/// once; the aggregate canonicalization rate is the measured floor input.
// The rate is a measurement, not an identity: f64 widening of the byte
// total is the point of the division that follows.
#[allow(clippy::cast_precision_loss)]
async fn run_lawful_population(
    gate: &AdmissionGate,
    config: &ServerConfig,
    profile: ProfileFrame,
) -> (f64, Duration) {
    let store = Arc::new(RecordingStore::new());
    let open = OpenUploads::new();
    let admissions = admit_sixteen(gate);
    let (outcomes, elapsed) = run_population(
        profile.bytes,
        profile.blob,
        config.request_deadline(),
        admissions,
        Arc::clone(&store),
        open.clone(),
    )
    .await;
    assert_eq!(outcomes.len(), 16);
    let mut canonical_total = 0u64;
    for outcome in &outcomes {
        match outcome {
            StreamOutcome::Completed {
                canonical,
                transport,
            } => {
                assert_eq!(
                    *canonical, profile.canonical,
                    "a lawful stream produces exactly its canonical extent"
                );
                assert_eq!(*transport, profile.transport, "the whole frame decodes");
                canonical_total += canonical;
            }
            StreamOutcome::Refused(error) => {
                panic!("a lawful stream was refused: {error:?}");
            }
        }
    }
    assert_eq!(
        store.commits(),
        16,
        "every lawful stream commits exactly once"
    );
    assert_eq!(
        store.aborts(),
        0,
        "no lawful stream leaves an aborted session"
    );
    assert_eq!(
        open.live_count(),
        0,
        "no lawful session survives its commit"
    );
    assert!(
        store.parts() >= 16,
        "the lawful population crossed part boundaries"
    );
    let seconds = elapsed.as_secs_f64();
    let aggregate_mib_per_s = canonical_total as f64 / (1024.0 * 1024.0) / seconds;
    // The tuned frames' measured shape — the evidence the bead and the
    // verification manifest record for the adversarial-input claim.
    eprintln!(
        "phase4.lawful_frame_canonical_bytes = {}",
        profile.canonical
    );
    eprintln!(
        "phase4.lawful_frame_transport_bytes = {}",
        profile.transport
    );
    eprintln!(
        "phase4.lawful_frame_expansion_ratio = {:.2}",
        profile.canonical as f64 / profile.transport as f64
    );
    (aggregate_mib_per_s, elapsed)
}

/// Phase 2: the refused population — sixteen streams pushed past the
/// lawful edge. A hard payload limit refuses each stream mid-flight, the
/// caller's abort closes every session, and the store shows zero committed
/// objects for the whole population.
async fn run_refused_population(
    gate: &AdmissionGate,
    config: &ServerConfig,
    profile: ProfileFrame,
) -> Duration {
    let store = Arc::new(RecordingStore::new());
    let open = OpenUploads::new();
    let admissions = admit_sixteen(gate);
    let (outcomes, elapsed) = run_population(
        profile.bytes,
        profile.blob,
        config.request_deadline(),
        admissions,
        Arc::clone(&store),
        open.clone(),
    )
    .await;
    assert_eq!(outcomes.len(), 16);
    eprintln!(
        "phase4.refused_frame_canonical_bytes = {}",
        profile.canonical
    );
    eprintln!(
        "phase4.refused_frame_transport_bytes = {}",
        profile.transport
    );
    for outcome in &outcomes {
        match outcome {
            StreamOutcome::Refused(error) => {
                // At record-cap scale the two hard guards nearly coincide:
                // the cumulative ratio can only cross 100:1 before the
                // record cap if the lawful frame sits within a fraction of
                // a percent of exactly 100:1, so which guard fires first
                // is a tuned-frame property, not a contract choice. The
                // benchmark pins the refusal to the closed class family —
                // a registered 413 payload limit ended the attempt — and
                // each variant's registered cap.
                match error {
                    TransportDecodeError::RecordTooLarge {
                        actual_bytes,
                        limit_bytes,
                    } => {
                        assert_eq!(
                            *limit_bytes, DEFAULT_RECORD_MAX_BYTES,
                            "the record guard refused at the registered cap"
                        );
                        assert!(
                            *actual_bytes > *limit_bytes,
                            "the record refusal is past the cap"
                        );
                        assert!(
                            *actual_bytes <= profile.canonical,
                            "the record refusal fired inside the frame"
                        );
                    }
                    TransportDecodeError::ExpansionRatioExceeded { max_ratio } => {
                        assert_eq!(
                            *max_ratio, 100,
                            "the ratio guard refused at the registered cap"
                        );
                    }
                    other => panic!(
                        "the refusal is outside the two hard payload-limit \
                         classes: {other:?}"
                    ),
                }
                let code = error.code();
                let code = code.as_str();
                assert!(
                    code == "request.record_too_large"
                        || code == "request.expansion_ratio_exceeded",
                    "the refusal is a registered 413 payload-limit class, got {code}"
                );
            }
            StreamOutcome::Completed { .. } => {
                panic!("a refused stream completed past its payload limits");
            }
        }
    }
    assert_eq!(store.commits(), 0, "a refused stream publishes no object");
    assert_eq!(
        store.aborts(),
        16,
        "every refused session ends in the caller's abort"
    );
    assert_eq!(
        open.live_count(),
        0,
        "no refused session survives its abort"
    );
    elapsed
}

/// The Phase 4 profile run: admission, sixteen lawful worst-case streams,
/// sixteen refused streams, and the measured floors.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "the four-vCPU/512 MiB profile run; the module docs carry the invocation"]
async fn the_reference_profile_sustains_the_phase4_floors() {
    let config = ServerConfig::builder()
        .listen_address("127.0.0.1:0")
        .max_inflight_upload_count(16)
        .max_inflight_per_client_count(4)
        .rate_per_minute_count(60)
        .rate_burst_count(8)
        .build()
        .expect("the profile configuration validates");
    assert_eq!(
        config.request_deadline(),
        Duration::from_mins(15),
        "the profile's request deadline is the 15-minute default"
    );

    let (lawful, refused) = build_profile_frames();

    let gate = AdmissionGate::new(&config, Arc::new(ServerMetrics::new()));
    let (aggregate_mib_per_s, lawful_elapsed) = run_lawful_population(&gate, &config, lawful).await;
    // Phase 1's evidence prints before phase 2 runs, so a phase-2 failure
    // still records the lawful population's measured numbers.
    eprintln!("phase4.aggregate_mib_per_s = {aggregate_mib_per_s:.1}");
    eprintln!(
        "phase4.lawful_elapsed_s = {:.3}",
        lawful_elapsed.as_secs_f64()
    );

    let refused_elapsed = run_refused_population(&gate, &config, refused).await;

    // The floors, asserted against the measured run.
    let peak = peak_rss_kib();
    assert!(
        aggregate_mib_per_s >= AGGREGATE_FLOOR_MIB_PER_S,
        "aggregate canonicalization {aggregate_mib_per_s:.1} MiB/s is below the \
         {AGGREGATE_FLOOR_MIB_PER_S} MiB/s floor"
    );
    assert!(
        peak <= RSS_CEILING_KIB,
        "peak RSS {peak} KiB exceeds the {RSS_CEILING_KIB} KiB ceiling"
    );
    assert!(
        lawful_elapsed < config.request_deadline(),
        "the lawful population outlived the request deadline"
    );
    assert!(
        refused_elapsed < config.request_deadline(),
        "the refused population outlived the request deadline"
    );

    eprintln!(
        "phase4.refused_elapsed_s = {:.3}",
        refused_elapsed.as_secs_f64()
    );
    eprintln!("phase4.peak_rss_kib = {peak}");
}
