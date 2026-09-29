# Synthetic `redaction-v1` leak corpus

This directory is an immutable, synthetic input corpus for the complete
redaction-v1 path. `corpus.json` deliberately contains detector-shaped test
material as fragmented content parts; the integration test joins those parts
only in memory, so no credential-shaped value is persisted or secret-scanned.

The integration test in
`crates/archivist-protocol/tests/redaction_v1_corpus.rs` verifies the corpus
manifest before constructing any `SourceRecord`. It then runs the complete
pipeline, including episode composition, and checks that episode bytes,
episode digests, and content-free coverage gaps are stable across repeated
runs. The test also proves that raw fixture values and reversible-map-shaped
members do not cross into an episode, gap, evidence digest, or persisted
serialization.

The `full-sweep` case exercises all four allowlisted structured fields, all
ten detectors, the credential/header, private-key/environment, path/entropy,
and hostname/email/username precedence overlaps, all typed marker classes,
all tenant-HMAC pseudonym classes, and repeated pseudonym stability. The
bounded cases are generated from explicit counts in the corpus so the checked
in file stays small while the resource limits remain exercised.
