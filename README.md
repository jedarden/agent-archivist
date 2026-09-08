# Agent Archivist

Agent Archivist is a design-stage, open system for collecting complete coding-agent
session histories from many hosts into S3-compatible object storage.

The intended system has two deliberately small halves:

- a host client discovers and incrementally uploads transcripts from supported
  agent harnesses; and
- a stateless ingestion service authenticates linked clients, validates payloads,
  and writes content-addressed blobs and provenance records to object storage.

S3 is the durable source of truth. ARMOR can provide the S3-compatible encrypted
storage path for a deployment, but it is an integration rather than a requirement.
AWS S3, Backblaze B2, MinIO, Garage, and other compatible implementations should
be usable through the same storage contract.

This repository is intentionally code-free at first. It records the architecture
before the private, deployment-specific prototype is generalized. It contains no
transcripts, credentials, infrastructure inventory, or history copied from that
prototype.

## Documents

- [Research findings](docs/research/transcript-archiving-findings.md) explains
  the observations and architectural conclusions behind the design.
- [System requirements](docs/notes/requirements.md) defines the normative
  behavior expected from the public implementation.

## Design principles

1. Capture all durable agent sessions, not only sessions launched by an
   orchestrator.
2. Preserve original bytes and provenance independently.
3. Make retries harmless through deterministic object identity.
4. Keep ingestion replicas stateless and replaceable.
5. Give clients no general-purpose object-store write access.
6. Treat raw transcripts as sensitive, untrusted data.
7. Keep storage and protocols open, versioned, and vendor-neutral.

## Status

Architecture and requirements are being established. No production-ready client
or server is included yet.

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE).
