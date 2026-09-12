# Agent Archivist release image.
#
# The versioning and reproducibility contract is
# docs/notes/release-container.md; tools/check-release-container.py (fast
# lane of scripts/definition-of-done.sh) rejects a Dockerfile or VERSION
# file that violates it. The canonical build — digest-reproducible — pins
# the image clock to the commit being built and disables build
# attestations (matching the kaniko release workflow, which emits none):
#
#   export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)"
#   docker build --provenance=false --sbom=false \
#     -f containers/agent-archivist/Dockerfile \
#     --build-arg AGENT_ARCHIVIST_VERSION="$(cat containers/agent-archivist/VERSION)" \
#     --build-arg SOURCE_DATE_EPOCH \
#     --tag ronaldraygun/agent-archivist:"$(cat containers/agent-archivist/VERSION)" \
#     .
#
# Both bases are digest-pinned: the digest is the pin, and the tag only
# documents what it is. Moving a base is a reviewed change that updates the
# digest and reruns the gate in the same commit (RC-011).

# Build stage. The tag pins the exact toolchain channel of
# rust-toolchain.toml (1.97.1): inside the container the image, not a
# rustup download, is the toolchain — which is why rust-toolchain.toml is
# deliberately not COPYied into the stage. The workspace is dependency-free,
# so --offline also means the build performs no crate-network access; the
# first external dependency lands with vendored sources and a same-commit
# update to this stage (RC-012, RC-014). The binary's mode and mtime are
# pinned (RC-018) so the runtime layer that consumes it is a function of
# its content, not of when the build ran.
FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS builder
ARG SOURCE_DATE_EPOCH
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --frozen --offline --bin archivist \
 && chmod 0555 target/release/archivist \
 && touch --date="@${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set}" \
      target/release/archivist

# Runtime stage: the pinned base plus the release binary, nothing else —
# no package installs, one new layer. The binary is bind-mounted
# read-only out of the builder stage and installed by a RUN (RC-015): a
# plain COPY --from=builder cannot produce a reproducible layer, because
# writing a file into /usr/local/bin updates that directory's mtime to
# the copy moment and the layer tar records it — two builds of identical
# content would ship two digests. The RUN therefore pins to
# SOURCE_DATE_EPOCH (RC-018) the binary AND every directory the step
# stamps with a wall-clock mtime: its parent /usr/local/bin (the cp), and
# /tmp plus /etc — the bind mount creates its target under /tmp, and the
# mount machinery itself touches /etc, and both dir mtimes land in the
# layer diff. With those four paths pinned the layer is a function of
# content alone, which the double-build digest comparison verifies. The
# image runs as a fixed numeric non-root UID (the distroless nonroot
# convention), which needs no passwd entry (RC-017). The version label is
# injected from the VERSION file content by the builder, and the binary
# itself carries only the package version compiled in from Cargo.toml
# (RC-016).
FROM debian:12.15-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime
ARG AGENT_ARCHIVIST_VERSION
ARG SOURCE_DATE_EPOCH
LABEL org.opencontainers.image.title="Agent Archivist" \
      org.opencontainers.image.description="Collects coding-agent session histories into S3-compatible object storage" \
      org.opencontainers.image.source="https://git.ardenone.com/jedarden/agent-archivist" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${AGENT_ARCHIVIST_VERSION}"
RUN --mount=type=bind,from=builder,source=/build/target/release/archivist,ro,target=/tmp/archivist \
    cp /tmp/archivist /usr/local/bin/archivist \
 && chmod 0555 /usr/local/bin/archivist \
 && touch --date="@${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH must be set}" \
      /usr/local/bin/archivist /usr/local/bin /etc /tmp
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/archivist"]
