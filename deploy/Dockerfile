# The ZT-next controller.
#
# The Rust binaries are built in a builder stage, so the runtime image holds
# no toolchain. The build context is the repository root, so the whole
# workspace is copied in.

FROM rust:1-bookworm AS builder

WORKDIR /build

# Copy the manifests first, so dependency compilation is cached across
# source changes.
COPY Cargo.toml Cargo.lock ./
COPY crates/zt-crypto/Cargo.toml crates/zt-crypto/
COPY crates/zt-controller/Cargo.toml crates/zt-controller/
COPY crates/zt-agent/Cargo.toml crates/zt-agent/
COPY crates/zt-legacy/Cargo.toml crates/zt-legacy/
COPY crates/zt-node/Cargo.toml crates/zt-node/
COPY crates/zt-testvectors/Cargo.toml crates/zt-testvectors/

# A placeholder source, so the dependency layer can be built without the
# real sources present. The placeholder build is allowed to fail: the point
# is to compile the dependencies, not the crates.
#
# The target directory is kept, so the dependency compilation is reused by
# the real build below.
RUN mkdir -p crates/zt-crypto/src crates/zt-controller/src crates/zt-agent/src \
             crates/zt-legacy/src crates/zt-node/src crates/zt-testvectors/src \
 && echo "" > crates/zt-crypto/src/lib.rs \
 && echo "" > crates/zt-controller/src/lib.rs \
 && echo "" > crates/zt-agent/src/lib.rs \
 && echo "" > crates/zt-legacy/src/lib.rs \
 && echo "" > crates/zt-node/src/lib.rs \
 && echo "" > crates/zt-testvectors/src/lib.rs \
 && cargo build --release -p zt-controller -p zt-agent || true

# The real sources. The trailing slash matters: without it, Docker copies
# the directory itself into the destination, which already exists, and the
# sources land in crates/crates/ instead.
COPY crates/ crates/

# Cargo fingerprints the placeholder sources, and a fingerprint that is
# still current would make the build skip the crates. Touching the sources
# invalidates those fingerprints, so the crates are rebuilt against the
# dependencies that are already compiled.
RUN find crates -name "*.rs" -exec touch {} + \
 && cargo build --release -p zt-controller -p zt-agent \
 && mkdir -p /out \
 && cp target/release/zt-controller /out/ \
 && cp target/release/zt-agent /out/

FROM debian:bookworm-slim AS runtime

# The controller's health check uses wget.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates wget \
 && rm -rf /var/lib/apt/lists/*

# The service runs unprivileged.
RUN useradd --system --create-home --home-dir /var/lib/zt-next zt-next

COPY --from=builder /out/zt-controller /usr/local/bin/zt-controller
COPY --from=builder /out/zt-agent /usr/local/bin/zt-agent

RUN mkdir -p /var/lib/zt-next && chown -R zt-next:zt-next /var/lib/zt-next

USER zt-next
WORKDIR /var/lib/zt-next

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/zt-controller"]
