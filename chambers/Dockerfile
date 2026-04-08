# ---------------------------------------------------------
# Stage 1: Build the Chambers daemon from source
# ---------------------------------------------------------
FROM rust:1.78-bookworm AS builder

WORKDIR /build

# Copy workspace manifests first for layer caching
COPY Cargo.toml rust-toolchain.toml ./
COPY .cargo .cargo
COPY chambers-core/Cargo.toml chambers-core/Cargo.toml
COPY chambers-daemon/Cargo.toml chambers-daemon/Cargo.toml
COPY chambers-verify/Cargo.toml chambers-verify/Cargo.toml

# Create stub sources so cargo can resolve the workspace
RUN mkdir -p chambers-core/src chambers-daemon/src chambers-verify/src && \
    echo "fn main() {}" > chambers-daemon/src/main.rs && \
    echo "fn main() {}" > chambers-verify/src/main.rs && \
    touch chambers-core/src/lib.rs

# Pre-build dependencies (cached unless Cargo.toml changes)
RUN cargo build --release 2>/dev/null || true

# Copy actual source code
COPY chambers-core/src chambers-core/src
COPY chambers-daemon/src chambers-daemon/src
COPY chambers-verify/src chambers-verify/src

# Build the real binaries
RUN cargo build --release

# ---------------------------------------------------------
# Stage 2: Minimal runtime image
# ---------------------------------------------------------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3 \
        nftables \
        iproute2 \
        v4l-utils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/chambers-daemon /usr/local/bin/chambers-daemon
COPY --from=builder /build/target/release/chambers-verify /usr/local/bin/chambers-verify

RUN useradd --system --no-create-home chambers
USER chambers

ENTRYPOINT ["chambers-daemon"]
