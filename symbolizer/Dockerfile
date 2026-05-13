# syntax=docker/dockerfile:1
# Multi-stage build for the bistouri-symbolizer binary.
#
# No kernel/eBPF dependencies — the symbolizer is pure user-space.
# Uses bookworm for glibc compatibility with addr2line and ELF parsing.

# ------------------------------------------------------------------------------
# Stage 1: Builder
# ------------------------------------------------------------------------------
FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

# Build the symbolizer binary.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p bistouri-symbolizer \
    && cp target/release/bistouri-symbolizer /app/bistouri-symbolizer

# ------------------------------------------------------------------------------
# Stage 2: Runtime
# ------------------------------------------------------------------------------
FROM debian:bookworm-slim

# ca-certificates is required by rustls-platform-verifier to initialize
# the TLS backend. Without it, reqwest's Client::builder().build() fails
# even for plain HTTP connections.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/bistouri-symbolizer .

ENTRYPOINT ["/app/bistouri-symbolizer"]
