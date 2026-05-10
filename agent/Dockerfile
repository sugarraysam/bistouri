# syntax=docker/dockerfile:1
# We use a multi-stage build to keep the final image as lightweight as possible.

# ------------------------------------------------------------------------------
# Stage 1: Builder
# ------------------------------------------------------------------------------
# We use the rust bookworm image to ensure glibc compatibility with the runtime stage.
FROM rust:1-bookworm AS builder

# Install eBPF and C compilation dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    make \
    pkg-config \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# libbpf-cargo requires rustfmt to format the generated skeleton
RUN rustup component add rustfmt

# Set up the working directory
WORKDIR /app

# Copy the actual source code
COPY . .

# Build the Rust application using BuildKit cache mounts.
# This caches the cargo registry and target directory, making subsequent builds blazingly fast.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p bistouri-agent \
    # Copy the compiled binary out of the cached target directory so it can be picked up by the next stage
    && cp target/release/bistouri-agent /app/bistouri-agent

# ------------------------------------------------------------------------------
# Stage 2: Runtime
# ------------------------------------------------------------------------------
# We use the bookworm-slim image for runtime. It provides glibc and minimal tools.
FROM debian:bookworm-slim

# Install runtime libraries required by libbpf dynamically
RUN apt-get update && apt-get install -y \
    libelf1 \
    zlib1g \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/bistouri-agent .

# Set the default executable
ENTRYPOINT ["/app/bistouri-agent"]
