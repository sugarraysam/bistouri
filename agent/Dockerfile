# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS chef

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libelf-dev \
        zlib1g-dev \
        make \
        pkg-config \
        protobuf-compiler \
        libprotobuf-dev

RUN cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
# Ensure the Cargo config file containing compiler flags is copied
# before cargo chef cook runs, so dependencies are built with correct flags
COPY .cargo /app/.cargo
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo chef cook --release --recipe-path recipe.json -p bistouri-agent

COPY . .
RUN rustup component add rustfmt
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release -p bistouri-agent \
    && cp target/release/bistouri-agent /app/bistouri-agent

FROM debian:bookworm-slim
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        libelf1 \
        zlib1g

WORKDIR /app
COPY --from=builder /app/bistouri-agent .
ENTRYPOINT ["/app/bistouri-agent"]
