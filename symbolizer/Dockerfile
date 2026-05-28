# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS chef
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
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
    cargo chef cook --release --recipe-path recipe.json -p bistouri-symbolizer

COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    cargo build --release -p bistouri-symbolizer \
    && cp target/release/bistouri-symbolizer /app/bistouri-symbolizer

FROM debian:bookworm-slim
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates
WORKDIR /app
COPY --from=builder /app/bistouri-symbolizer .
ENTRYPOINT ["/app/bistouri-symbolizer"]
