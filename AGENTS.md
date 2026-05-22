# AI Agent Guidelines for Bistouri

You are assisting with Bistouri, an eBPF-based profiling agent written
in Rust and C. **Assume this is a standalone project.**

## Architecture

- **Agent (`agent/`)**: eBPF daemon capturing stack traces via PSI
  triggers. Uses `tokio` and `libbpf-rs`. eBPF code is C.
- **Shared API (`api/`)**: gRPC/Protobuf definitions.
- **Symbolizer (`symbolizer/`)**: Centralized service for cross-host
  resolution.

## Strict Coding Constraints

### Rust (Performance & Memory)

- **Zero-Allocation Hot Paths**: Avoid `clone()`, `format!()`, and
  implicit copies. Favor borrowing and strict lifetimes.
- **Capacity Planning**: Use `with_capacity` universally when
  initializing `Vec`, `HashMap`, etc.
- **Static over Dynamic**: Prefer static dispatch with generics
  (`impl Trait`) over `dyn Trait` to avoid vtable penalties.
- **Async**: Use `#[async_trait::async_trait]`. Never block the `tokio`
  event loop. Offload `/proc` walks or parsing to
  `tokio::task::spawn_blocking`.
- **Testing**: Use `rstest` table-tests for parameterized edge cases.
  Keep coverage high.

### eBPF & Kernel (C & Rust integration)

- **Verifier Safe**: BPF code must have bounded loops and avoid complex
  branching.
- **Layout Parity**: Shared C/Rust structs MUST use `#[repr(C)]` in
  Rust.
- **Map Streaming**: Use BPF ring buffers over perf buffers for
  high-throughput events.
- **Naming Limits**: Never use the `bpf_` prefix for user-space types;
  it is reserved for Linux kernel BPF helpers.

## OSS Workflow & Building

This project is built using Make and Cargo natively.

- Run `make ci` from the root to execute formatting, clippy, and tests.
- Run `make -C agent <target>` for agent-specific tasks (e.g.,
  docker-build).
- **All code must pass `make ci` before completion.**

> **Monorepo Note**: If working inside the Ringbuffer monorepo, the root
> `AGENTS.md` takes precedence for tooling and execution. Use
> `moon run bistouri:<task>` instead of `make`.
