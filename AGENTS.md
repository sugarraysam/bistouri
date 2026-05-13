# AI Agent Context & Guidelines for Bistouri

Welcome! You are assisting with Bistouri, a workspace containing an
eBPF-based profiling agent written in Rust and a centralized symbolizer
service.

## Project Goal

The goal of Bistouri is to capture stack traces from Linux processes
dynamically, triggered by Pressure Stall Information (PSI) events
(Memory, CPU, IO). These captured stack traces are sent to a centralized
symbolizer service for cross-host symbol resolution.

## Workspace Structure

- `agent/`: The eBPF profiling agent daemon. Requires Linux kernel
  headers and libbpf at build time.
- `api/`: Shared gRPC/Protobuf definitions consumed by both agent and
  symbolizer. No platform-specific dependencies.
- `symbolizer/`: The centralized symbolizer service (downstream consumer
  of agent payloads). No kernel dependencies.

## Architecture & Tech Stack

- User Space: Rust, using tokio for async operations and libbpf-rs for
  interacting with the eBPF subsystem (agent only).
- Kernel Space (eBPF): C, compiled to eBPF byte-code using libbpf-cargo
  (agent only).
- Network: gRPC (tonic) for agent → symbolizer communication, with
  Protobuf schemas defined in the `api/` crate.

## Coding Rules & Guidelines

### 1. Rust Best Practices

- Idiomatic Code: Use modern Rust idioms. Leverage the type system to
  enforce state transitions and invariants.
- Clean Code: Let the code speak for itself by using descriptive names.
  Keep comments light; only use them where design choices are made or to
  explain tradeoffs.
- Modularity & Traits: Try to use Rust `trait`s wherever possible to make the
  code modular and to allow reimplementing modules where it makes sense. However,
  use them conservatively and only for important modules and functionalities
  where future extensibility is very likely.
- Interfaces & Boundaries: Use the `todo!()` macro where interface boundaries are
  drawn. It is acceptable to not finish the implementation of something, as we
  do modular bite-sized changes. When a boundary is reached, add a `todo!()`
  to finish it later.
- Clippy Checks: All code must pass cargo clippy without warnings. Fix
  clippy lints as part of the development process.
- Error Handling: Use thiserror for error handling. It is idiomatic for
  each module to express and declare the specific errors they own,
  rather than using a generic anyhow::Result everywhere. Propagate
  errors using ? when appropriate.
- Async: Use tokio for any I/O bound operations. Avoid blocking the
  async runtime.
- Safety: Minimize the use of unsafe. When unsafe is strictly required
  (often the case when dealing with raw pointers from libbpf-rs or
  libc), strictly document the safety invariants being upheld.
- Testing: Favor the `rstest` crate with the table-test pattern
  (`#[rstest]` + `#[case]`) for parametrized tests. This makes it
  trivial to add coverage for newly discovered edge cases — just add a
  new `#[case]` line. Use standalone `#[test]` only for complex
  lifecycle tests that don't fit a table structure.
- Allocation Discipline: Avoid unnecessary heap allocations on hot paths.
  Do not call `.clone()`, `.to_string()`, or `format!()` unless strictly
  required by an API boundary. Prefer borrowing (`&str` over `String`,
  `&[T]` over `Vec<T>`) and use `Copy` types where possible. When a
  value must be moved into a consuming call, read any fields needed for
  logging/error context from the result of that call rather than cloning
  them beforehand.
- Units in Names: Variables, struct fields, CLI flags, and environment
  variables that carry dimensional values must include the unit as a
  suffix (e.g. `timeout_secs`, `budget_bytes`, `capacity_entries`,
  `interval_ms`). This makes the expected unit self-documenting and
  prevents callers from passing the wrong magnitude.

### 2. eBPF Specific Guidelines (agent/ crate only)

- eBPF Verifier: Keep eBPF programs simple to satisfy the Linux kernel
  verifier. Avoid unbound loops and ensure memory accesses are
  bounds-checked.
- Shared Data Structures: Any struct shared between the eBPF C code and
  the Rust user-space code MUST have an identical layout. Use
  `#[repr(C)]` in Rust.
- Map Interactions: Prefer eBPF ring buffers over perf buffers for
  high-throughput event streaming from kernel to user-space.
- Naming: The `bpf_` prefix is reserved for Linux kernel BPF helper
  functions (e.g. `bpf_get_current_pid_tgid`, `bpf_ringbuf_reserve`).
  Never use it for user-space types, map names, or variables. Use
  descriptive domain names instead (e.g. `stack_trace_event` not
  `bpf_perf_event`).

### 3. Workflow & Building

- The workspace is built from the repository root via `make ci`, which
  runs `cargo fmt`, `cargo clippy`, and `cargo test` across all crates.
- Agent-specific targets (docker-build, integration-tests) live in
  `agent/Makefile` and are invoked via `make -C agent <target>`.
- EBPF compilation is integrated into `agent/build.rs` via libbpf-cargo.
- Running the agent binary requires root privileges (or appropriate
  capabilities like `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`) to load
  eBPF programs into the kernel.
- Make Checks: All code modifications must pass `make ci` from the
  workspace root.

### 4. Eventual Consistency

Bistouri operates under an eventual consistency model. During
transient operations like config reloads, brief windows may exist
where stale BPF events are generated or PSI watchers are temporarily
absent. The system is designed to converge to the correct state within
one proc_walk cycle. User-space filtering ensures no stale events
produce incorrect side effects.

### 5. Event Loop Protection

The tokio event loop must never be blocked by CPU-heavy or I/O-bound
synchronous work. Use `tokio::task::spawn_blocking` for operations
like file parsing, /proc walking, or any computation that may take
more than a trivial amount of time. Keep the event loop crisp and
responsive to async events (PSI triggers, inotify, channels).
