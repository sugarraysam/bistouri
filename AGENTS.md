# AI Agent Context & Guidelines for Bistouri

Welcome! You are assisting with Bistouri, an eBPF-based profiling agent
written in Rust.

## Project Goal

The goal of Bistouri is to capture stack traces from Linux processes
dynamically, triggered by Pressure Stall Information (PSI) events
(Memory, CPU, IO). These captured stack traces are eventually sent to an
external symbolizer service for analysis.

## Architecture & Tech Stack

- User Space: Rust, using tokio for async operations and libbpf-rs for
  interacting with the eBPF subsystem.
- Kernel Space (eBPF): C, compiled to eBPF byte-code using libbpf-cargo.

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

### 2. eBPF Specific Guidelines

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

- EBPF compilation is integrated into cargo build via build.rs and
  libbpf-cargo.
- Running the resulting binary requires root privileges (or appropriate
  capabilities like `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_PERFMON`) to load
  eBPF programs into the kernel.
- Make Checks: All code modifications must pass the `make` command,
  which runs `cargo fmt`, `cargo clippy`, and other essential validation
  steps.

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
