# AI Agent Context & Guidelines for Bistouri

Welcome! You are assisting with Bistouri, an eBPF-based profiling agent written in Rust.

## Project Goal
The goal of Bistouri is to capture stack traces from Linux processes dynamically, triggered by Pressure Stall Information (PSI) events (Memory, CPU, IO). These captured stack traces are eventually sent to an external symbolizer service for analysis.

## Architecture & Tech Stack
- User Space: Rust, using tokio for async operations and libbpf-rs for interacting with the eBPF subsystem.
- Kernel Space (eBPF): C, compiled to eBPF byte-code using libbpf-cargo. 
- Key Dependencies:
  - libbpf-rs & libbpf-cargo for eBPF lifecycle and compilation.
  - tokio for the asynchronous runtime.
  - thiserror for strict, idiomatic error handling.
  - perf-event and libc for system-level interactions.
  - vmlinux.h (generated) for kernel types.

## Directory Structure
- src/agent/: Rust user-space code. Contains the main logic for polling PSI events, loading eBPF programs, reading maps/ring-buffers, and communicating with the symbolizer.
- src/bpf/: C source code for the eBPF programs (e.g., profiler.bpf.c, profiler.h).
- build.rs: Cargo build script, heavily utilized by libbpf-cargo to compile the eBPF source into skeletons.

## Coding Rules & Guidelines

### 1. Rust Best Practices
- Idiomatic Code: Use modern Rust idioms. Leverage the type system to enforce state transitions and invariants.
- Clippy Checks: All code must pass cargo clippy without warnings. Fix clippy lints as part of the development process.
- Error Handling: Use thiserror for error handling. It is idiomatic for each module to express and declare the specific errors they own, rather than using a generic anyhow::Result everywhere. Propagate errors using ? when appropriate.
- Async: Use tokio for any I/O bound operations. Avoid blocking the async runtime.
- Safety: Minimize the use of unsafe. When unsafe is strictly required (often the case when dealing with raw pointers from libbpf-rs or libc), strictly document the safety invariants being upheld.

### 2. eBPF Specific Guidelines
- eBPF Verifier: Keep eBPF programs simple to satisfy the Linux kernel verifier. Avoid unbound loops and ensure memory accesses are bounds-checked.
- Shared Data Structures: Any struct shared between the eBPF C code and the Rust user-space code MUST have an identical layout. Use #[repr(C)] in Rust.
- Map Interactions: Prefer eBPF ring buffers over perf buffers for high-throughput event streaming from kernel to user-space.

### 3. Workflow & Building
- EBPF compilation is integrated into cargo build via build.rs and libbpf-cargo.
- Running the resulting binary requires root privileges (or appropriate capabilities like CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON) to load eBPF programs into the kernel.

## Common Tasks for this Project
- Wiring up Linux PSI event polling using poll() or epoll via libc or tokio.
- Emitting stack traces from eBPF using bpf_get_stackid or bpf_get_stack.
- Processing ring buffer events in Rust asynchronously.
- Batching and sending stack traces to a gRPC/HTTP symbolizer service.
