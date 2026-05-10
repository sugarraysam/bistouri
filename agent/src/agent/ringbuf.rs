use super::profiler::METRIC_RINGBUF_POLL_ERRORS;
use crate::agent::error::{AgentError, Result};
use libbpf_rs::RingBuffer;
use std::os::fd::BorrowedFd;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::error;

const MAX_CONSUME_ERRORS: u32 = 3;
const METRIC_CONSUME_ERRORS: &str = "bistouri_profiler_consume_errors";

/// Async wrapper around `libbpf_rs::RingBuffer` that integrates with tokio's
/// IO reactor. Owns both the ring buffer (which holds the epoll fd) and the
/// `AsyncFd` registration, ensuring correct drop order.
///
/// Uses `&mut self` for async methods because `RingBuffer` holds `FnMut`
/// callbacks that are `!Sync`. `&mut T` only requires `T: Send` (not `Sync`)
/// to be `Send` across await points, which `RingBuffer` satisfies.
pub(crate) struct AsyncRingBuffer {
    ring_buffer: RingBuffer<'static>,
    async_fd: AsyncFd<BorrowedFd<'static>>,
}

impl AsyncRingBuffer {
    pub(crate) fn new(ring_buffer: RingBuffer<'static>) -> Result<Self> {
        let epoll_fd = ring_buffer.epoll_fd();

        // SAFETY: The epoll fd is owned by `ring_buffer` which lives inside this
        // struct. BorrowedFd does not close the fd on drop — RingBuffer remains
        // the sole owner. The 'static lifetime is valid because the fd lives as
        // long as the struct.
        let borrowed = unsafe { BorrowedFd::borrow_raw(epoll_fd) };
        let async_fd = AsyncFd::new(borrowed)
            .map_err(|e| AgentError::Io("failed to register ringbuf epoll fd".into(), e))?;

        Ok(Self {
            ring_buffer,
            async_fd,
        })
    }

    /// Runs the async polling loop until cancelled.
    ///
    /// Yields to tokio when no data is available, then drains all pending
    /// events via `consume()` when woken.
    ///
    /// On `consume()` failure: retries up to `MAX_CONSUME_ERRORS` consecutive
    /// times. If exhausted, aborts the process — the BPF event pipeline is
    /// irrecoverably broken and the agent cannot fulfill its purpose.
    ///
    /// On epoll error: aborts immediately — same rationale.
    pub(crate) async fn run(&mut self, cancel: CancellationToken) {
        let mut consecutive_errors: u32 = 0;

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = self.async_fd.readable() => {
                    match result {
                        Ok(mut guard) => {
                            match self.ring_buffer.consume() {
                                Ok(()) => {
                                    consecutive_errors = 0;
                                }
                                Err(e) => {
                                    consecutive_errors += 1;
                                    metrics::counter!(METRIC_CONSUME_ERRORS).increment(1);
                                    error!(
                                        error = %e,
                                        attempt = consecutive_errors,
                                        max = MAX_CONSUME_ERRORS,
                                        "ring buffer consume() failed — this indicates \
                                         a callback returned non-zero or an internal \
                                         libbpf error. Retrying.",
                                    );
                                    if consecutive_errors >= MAX_CONSUME_ERRORS {
                                        error!(
                                            "ring buffer consume() failed {} consecutive \
                                             times — BPF event pipeline is irrecoverably \
                                             broken. Aborting process.",
                                            MAX_CONSUME_ERRORS,
                                        );
                                        std::process::abort();
                                    }
                                }
                            }
                            guard.clear_ready();
                        }
                        Err(e) => {
                            error!(
                                error = %e,
                                "ringbuf epoll error — BPF event pipeline is \
                                 irrecoverably broken. Aborting process.",
                            );
                            metrics::counter!(METRIC_RINGBUF_POLL_ERRORS).increment(1);
                            std::process::abort();
                        }
                    }
                }
            }
        }
    }
}
