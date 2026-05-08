use super::profiler::METRIC_RINGBUF_POLL_ERRORS;
use crate::agent::error::{AgentError, Result};
use libbpf_rs::RingBuffer;
use std::os::fd::BorrowedFd;
use tokio::io::unix::AsyncFd;
use tokio_util::sync::CancellationToken;
use tracing::error;

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
    /// events via `consume()` when woken. On epoll error, increments a
    /// Prometheus counter and exits — the agent continues in degraded state
    /// (PSI watchers and config reloads still function, but no new BPF events
    /// are processed).
    pub(crate) async fn run(&mut self, cancel: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                result = self.async_fd.readable() => {
                    match result {
                        Ok(mut guard) => {
                            self.ring_buffer.consume().unwrap_or(());
                            guard.clear_ready();
                        }
                        Err(e) => {
                            error!(error = %e, "ringbuf epoll error, polling stopped");
                            metrics::counter!(METRIC_RINGBUF_POLL_ERRORS).increment(1);
                            break;
                        }
                    }
                }
            }
        }
    }
}
