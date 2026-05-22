//! Top-level daemon lifecycle for the symbolizer service.
//!
//! `SymbolizerDaemon::start()` boots all subsystems, `shutdown()`
//! tears them down. `main()` is a thin CLI shim that calls both.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::info;

use crate::debuginfod::DebuginfodClient;
use crate::resolve::cache::CachePool;
use crate::resolve::SessionResolver;
use crate::server::{
    ProcessingWorker, SymbolizerService, DEFAULT_MAX_CONCURRENT_SESSIONS, DEFAULT_QUEUE_CAPACITY,
};
use crate::sink::SessionSink;

/// Configuration for the symbolizer daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// gRPC listen address.
    pub listen_addr: SocketAddr,

    /// Processing queue capacity (pending sessions awaiting dispatch).
    ///
    /// When the queue is full, `ReportSession` returns `RESOURCE_EXHAUSTED`
    /// instead of blocking. Defaults to [`DEFAULT_QUEUE_CAPACITY`] (1024).
    pub queue_capacity: usize,

    /// Maximum number of sessions resolved + stored concurrently.
    ///
    /// Controls the semaphore that bounds parallel `tokio::spawn` tasks.
    /// Independent of `queue_capacity` — one controls buffer depth, the
    /// other controls parallelism.
    ///
    /// Defaults to [`DEFAULT_MAX_CONCURRENT_SESSIONS`] (16).
    pub max_concurrent_sessions: usize,
}

impl DaemonConfig {
    fn effective_queue_capacity(&self) -> usize {
        if self.queue_capacity == 0 {
            DEFAULT_QUEUE_CAPACITY
        } else {
            self.queue_capacity
        }
    }

    fn effective_max_concurrent(&self) -> usize {
        if self.max_concurrent_sessions == 0 {
            DEFAULT_MAX_CONCURRENT_SESSIONS
        } else {
            self.max_concurrent_sessions
        }
    }
}

/// Top-level lifecycle manager for the symbolizer service.
///
/// Owns a `CancellationToken` for coordinated shutdown and handles for
/// both the gRPC server and the background processing worker.
pub struct SymbolizerDaemon {
    cancel: CancellationToken,
    server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
    worker: ProcessingWorker,
}

impl SymbolizerDaemon {
    /// Boots the symbolizer service and starts serving gRPC requests.
    ///
    /// Returns immediately with a running daemon. Call `shutdown()` to
    /// stop the server gracefully.
    pub async fn start<C, S>(
        config: DaemonConfig,
        client: Arc<C>,
        sink: Arc<S>,
        caches: CachePool,
    ) -> anyhow::Result<Self>
    where
        C: DebuginfodClient + 'static,
        S: SessionSink + 'static + ?Sized,
    {
        let cancel = CancellationToken::new();

        let resolver = Arc::new(SessionResolver::new(caches, client));

        let queue_capacity = config.effective_queue_capacity();
        let max_concurrent = config.effective_max_concurrent();
        info!(
            queue_capacity,
            max_concurrent, "processing pipeline configured"
        );

        // Spawn the dispatcher + worker pool. Returns the sender half
        // that the gRPC service uses to enqueue payloads.
        let (tx, worker) = ProcessingWorker::spawn(resolver, sink, queue_capacity, max_concurrent);

        let service = SymbolizerService::new(tx);

        let addr = config.listen_addr;
        info!(addr = %addr, "gRPC server listening");

        let signal = cancel.clone();
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(
                    bistouri_api::v1::capture_service_server::CaptureServiceServer::new(service),
                )
                .serve_with_shutdown(addr, async move {
                    signal.cancelled().await;
                })
                .await
        });

        Ok(Self {
            cancel,
            server_handle,
            worker,
        })
    }

    /// Shuts down the gRPC server and background processing gracefully.
    ///
    /// 1. Cancel the gRPC server (stop accepting new connections).
    ///    This drops the `SymbolizerService` which holds the only
    ///    `mpsc::Sender` clone — the dispatcher sees channel-closed.
    /// 2. Wait for the dispatcher to drain remaining items and all
    ///    in-flight tasks to complete.
    pub async fn shutdown(self) {
        // Stop accepting new RPCs — drops the service and its Sender.
        self.cancel.cancel();
        let _ = self.server_handle.await;

        // Drain remaining queued sessions + wait for in-flight tasks.
        self.worker.join().await;
        info!("symbolizer daemon shutdown complete");
    }
}
