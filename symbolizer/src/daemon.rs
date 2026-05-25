//! Top-level daemon lifecycle for the symbolizer service.
//!
//! `SymbolizerDaemon::start()` boots all subsystems, `shutdown()`
//! tears them down. `main()` is a thin CLI shim that calls both.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use metrics::gauge;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::info;

use crate::debuginfod::DebuginfodClient;
use crate::resolve::cache::CachePool;
use crate::resolve::SessionResolver;
use crate::server::{ProcessingWorker, SymbolizerService};
use crate::sink::SessionSink;
use crate::telemetry::{
    METRIC_CACHE_CAPACITY_BYTES, METRIC_CACHE_USAGE_BYTES, METRIC_NEGATIVE_CACHE_ENTRIES,
};

/// Default processing queue capacity.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

/// Default maximum concurrent session resolution tasks.
pub const DEFAULT_MAX_CONCURRENT_SESSIONS: usize = 16;

/// Default maximum concurrent debuginfod fetches during prefetch.
pub const DEFAULT_DEBUGINFOD_FETCH_CONCURRENCY: usize = 16;

/// Configuration for the symbolizer daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// gRPC listen address.
    pub listen_addr: SocketAddr,

    /// Processing queue capacity (pending sessions awaiting dispatch).
    ///
    /// When the queue is full, `ReportSession` returns `RESOURCE_EXHAUSTED`
    /// instead of blocking.
    pub queue_capacity: usize,

    /// Maximum number of sessions resolved + stored concurrently.
    ///
    /// Controls the semaphore that bounds parallel `tokio::spawn` tasks.
    /// Independent of `queue_capacity` — one controls buffer depth, the
    /// other controls parallelism.
    pub max_concurrent_sessions: usize,

    /// Maximum number of concurrent debuginfod fetches during prefetch.
    pub debuginfod_fetch_concurrency: usize,

    /// Interval in seconds for reporting cache gauge metrics.
    ///
    /// Should match your Prometheus scrape interval.
    pub gauge_interval_secs: u64,
}

/// Top-level lifecycle manager for the symbolizer service.
///
/// Owns a `CancellationToken` for coordinated shutdown and handles for
/// both the gRPC server and the background processing worker.
pub struct SymbolizerDaemon {
    cancel: CancellationToken,
    server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
    worker: ProcessingWorker,
    gauge_handle: JoinHandle<()>,
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

        // Record static cache capacity gauges + clone for periodic reporter
        // BEFORE moving `caches` into the resolver.
        record_cache_capacities(&caches);
        let gauge_caches = caches.clone();

        let resolver = Arc::new(SessionResolver::new(
            caches,
            client,
            config.debuginfod_fetch_concurrency,
        ));

        info!(
            queue_capacity = config.queue_capacity,
            max_concurrent = config.max_concurrent_sessions,
            gauge_interval_secs = config.gauge_interval_secs,
            "processing pipeline configured"
        );

        // Spawn the dispatcher + worker pool. Returns the sender half
        // that the gRPC service uses to enqueue payloads.
        let (tx, worker) = ProcessingWorker::spawn(
            resolver,
            sink,
            config.queue_capacity,
            config.max_concurrent_sessions,
        );

        let service = SymbolizerService::new(tx);

        // Spawn periodic cache gauge reporter.
        let gauge_interval = Duration::from_secs(config.gauge_interval_secs.max(1));
        let gauge_cancel = cancel.clone();
        let gauge_handle = tokio::spawn(async move {
            cache_gauge_reporter(gauge_caches, gauge_interval, gauge_cancel).await;
        });

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
            gauge_handle,
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
        let _ = self.gauge_handle.await;
        info!("symbolizer daemon shutdown complete");
    }
}

/// Records static cache capacity gauges (called once at startup).
fn record_cache_capacities(caches: &CachePool) {
    gauge!(METRIC_CACHE_CAPACITY_BYTES, "tier" => "l1", "space" => "user")
        .set(caches.user_objects.max_capacity_bytes() as f64);
    gauge!(METRIC_CACHE_CAPACITY_BYTES, "tier" => "l1", "space" => "kernel")
        .set(caches.kernel_objects.max_capacity_bytes() as f64);
    gauge!(METRIC_CACHE_CAPACITY_BYTES, "tier" => "l2", "space" => "user")
        .set(caches.user_symbols.budget_bytes() as f64);
    gauge!(METRIC_CACHE_CAPACITY_BYTES, "tier" => "l2", "space" => "kernel")
        .set(caches.kernel_symbols.budget_bytes() as f64);
}

/// Periodically records cache usage gauges.
async fn cache_gauge_reporter(caches: CachePool, interval: Duration, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                // L1 object caches: moka weighted_size() returns actual bytes.
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l1", "space" => "user")
                    .set(caches.user_objects.weighted_size() as f64);
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l1", "space" => "kernel")
                    .set(caches.kernel_objects.weighted_size() as f64);

                // L2 symbol caches: estimated byte usage.
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l2", "space" => "user")
                    .set(caches.user_symbols.estimated_byte_usage() as f64);
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l2", "space" => "kernel")
                    .set(caches.kernel_symbols.estimated_byte_usage() as f64);

                // Negative cache entry count.
                gauge!(METRIC_NEGATIVE_CACHE_ENTRIES)
                    .set(caches.negative.entry_count() as f64);
            }
        }
    }
}
