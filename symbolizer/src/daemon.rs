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

use crate::resolve::cache::CachePool;
use crate::resolve::SessionResolver;
use crate::server::{ProcessingWorker, SymbolizerService};
use crate::sink::SessionSink;
use crate::telemetry::{
    METRIC_CACHE_CAPACITY_BYTES, METRIC_CACHE_ENTRY_COUNT, METRIC_CACHE_USAGE_BYTES,
    METRIC_NEGATIVE_CACHE_CAPACITY, METRIC_NEGATIVE_CACHE_ENTRIES,
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
    pub async fn start<S>(
        config: DaemonConfig,
        sink: Arc<S>,
        caches: CachePool,
    ) -> anyhow::Result<Self>
    where
        S: SessionSink + 'static + ?Sized,
    {
        let cancel = CancellationToken::new();

        // Record static cache capacity gauges + clone for periodic reporter
        // BEFORE moving `caches` into the resolver.
        record_cache_capacities(&caches);
        let gauge_caches = caches.clone();

        let resolver = Arc::new(SessionResolver::new(caches));

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
    gauge!(METRIC_NEGATIVE_CACHE_CAPACITY).set(caches.negative.max_capacity() as f64);
}

/// Periodically records cache usage gauges.
///
/// `future::Cache::run_pending_tasks()` is async — it performs moka's
/// deferred maintenance without blocking the tokio event loop.
/// `sync::Cache::run_pending_tasks()` (L2 symbol caches) is synchronous
/// but completes in microseconds and doesn't warrant `spawn_blocking`.
async fn cache_gauge_reporter(caches: CachePool, interval: Duration, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = ticker.tick() => {
                // Force moka's deferred maintenance before reading gauges.
                // Without this, weighted_size() can return stale values (even 0)
                // because moka batches bookkeeping into async maintenance tasks.
                caches.user_objects.run_pending_tasks().await;
                caches.kernel_objects.run_pending_tasks().await;
                caches.user_symbols.run_pending_tasks();
                caches.kernel_symbols.run_pending_tasks();

                // Snapshot all cache stats once per tick.
                let l1_user_bytes = caches.user_objects.weighted_size();
                let l1_user_entries = caches.user_objects.entry_count();
                let l1_kernel_bytes = caches.kernel_objects.weighted_size();
                let l1_kernel_entries = caches.kernel_objects.entry_count();
                let l2_user_bytes = caches.user_symbols.weighted_byte_usage();
                let l2_user_entries = caches.user_symbols.entry_count();
                let l2_kernel_bytes = caches.kernel_symbols.weighted_byte_usage();
                let l2_kernel_entries = caches.kernel_symbols.entry_count();
                let negative_entries = caches.negative.entry_count();

                // Record Prometheus gauges from the snapshot.
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l1", "space" => "user")
                    .set(l1_user_bytes as f64);
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l1", "space" => "kernel")
                    .set(l1_kernel_bytes as f64);
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l2", "space" => "user")
                    .set(l2_user_bytes as f64);
                gauge!(METRIC_CACHE_USAGE_BYTES, "tier" => "l2", "space" => "kernel")
                    .set(l2_kernel_bytes as f64);
                gauge!(METRIC_NEGATIVE_CACHE_ENTRIES).set(negative_entries as f64);
                gauge!(METRIC_CACHE_ENTRY_COUNT, "tier" => "l1", "space" => "user")
                    .set(l1_user_entries as f64);
                gauge!(METRIC_CACHE_ENTRY_COUNT, "tier" => "l1", "space" => "kernel")
                    .set(l1_kernel_entries as f64);
                gauge!(METRIC_CACHE_ENTRY_COUNT, "tier" => "l2", "space" => "user")
                    .set(l2_user_entries as f64);
                gauge!(METRIC_CACHE_ENTRY_COUNT, "tier" => "l2", "space" => "kernel")
                    .set(l2_kernel_entries as f64);

                // Periodic operational heartbeat — visible at info level in
                // kubectl logs. Emits once per gauge_interval (default 15s),
                // NOT per session. MiB values are emitted as raw f64 fields
                // to avoid per-tick format!() String allocations.
                let mib = 1024.0 * 1024.0;
                info!(
                    l1_user_mib = l1_user_bytes as f64 / mib,
                    l1_user_entries,
                    l1_kernel_mib = l1_kernel_bytes as f64 / mib,
                    l1_kernel_entries,
                    l2_user_mib = l2_user_bytes as f64 / mib,
                    l2_kernel_mib = l2_kernel_bytes as f64 / mib,
                    negative_entries,
                    "cache status"
                );
            }
        }
    }
}
