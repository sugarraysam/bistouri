//! Shared CLI arguments for any binary embedding the symbolizer daemon.
//!
//! Use `#[command(flatten)]` to embed [`CommonArgs`] into your binary's
//! `Args` struct. This is the single source of truth for all symbolizer
//! daemon configuration — no duplication, no skew.
//!
//! ```ignore
//! use bistouri_symbolizer::cli::CommonArgs;
//!
//! #[derive(clap::Parser)]
//! struct Args {
//!     #[command(flatten)]
//!     common: CommonArgs,
//!
//!     // Your binary-specific args...
//!     #[arg(long, env = "CLICKHOUSE_URL")]
//!     clickhouse_url: String,
//! }
//! ```

use std::path::PathBuf;
use std::time::Duration;

use crate::daemon::{
    DaemonConfig, DEFAULT_DEBUGINFOD_FETCH_CONCURRENCY, DEFAULT_MAX_CONCURRENT_SESSIONS,
    DEFAULT_QUEUE_CAPACITY,
};
use crate::resolve::cache::{CachePool, NegativeCache, ObjectCache, SymbolCache};

/// Thin wrapper around [`parse_size::parse_size`] for clap `value_parser` compatibility.
///
/// `parse_size::parse_size` is generic over `impl AsRef<str>`, producing a
/// monomorphized function that doesn't satisfy clap's `for<'a> Fn(&'a str)`
/// higher-ranked lifetime bound. This concrete wrapper fixes the lifetime.
fn parse_memory_size(s: &str) -> Result<u64, parse_size::Error> {
    parse_size::parse_size(s)
}

/// Shared CLI arguments for the symbolizer daemon.
///
/// Embed in your binary's `Args` via `#[command(flatten)]`.
/// All fields have sensible defaults and respect env vars.
#[derive(clap::Args, Debug, Clone)]
pub struct CommonArgs {
    /// gRPC listen address.
    #[arg(long, default_value = "0.0.0.0:50051", env = "SYMBOLIZER_LISTEN_ADDR")]
    pub listen_addr: String,

    /// Prometheus metrics port.
    #[arg(long, default_value_t = 9091, env = "SYMBOLIZER_METRICS_PORT")]
    pub metrics_port: u16,

    /// Debuginfod server URL.
    #[arg(long, default_value = "http://localhost:8002", env = "DEBUGINFOD_URL")]
    pub debuginfod_url: String,

    /// Local debuginfod cache directory (shared volume).
    /// If set, artifacts are read from disk before falling back to HTTP.
    #[arg(long, env = "DEBUGINFOD_CACHE_PATH")]
    pub debuginfod_cache_path: Option<PathBuf>,

    /// Byte budget for user-space object cache (L1).
    /// Default: 256 MiB — fits ~15–250 typical user-space debuginfo objects.
    #[arg(
        long,
        default_value = "256MiB",
        env = "SYMBOLIZER_USER_OBJECT_BUDGET_BYTES",
        value_parser = parse_memory_size
    )]
    pub user_object_budget_bytes: u64,

    /// Byte budget for kernel object cache (L1).
    /// Default: 512 MiB — guarantees at least one vmlinux (200–400 MB)
    /// plus headroom for kernel modules.
    #[arg(
        long,
        default_value = "512MiB",
        env = "SYMBOLIZER_KERNEL_OBJECT_BUDGET_BYTES",
        value_parser = parse_memory_size
    )]
    pub kernel_object_budget_bytes: u64,

    /// Byte budget for user symbol cache (L2).
    /// Internally divided by 256 bytes/entry to compute entry count.
    /// (Key: 28B + Arc<ResolvedFrame>: ~152B + moka overhead: ~64B = ~256B/entry)
    #[arg(
        long,
        default_value = "128MiB",
        env = "SYMBOLIZER_USER_SYMBOL_BUDGET_BYTES",
        value_parser = parse_memory_size
    )]
    pub user_symbol_budget_bytes: u64,

    /// Byte budget for kernel symbol cache (L2).
    /// Internally divided by 256 bytes/entry to compute entry count.
    /// (Key: 28B + Arc<ResolvedFrame>: ~152B + moka overhead: ~64B = ~256B/entry)
    #[arg(
        long,
        default_value = "128MiB",
        env = "SYMBOLIZER_KERNEL_SYMBOL_BUDGET_BYTES",
        value_parser = parse_memory_size
    )]
    pub kernel_symbol_budget_bytes: u64,

    /// Maximum number of negative cache entries (404'd build IDs).
    #[arg(
        long,
        default_value_t = 4096,
        env = "SYMBOLIZER_NEGATIVE_CACHE_ENTRIES"
    )]
    pub negative_cache_entries: u64,

    /// Negative cache TTL in seconds.
    #[arg(long, default_value_t = 300, env = "SYMBOLIZER_NEGATIVE_TTL_SECS")]
    pub negative_ttl_secs: u64,

    /// Log level filter (e.g. "info", "bistouri_symbolizer=debug").
    /// Falls back to RUST_LOG env var, then "info".
    #[arg(long, env = "RUST_LOG")]
    pub log_level: Option<String>,

    /// Processing queue capacity.
    #[arg(
        long,
        default_value_t = DEFAULT_QUEUE_CAPACITY,
        env = "SYMBOLIZER_QUEUE_CAPACITY"
    )]
    pub queue_capacity: usize,

    /// Maximum number of sessions resolved + stored concurrently.
    #[arg(
        long,
        default_value_t = DEFAULT_MAX_CONCURRENT_SESSIONS,
        env = "SYMBOLIZER_MAX_CONCURRENT_SESSIONS"
    )]
    pub max_concurrent_sessions: usize,

    /// Maximum number of global concurrent debuginfod fetches (managed by the fetch coordinator).
    #[arg(
        long,
        default_value_t = DEFAULT_DEBUGINFOD_FETCH_CONCURRENCY,
        env = "DEBUGINFOD_FETCH_CONCURRENCY"
    )]
    pub debuginfod_fetch_concurrency: usize,

    /// Interval in seconds for reporting cache gauge metrics.
    /// Should match your Prometheus scrape interval (default: 15s).
    #[arg(long, default_value_t = 15, env = "SYMBOLIZER_GAUGE_INTERVAL_SECS")]
    pub gauge_interval_secs: u64,

    /// Maximum number of tokio blocking threads for CPU-bound DWARF
    /// resolution. Defaults to `max_concurrent_sessions` so every
    /// semaphore-permitted resolve task gets a blocking thread without
    /// queuing. Cap this to bound thread-stack memory (~1 MiB per thread).
    #[arg(long, env = "SYMBOLIZER_BLOCKING_THREADS")]
    pub blocking_threads: Option<usize>,
}

impl CommonArgs {
    /// Returns the configured blocking thread cap, defaulting to
    /// `max_concurrent_sessions` to match semaphore capacity.
    pub fn blocking_thread_count(&self) -> usize {
        self.blocking_threads
            .unwrap_or(self.max_concurrent_sessions)
    }

    /// Constructs the [`CachePool`] from the configured byte budgets.
    pub fn build_caches(&self) -> CachePool {
        CachePool {
            user_objects: ObjectCache::new(self.user_object_budget_bytes),
            kernel_objects: ObjectCache::new(self.kernel_object_budget_bytes),
            user_symbols: SymbolCache::new_byte_budget(self.user_symbol_budget_bytes),
            kernel_symbols: SymbolCache::new_byte_budget(self.kernel_symbol_budget_bytes),
            negative: NegativeCache::new(
                self.negative_cache_entries,
                Duration::from_secs(self.negative_ttl_secs),
            ),
        }
    }

    /// Builds the [`DaemonConfig`] from the shared args.
    pub fn build_daemon_config(&self) -> anyhow::Result<DaemonConfig> {
        Ok(DaemonConfig {
            listen_addr: self.listen_addr.parse()?,
            queue_capacity: self.queue_capacity,
            max_concurrent_sessions: self.max_concurrent_sessions,
            debuginfod_fetch_concurrency: self.debuginfod_fetch_concurrency,
            gauge_interval_secs: self.gauge_interval_secs,
        })
    }

    /// Initializes the tracing subscriber with the configured log level.
    ///
    /// Resolution: `--log-level` flag > `RUST_LOG` env > `"info"`.
    pub fn init_logging(&self) {
        let filter = self.log_level.as_deref().unwrap_or("info").to_string();
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(&filter))
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::rfc_3339())
            .init();
    }

    /// Starts the Prometheus metrics exporter on `0.0.0.0:{metrics_port}`.
    pub fn init_metrics(&self) -> anyhow::Result<()> {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(([0, 0, 0, 0], self.metrics_port))
            .install()
            .map_err(|e| anyhow::anyhow!("metrics server on port {}: {e}", self.metrics_port))
    }

    /// Total cache budget in bytes (sum of all L1 + L2 budgets).
    pub fn total_cache_budget(&self) -> u64 {
        self.user_object_budget_bytes
            + self.kernel_object_budget_bytes
            + self.user_symbol_budget_bytes
            + self.kernel_symbol_budget_bytes
    }

    /// Wraps a given `DebuginfodClient` with a filesystem-backed cache if `debuginfod_cache_path` is set.
    pub fn build_client<C>(
        &self,
        base_client: C,
    ) -> std::sync::Arc<dyn crate::debuginfod::DebuginfodClient>
    where
        C: crate::debuginfod::DebuginfodClient + 'static,
    {
        if let Some(cache_path) = &self.debuginfod_cache_path {
            tracing::info!(path = %cache_path.display(), "enabling filesystem cache (L1)");
            let fs_client =
                crate::debuginfod::filesystem::FilesystemDebuginfodClient::new(cache_path.clone());
            std::sync::Arc::new(crate::debuginfod::tiered::TieredDebuginfodClient::new(
                fs_client,
                base_client,
            ))
        } else {
            std::sync::Arc::new(base_client)
        }
    }

    /// Validates total cache budget against the cgroup v2 memory limit.
    ///
    /// Fails hard if total cache budget exceeds the configured threshold
    /// of the cgroup limit or 100% of the limit (guaranteed OOM).
    pub fn validate_cache_vs_cgroup(&self, threshold: f64) -> anyhow::Result<()> {
        let total_cache = self.total_cache_budget();
        let total_cache_mb = total_cache / (1024 * 1024);

        let cgroup_limit = self.read_cgroup_memory_limit()?;
        let cgroup_limit_mb = cgroup_limit / (1024 * 1024);
        let threshold_bytes = (cgroup_limit as f64 * threshold) as u64;
        let headroom_mb = cgroup_limit.saturating_sub(total_cache) / (1024 * 1024);

        tracing::info!(
            total_cache_mb,
            cgroup_limit_mb,
            threshold_pct = format!("{:.0}%", threshold * 100.0),
            headroom_mb,
            "cache budget vs cgroup memory"
        );

        if total_cache > cgroup_limit {
            anyhow::bail!(
                "total cache budget ({total_cache_mb} MiB) EXCEEDS cgroup memory limit \
                 ({cgroup_limit_mb} MiB). OOM is guaranteed. \
                 Reduce cache budgets or increase container memory limit."
            );
        }

        if total_cache > threshold_bytes {
            anyhow::bail!(
                "total cache budget ({total_cache_mb} MiB) exceeds {:.0}% of cgroup memory \
                 limit ({cgroup_limit_mb} MiB). Headroom: {headroom_mb} MiB. \
                 Reduce cache budgets or increase container memory limit.",
                threshold * 100.0
            );
        }

        Ok(())
    }

    /// Reads the cgroup v2 memory limit from `/sys/fs/cgroup/memory.max`.
    ///
    /// Fails hard if:
    /// - cgroup v2 is not available (we always run in k8s containers)
    /// - `memory.max` is "max" (unbounded — pod has no resource limits)
    fn read_cgroup_memory_limit(&self) -> anyhow::Result<u64> {
        let contents = std::fs::read_to_string("/sys/fs/cgroup/memory.max").map_err(|e| {
            anyhow::anyhow!(
                "cgroup v2 memory.max not available: {e}. \
                 The symbolizer must run inside a cgroup v2 container \
                 with memory limits defined."
            )
        })?;
        let trimmed = contents.trim();
        if trimmed == "max" {
            anyhow::bail!(
                "cgroup memory.max is 'max' (unbounded). \
                 The pod has no memory resource limit defined. \
                 Set spec.containers[].resources.limits.memory in the pod manifest."
            );
        }
        trimmed
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("failed to parse cgroup memory.max '{trimmed}': {e}"))
    }
}
