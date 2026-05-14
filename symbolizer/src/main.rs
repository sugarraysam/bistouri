use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tracing::info;

use bistouri_symbolizer::daemon::{DaemonConfig, SymbolizerDaemon};
use bistouri_symbolizer::debuginfod::filesystem::FilesystemDebuginfodClient;
use bistouri_symbolizer::debuginfod::http::HttpDebuginfodClient;
use bistouri_symbolizer::debuginfod::tiered::TieredDebuginfodClient;
use bistouri_symbolizer::resolve::cache::{CachePool, NegativeCache, ObjectCache, SymbolCache};
use bistouri_symbolizer::sink::log::LogSink;

/// Bistouri symbolizer service — resolves raw stack traces from agents
/// into human-readable function names, source files, and line numbers.
#[derive(Parser, Debug)]
#[command(name = "bistouri-symbolizer", version)]
struct Args {
    /// gRPC listen address.
    #[arg(long, default_value = "0.0.0.0:50051", env = "SYMBOLIZER_LISTEN_ADDR")]
    listen_addr: String,

    /// Prometheus metrics port.
    #[arg(long, default_value_t = 9091, env = "SYMBOLIZER_METRICS_PORT")]
    metrics_port: u16,

    /// Debuginfod server URL.
    #[arg(long, default_value = "http://localhost:8002", env = "DEBUGINFOD_URL")]
    debuginfod_url: String,

    /// Local debuginfod cache directory (shared volume).
    /// If set, artifacts are read from disk before falling back to HTTP.
    #[arg(long, env = "DEBUGINFOD_CACHE_PATH")]
    debuginfod_cache_path: Option<PathBuf>,

    /// Byte budget for user-space object cache (L1).
    /// Default: 256 MiB — fits ~15–250 typical user-space debuginfo objects.
    #[arg(
        long,
        default_value_t = 256 * 1024 * 1024,
        env = "SYMBOLIZER_USER_OBJECT_BUDGET_BYTES"
    )]
    user_object_budget_bytes: u64,

    /// Byte budget for kernel object cache (L1).
    /// Default: 512 MiB — guarantees at least one vmlinux (200–400 MB)
    /// plus headroom for kernel modules.
    #[arg(
        long,
        default_value_t = 512 * 1024 * 1024,
        env = "SYMBOLIZER_KERNEL_OBJECT_BUDGET_BYTES"
    )]
    kernel_object_budget_bytes: u64,

    /// Max entries in user symbol cache (L2).
    /// Default: 500K entries — ~25 MiB of keys + Arc pointers.
    #[arg(
        long,
        default_value_t = 500_000,
        env = "SYMBOLIZER_USER_SYMBOL_CAPACITY_ENTRIES"
    )]
    user_symbol_capacity_entries: u64,

    /// Max entries in kernel symbol cache (L2).
    /// Default: 500K entries — ~25 MiB of keys + Arc pointers.
    #[arg(
        long,
        default_value_t = 500_000,
        env = "SYMBOLIZER_KERNEL_SYMBOL_CAPACITY_ENTRIES"
    )]
    kernel_symbol_capacity_entries: u64,

    /// Maximum number of negative cache entries (404'd build IDs).
    #[arg(
        long,
        default_value_t = 4096,
        env = "SYMBOLIZER_NEGATIVE_CACHE_ENTRIES"
    )]
    negative_cache_entries: u64,

    /// Negative cache TTL in seconds.
    #[arg(long, default_value_t = 300, env = "SYMBOLIZER_NEGATIVE_TTL_SECS")]
    negative_ttl_secs: u64,

    /// Log level filter (e.g. "info", "bistouri_symbolizer=debug").
    /// Falls back to RUST_LOG env var, then "info".
    #[arg(long, env = "RUST_LOG")]
    log_level: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Log level resolution: --log-level flag > RUST_LOG env > "info"
    // Clap's `env` attribute handles flag > env precedence, so
    // args.log_level is Some if either was set.
    let filter = args.log_level.as_deref().unwrap_or("info").to_string();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&filter))
        .init();

    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], args.metrics_port))
        .install()
        .map_err(|e| anyhow::anyhow!("metrics server on port {}: {e}", args.metrics_port))?;

    bistouri_symbolizer::telemetry::describe_all();

    info!(
        listen_addr = %args.listen_addr,
        metrics_port = args.metrics_port,
        debuginfod_url = %args.debuginfod_url,
        debuginfod_cache_path = ?args.debuginfod_cache_path,
        user_object_budget_mb = args.user_object_budget_bytes / (1024 * 1024),
        kernel_object_budget_mb = args.kernel_object_budget_bytes / (1024 * 1024),
        user_symbol_capacity_entries = args.user_symbol_capacity_entries,
        kernel_symbol_capacity_entries = args.kernel_symbol_capacity_entries,
        "starting bistouri-symbolizer"
    );

    let caches = CachePool {
        user_objects: ObjectCache::new(args.user_object_budget_bytes),
        kernel_objects: ObjectCache::new(args.kernel_object_budget_bytes),
        user_symbols: SymbolCache::new(args.user_symbol_capacity_entries),
        kernel_symbols: SymbolCache::new(args.kernel_symbol_capacity_entries),
        negative: NegativeCache::new(
            args.negative_cache_entries,
            Duration::from_secs(args.negative_ttl_secs),
        ),
    };

    let config = DaemonConfig {
        listen_addr: args.listen_addr.parse()?,
    };

    let sink = Arc::new(LogSink);

    // Build the debuginfod client.
    // If a cache path is provided, compose filesystem + HTTP (tiered).
    // Otherwise, use HTTP only.
    let http_client = HttpDebuginfodClient::new(args.debuginfod_url)
        .map_err(|e| anyhow::anyhow!("failed to create debuginfod client: {e:#}"))?;

    let daemon = if let Some(cache_path) = args.debuginfod_cache_path {
        info!(path = %cache_path.display(), "enabling filesystem-backed debuginfod (tiered)");
        let fs_client = FilesystemDebuginfodClient::new(cache_path);
        let client = Arc::new(TieredDebuginfodClient::new(fs_client, http_client));
        SymbolizerDaemon::start(config, client, sink, caches).await?
    } else {
        let client = Arc::new(http_client);
        SymbolizerDaemon::start(config, client, sink, caches).await?
    };

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down");

    daemon.shutdown().await;
    info!("shutdown complete");

    Ok(())
}
