use std::sync::Arc;

use clap::Parser;
use tracing::info;

use bistouri_symbolizer::daemon::{DaemonConfig, SymbolizerDaemon};
use bistouri_symbolizer::debuginfod::http::HttpDebuginfodClient;
use bistouri_symbolizer::sink::log::LogSink;

/// Bistouri symbolizer service — resolves raw stack traces from agents
/// into human-readable function names, source files, and line numbers.
#[derive(Parser, Debug)]
#[command(name = "bistouri-symbolizer", version)]
struct Args {
    /// gRPC listen address.
    #[arg(long, default_value = "0.0.0.0:50051", env = "SYMBOLIZER_LISTEN_ADDR")]
    listen_addr: String,

    /// Debuginfod server URL.
    #[arg(long, default_value = "http://localhost:8002", env = "DEBUGINFOD_URL")]
    debuginfod_url: String,

    /// Maximum number of parsed ELF objects to cache.
    #[arg(long, default_value_t = 256, env = "SYMBOLIZER_CACHE_SIZE")]
    cache_size: usize,

    /// Maximum number of negative cache entries (404'd build IDs).
    #[arg(long, default_value_t = 512, env = "SYMBOLIZER_NEGATIVE_CACHE_SIZE")]
    negative_cache_size: usize,

    /// Maximum number of resolved symbols to cache (L2 symbol cache).
    #[arg(long, default_value_t = 100_000, env = "SYMBOLIZER_SYMBOL_CACHE_SIZE")]
    symbol_cache_size: usize,

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
    let filter = args
        .log_level
        .as_deref()
        .unwrap_or("info")
        .to_string();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&filter))
        .init();

    info!(
        listen_addr = %args.listen_addr,
        debuginfod_url = %args.debuginfod_url,
        cache_size = args.cache_size,
        "starting bistouri-symbolizer"
    );

    let client = Arc::new(
        HttpDebuginfodClient::new(args.debuginfod_url)
            .map_err(|e| anyhow::anyhow!("failed to create debuginfod client: {e:#}"))?,
    );

    let sink = Arc::new(LogSink);

    let config = DaemonConfig {
        listen_addr: args.listen_addr.parse()?,
        cache_size: args.cache_size,
        negative_cache_size: args.negative_cache_size,
        symbol_cache_size: args.symbol_cache_size,
    };

    let daemon = SymbolizerDaemon::start(config, client, sink).await?;

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down");

    daemon.shutdown().await;
    info!("shutdown complete");

    Ok(())
}
