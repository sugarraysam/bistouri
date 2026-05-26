use std::sync::Arc;

use clap::Parser;
use tracing::info;

use bistouri_symbolizer::cli::CommonArgs;
use bistouri_symbolizer::daemon::SymbolizerDaemon;
use bistouri_symbolizer::debuginfod::http::HttpDebuginfodClient;
use bistouri_symbolizer::sink::log::LogSink;

/// Bistouri symbolizer service — resolves raw stack traces from agents
/// into human-readable function names, source files, and line numbers.
///
/// This is the open-source reference binary using `LogSink`.
/// For production storage backends (ClickHouse, etc.), build a custom
/// binary that imports `bistouri-symbolizer` as a library and implements
/// `SessionSink`. See the crate-level docs for an example.
#[derive(Parser, Debug)]
#[command(name = "bistouri-symbolizer", version)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let common = &args.common;

    common.init_logging();
    common.init_metrics()?;
    bistouri_symbolizer::telemetry::describe_all();

    info!(
        listen_addr = %common.listen_addr,
        metrics_port = common.metrics_port,
        debuginfod_url = %common.debuginfod_url,
        debuginfod_cache_path = ?common.debuginfod_cache_path,
        user_object_budget_mb = common.user_object_budget_bytes / (1024 * 1024),
        kernel_object_budget_mb = common.kernel_object_budget_bytes / (1024 * 1024),
        user_symbol_budget_mb = common.user_symbol_budget_bytes / (1024 * 1024),
        kernel_symbol_budget_mb = common.kernel_symbol_budget_bytes / (1024 * 1024),
        "starting bistouri-symbolizer"
    );

    let caches = common.build_caches();
    let config = common.build_daemon_config()?;

    // Log-only sink — for production storage, build a custom binary
    // with your own SessionSink implementation.
    let sink = Arc::new(LogSink);

    // Build the debuginfod client.
    let http_client = HttpDebuginfodClient::new(common.debuginfod_url.clone())
        .map_err(|e| anyhow::anyhow!("failed to create debuginfod client: {e:#}"))?;
    let client = common.build_client(http_client);

    let daemon = SymbolizerDaemon::start(config, client, sink, caches).await?;

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down");

    daemon.shutdown().await;
    info!("shutdown complete");

    Ok(())
}
