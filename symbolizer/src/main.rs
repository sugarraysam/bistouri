#[cfg(not(frame_pointers_enabled))]
compile_error!(
    "CRITICAL BUILD ERROR: Rust binaries must be compiled with frame pointers enabled!\n\
     Please ensure that `.cargo/config.toml` exists with `rustflags = [\"-C\", \"force-frame-pointers=yes\"]` \
     under the [build] section, or RUSTFLAGS is set."
);

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::sync::Arc;

use clap::Parser;
use tracing::info;

use bistouri_symbolizer::cli::{clap_styles, CommonArgs};
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
#[command(
    name = "bistouri-symbolizer",
    version,
    color = clap::ColorChoice::Always,
    styles = clap_styles()
)]
struct Args {
    #[command(flatten)]
    common: CommonArgs,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let blocking_threads = args.common.blocking_thread_count();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(blocking_threads)
        .build()
        .expect("failed to build tokio runtime");

    runtime.block_on(async_main(args))
}

async fn async_main(args: Args) -> anyhow::Result<()> {
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

    // Build the debuginfod client.
    let http_client = HttpDebuginfodClient::new(common.debuginfod_url.clone())
        .map_err(|e| anyhow::anyhow!("failed to create debuginfod client: {e:#}"))?;
    let client = common.build_client(http_client);

    // Client must be created before caches — ObjectCache is a loading cache
    // that holds a reference to the debuginfod client.
    let caches = common.build_caches(client);
    let config = common.build_daemon_config()?;

    // Log-only sink — for production storage, build a custom binary
    // with your own SessionSink implementation.
    let sink = Arc::new(LogSink);

    let daemon = SymbolizerDaemon::start(config, sink, caches).await?;

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down");

    daemon.shutdown().await;
    info!("shutdown complete");

    Ok(())
}
