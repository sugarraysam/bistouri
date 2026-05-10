mod agent;
mod args;
mod capture;
mod daemon;
mod sys;
mod telemetry;
mod trigger;

use args::Args;
use clap::Parser;
use daemon::BistouriDaemon;
use tracing::info;

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Log level resolution: --log-level flag > RUST_LOG env > "bistouri=info"
    // Clap's `env` attribute already handles flag > env precedence, so
    // args.log_level is Some if either was set.
    let filter = args
        .log_level
        .as_deref()
        .unwrap_or("bistouri=info")
        .to_string();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&filter))
        .init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(args.io_threads)
        .max_blocking_threads(args.blocking_threads)
        .enable_all()
        .thread_name("bistouri-worker")
        .build()?;

    rt.block_on(run(args))
}

async fn run(args: Args) -> anyhow::Result<()> {
    let daemon = BistouriDaemon::start(args).await?;

    tokio::signal::ctrl_c().await?;
    info!("received Ctrl-C, shutting down");

    daemon.shutdown().await;
    info!("shutdown complete");

    Ok(())
}
