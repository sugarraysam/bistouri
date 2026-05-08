mod agent;
mod args;
mod capture;
mod sys;
mod trigger;

use agent::error::AgentError;
use args::Args;
use clap::Parser;
use std::sync::Arc;
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};
use tokio_util::sync::CancellationToken;
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
    let cache: SharedCgroupCache = Arc::new(std::sync::RwLock::new(CgroupCache::new()?));

    let watcher_cache = Arc::clone(&cache);
    let cgroup_watcher = tokio::spawn(async move {
        let _ = cgroup_watcher_task(watcher_cache).await;
    });

    // Initialize the global metrics recorder and start the Prometheus HTTP
    // scrape endpoint. Bind failure (e.g. port conflict) is fatal at startup.
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], args.metrics_port))
        .install()
        .map_err(|e| anyhow::anyhow!("metrics server on port {}: {e}", args.metrics_port))?;

    // Phase 1: Prepare TriggerAgent — loads config, creates channel.
    // No BPF dependency yet, so ProfilerAgent can receive the Sender.
    let prepared = trigger::PreparedTriggerAgent::prepare(args.config, Arc::clone(&cache)).await;

    // Phase 2: Build ProfilerAgent with the Sender from phase 1.
    let agent_builder =
        agent::profiler::ProfilerAgentBuilder::new().with_trigger_tx(prepared.trigger_tx());
    let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;
    let comm_lpm_trie_handle = loaded_agent.comm_lpm_trie_handle()?;

    let poll_cancel = CancellationToken::new();
    let poll_handle = loaded_agent.start_polling(poll_cancel.clone())?;

    // Phase 3: Start TriggerAgent with the BPF trie handle from phase 2.
    let trigger_handle = prepared.start(comm_lpm_trie_handle).await?;

    info!("BPF profiler agent started");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AgentError::Io("Ctrl-C signal error".into(), e))?;

    info!("received Ctrl-C, shutting down");

    // Cancel the async ring buffer polling task
    poll_cancel.cancel();
    let _ = poll_handle.await;

    // Signal TriggerAgent event loop to stop and await its task
    let task_handle = trigger_handle.shutdown();
    let _ = task_handle.await;

    // Abort cgroup watcher
    cgroup_watcher.abort();
    let _ = cgroup_watcher.await;

    info!("shutdown complete");

    Ok(())
}
