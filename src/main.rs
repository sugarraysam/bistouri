mod agent;
mod args;
mod sys;
mod trigger;

use agent::error::AgentError;
use args::Args;
use clap::Parser;
use std::sync::{Arc, RwLock};
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};
use tracing::info;
use trigger::config::TriggerConfig;

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
    let cache: SharedCgroupCache = Arc::new(RwLock::new(CgroupCache::new()?));

    let watcher_cache = Arc::clone(&cache);
    let cgroup_watcher = tokio::spawn(async move {
        let _ = cgroup_watcher_task(watcher_cache).await;
    });

    let trigger_config = TriggerConfig::load_or_default(&args.config).await;

    let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel::<trigger::ProcessMatchEvent>(1024);

    let agent_builder =
        agent::profiler::ProfilerAgentBuilder::new().with_trigger_tx(trigger_tx.clone());
    let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;
    let comm_lpm_trie_handle = loaded_agent.comm_lpm_trie_handle()?;

    let (poll_handle, stop_flag) = loaded_agent.start_polling()?;

    // Start TriggerAgent — proc_walk, PSI watchers, and config file watcher
    // are all managed internally by the agent.
    let trigger_handle = trigger::TriggerAgent::start(
        trigger_config,
        args.config,
        comm_lpm_trie_handle,
        Arc::clone(&cache),
        trigger_tx,
        trigger_rx,
    )
    .await?;

    info!("BPF profiler agent started");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AgentError::Io("Ctrl-C signal error".into(), e))?;

    info!("received Ctrl-C, shutting down");

    // Signal the ringbuffers polling thread to stop
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    // Wait for the polling thread to exit cleanly
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
