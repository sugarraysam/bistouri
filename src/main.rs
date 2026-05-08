mod agent;
mod args;
mod capture;
mod sys;
mod trigger;

use agent::error::AgentError;
use args::Args;
use capture::orchestrator::{CaptureOrchestrator, STACK_SAMPLE_CHANNEL_SIZE};
use capture::trace::StackSample;
use clap::Parser;
use std::sync::Arc;
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};
use tokio::sync::mpsc;
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

    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(([0, 0, 0, 0], args.metrics_port))
        .install()
        .map_err(|e| anyhow::anyhow!("metrics server on port {}: {e}", args.metrics_port))?;

    // Stack sample channel created here (not inside orchestrator) because the
    // BPF ringbuffer callback needs the Sender at agent build time — before
    // the orchestrator exists. All other channels are internal to start().
    let (stack_tx, stack_rx) = mpsc::channel::<StackSample>(STACK_SAMPLE_CHANNEL_SIZE);

    // Phase 1: Prepare TriggerAgent (loads config, creates event channel).
    let prepared = trigger::PreparedTriggerAgent::prepare(args.config, Arc::clone(&cache)).await;

    // Phase 2: Build ProfilerAgent with trigger + stack sample senders.
    let agent_builder = agent::profiler::ProfilerAgentBuilder::new()
        .with_trigger_tx(prepared.trigger_tx())
        .with_stack_tx(stack_tx);
    let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;
    let comm_lpm_trie_handle = loaded_agent.comm_lpm_trie_handle()?;
    let pid_filter_handle = loaded_agent.pid_filter_handle()?;

    let poll_cancel = CancellationToken::new();
    let poll_handle = loaded_agent.start_polling(poll_cancel.clone())?;

    // Phase 3: Start CaptureOrchestrator with BPF pid filter and stack channel.
    let mut orch_handle =
        CaptureOrchestrator::start(pid_filter_handle, args.capture_duration_secs, stack_rx);

    // Phase 4: Start TriggerAgent with BPF trie handle and capture channel.
    let trigger_handle = prepared
        .start(comm_lpm_trie_handle, orch_handle.capture_tx.clone())
        .await?;

    // Downstream consumer — logs completed sessions until symbolizer is wired.
    let downstream_handle = tokio::spawn(async move {
        while let Some(session) = orch_handle.completed_rx.recv().await {
            info!(
                session_id = %session.session_id,
                pid = session.pid,
                comm = %session.comm,
                resource = ?session.resource,
                total_samples = session.total_samples,
                unique_traces = session.stack_traces.len(),
                "completed session ready for symbolization",
            );
            // TODO: forward to symbolizer service
        }
    });

    info!("BPF profiler agent started");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AgentError::Io("Ctrl-C signal error".into(), e))?;

    info!("received Ctrl-C, shutting down");

    poll_cancel.cancel();
    let _ = poll_handle.await;

    let task_handle = trigger_handle.shutdown();
    let _ = task_handle.await;

    downstream_handle.abort();
    let _ = downstream_handle.await;

    cgroup_watcher.abort();
    let _ = cgroup_watcher.await;

    info!("shutdown complete");

    Ok(())
}
