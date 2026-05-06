mod agent;
mod sys;
mod trigger;

use agent::error::AgentError;
use std::sync::{Arc, RwLock};
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cache: SharedCgroupCache = Arc::new(RwLock::new(CgroupCache::new()?));

    let watcher_cache = Arc::clone(&cache);
    let watcher_handle = tokio::spawn(async move {
        let _ = cgroup_watcher_task(watcher_cache).await;
    });

    // Create TriggerConfig
    let trigger_config_path = "trigger.yaml";
    let trigger_config = std::sync::Arc::new(trigger::config::TriggerConfig::load_from_file(
        trigger_config_path,
    )?);
    let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel::<trigger::ProcessMatchEvent>(1024);

    let agent_builder = agent::profiler::ProfilerAgentBuilder::new()
        .with_trigger(std::sync::Arc::clone(&trigger_config), trigger_tx.clone());
    let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;

    let (poll_handle, stop_flag) = loaded_agent.start_polling()?;

    // Initialize TriggerAgent — proc_walk and event loop are managed internally.
    // TODO: the control_tx on the returned handle can be used to send
    // TriggerControl::Reload messages once a config file watcher is implemented.
    let trigger_handle = trigger::TriggerAgent::start(
        trigger_config,
        std::sync::Arc::clone(&cache),
        trigger_tx,
        trigger_rx,
    )
    .await?;

    println!("BPF profiler agent started. Press Ctrl-C to exit.");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AgentError::Io("Ctrl-C signal error".into(), e))?;

    println!("Received Ctrl-C, shutting down...");

    // Signal the ringbuffers polling thread to stop
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    // Wait for the polling thread to exit cleanly
    let _ = poll_handle.await;

    // Signal TriggerAgent event loop to stop and await its task
    let task_handle = trigger_handle.shutdown();
    let _ = task_handle.await;

    // Abort the cgroup watcher task
    watcher_handle.abort();
    let _ = watcher_handle.await;

    println!("Shutdown complete.");

    Ok(())
}
