mod agent;
mod sys;
mod trigger;

use agent::error::AgentError;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};
use trigger::config::TriggerConfig;

/// Default config file path when BISTOURI_CONFIG is not set.
const DEFAULT_CONFIG_PATH: &str = "/etc/bistouri/trigger.yaml";

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cache: SharedCgroupCache = Arc::new(RwLock::new(CgroupCache::new()?));

    let watcher_cache = Arc::clone(&cache);
    let cgroup_watcher = tokio::spawn(async move {
        let _ = cgroup_watcher_task(watcher_cache).await;
    });

    // Config path: BISTOURI_CONFIG env var or /etc/bistouri/trigger.yaml
    let config_path = PathBuf::from(
        std::env::var("BISTOURI_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG_PATH.to_string()),
    );

    let trigger_config = TriggerConfig::load_or_default(&config_path).await;

    let (trigger_tx, trigger_rx) = tokio::sync::mpsc::channel::<trigger::ProcessMatchEvent>(1024);

    let agent_builder =
        agent::profiler::ProfilerAgentBuilder::new().with_trigger_tx(trigger_tx.clone());
    let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;
    let comm_lpm_trie_handle = loaded_agent.comm_lpm_trie_handle()?;

    let (poll_handle, stop_flag) = loaded_agent.start_polling()?;

    // Start TriggerAgent — proc_walk and event loop are managed internally.
    let trigger_handle = trigger::TriggerAgent::start(
        trigger_config,
        comm_lpm_trie_handle,
        Arc::clone(&cache),
        trigger_tx,
        trigger_rx,
    )
    .await?;

    // Spawn config file watcher — sends Reload messages on config changes.
    let config_watcher = tokio::spawn(trigger::watcher::config_watcher_task(
        config_path,
        trigger_handle.control_tx(),
    ));

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

    // Abort watcher tasks
    config_watcher.abort();
    let _ = config_watcher.await;
    cgroup_watcher.abort();
    let _ = cgroup_watcher.await;

    println!("Shutdown complete.");

    Ok(())
}
