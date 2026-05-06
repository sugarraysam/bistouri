mod agent;
mod sys;

use agent::error::AgentError;
use agent::profiler::ProfilerAgentBuilder;
use std::sync::{Arc, RwLock};
use sys::cgroup::{cgroup_watcher_task, CgroupCache, SharedCgroupCache};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cache: SharedCgroupCache = Arc::new(RwLock::new(CgroupCache::new()?));

    let watcher_cache = Arc::clone(&cache);
    let watcher_handle = tokio::spawn(async move {
        let _ = cgroup_watcher_task(watcher_cache).await;
    });

    let agent = ProfilerAgentBuilder::new().try_build()?;
    let mut loaded_agent = agent.load_and_attach()?;

    let (poll_handle, stop_flag) = loaded_agent.start_polling()?;

    println!("BPF profiler agent started. Press Ctrl-C to exit.");

    tokio::signal::ctrl_c()
        .await
        .map_err(|e| AgentError::Io("Ctrl-C signal error".into(), e))?;

    println!("Received Ctrl-C, shutting down...");

    // TODO: rework this is this idiomatic?
    // Signal the ringbuffers polling thread to stop
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    // Wait for the polling thread to exit cleanly
    let _ = poll_handle.await;

    // Abort the cgroup watcher task
    watcher_handle.abort();
    let _ = watcher_handle.await;

    println!("Shutdown complete.");

    Ok(())
}
