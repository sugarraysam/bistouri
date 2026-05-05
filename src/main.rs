mod agent;

use agent::profiler::ProfilerAgentBuilder;
use anyhow::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let agent = ProfilerAgentBuilder::new().try_build()?;
    let mut loaded_agent = agent.load_and_attach()?;

    let (poll_handle, stop_flag) = loaded_agent.start_polling()?;

    println!("BPF profiler agent started. Press Ctrl-C to exit.");

    tokio::signal::ctrl_c().await?;
    println!("Received Ctrl-C, shutting down...");

    // Signal the polling thread to stop
    stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);

    // Wait for the polling thread to exit cleanly
    let _ = poll_handle.await;

    println!("Shutdown complete.");
    Ok(())
}
