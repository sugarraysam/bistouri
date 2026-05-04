mod agent;

use agent::profiler::ProfilerAgentBuilder;
use anyhow::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut agent = ProfilerAgentBuilder::new().try_build()?;
    agent.load_and_attach()?;

    println!("BPF profiler agent started. Press Ctrl-C to exit.");
    println!("Check /sys/kernel/debug/tracing/trace_pipe for output.");

    tokio::signal::ctrl_c().await?;

    Ok(())
}
