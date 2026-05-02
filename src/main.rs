mod profiler {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}

use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use profiler::*;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut object = std::mem::MaybeUninit::uninit();
    let builder = ProfilerSkelBuilder::default();
    let open_skel = builder.open(&mut object)?;
    let mut skel = open_skel.load()?;
    skel.attach()?;

    println!("BPF program loaded and attached. Press Ctrl-C to exit.");
    println!("Check /sys/kernel/debug/tracing/trace_pipe for output.");

    tokio::signal::ctrl_c().await?;

    Ok(())
}
