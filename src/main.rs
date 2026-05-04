mod profiler {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}

use anyhow::Result;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::SkelBuilder;
use perf_event::{events::Software, Builder};
use profiler::*;
use std::os::fd::IntoRawFd;
use std::thread;

fn perf_event_open(cpu: i32, freq: u64) -> Result<i32> {
    let mut builder = Builder::new()
        .kind(Software::CPU_CLOCK)
        .any_pid()
        .one_cpu(cpu as usize);
    
    builder.sample_frequency(freq);

    let event = builder.build()?;

    // We consume the event into a raw file descriptor so it doesn't
    // automatically close when 'event' drops out of scope.
    // libbpf-rs will now manage the lifecycle of this FD.
    Ok(event.into_raw_fd())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut object = std::mem::MaybeUninit::uninit();
    let builder = ProfilerSkelBuilder::default();
    let open_skel = builder.open(&mut object)?;
    let skel = open_skel.load()?;

    let ncpus = thread::available_parallelism()?.get();
    let mut _links = Vec::new();

    for cpu in 0..ncpus {
        let fd = perf_event_open(cpu as i32, 19)?;
        let link = skel.progs.handle_perf.attach_perf_event(fd)?;
        _links.push(link);
    }

    println!(
        "BPF program attached to {} CPUs at 19Hz. Press Ctrl-C to exit.",
        ncpus
    );
    println!("Check /sys/kernel/debug/tracing/trace_pipe for output.");

    tokio::signal::ctrl_c().await?;

    Ok(())
}
