use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use perf_event::{events::Software, Builder, Counter};
use std::os::fd::AsRawFd;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}

const DEFAULT_SAMPLING_FREQ_HZ: u64 = 19;

pub(crate) struct ProfilerAgent {
    freq: u64,
    ncpus: usize,
    object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
    skel: Option<bpf::ProfilerSkel<'static>>,
    links: Vec<libbpf_rs::Link>,
}

impl Drop for ProfilerAgent {
    fn drop(&mut self) {
        // We must drop the links and skeleton BEFORE the memory object they borrow from.
        self.links.clear();
        self.skel.take();

        // `self.object` is safely dropped automatically after this scope ends.
    }
}

impl ProfilerAgent {
    fn try_new(freq: u64) -> Result<Self> {
        let ncpus = libbpf_rs::num_possible_cpus().context("Failed to get possible CPUs")?;

        Ok(Self {
            freq,
            ncpus,
            object: Box::new(std::mem::MaybeUninit::uninit()),
            skel: None,
            links: Vec::with_capacity(ncpus),
        })
    }

    /// Loads the eBPF program into the kernel and attaches perf events to all CPUs.
    pub(crate) fn load_and_attach(&mut self) -> Result<()> {
        if self.skel.is_some() {
            return Ok(());
        }

        let builder = bpf::ProfilerSkelBuilder::default();

        let open_skel = builder
            .open(&mut *self.object)
            .context("Failed to open BPF skeleton")?;

        let skel = open_skel.load().context("Failed to load BPF skeleton")?;

        // SAFETY: Erasing lifetime because `self.object` is Boxed and outlives `self.skel`.
        let skel: bpf::ProfilerSkel<'static> = unsafe { std::mem::transmute(skel) };
        self.skel = Some(skel);

        self.attach_perf_events()?;

        Ok(())
    }

    fn attach_perf_events(&mut self) -> Result<()> {
        let skel = self
            .skel
            .as_mut()
            .expect("Skeleton must be loaded before attaching");

        for cpu in 0..self.ncpus {
            let event = Self::perf_event_open(cpu as i32, self.freq)?;

            let fd = event.as_raw_fd();
            let link = skel
                .progs
                .handle_perf
                .attach_perf_event(fd)
                .context(format!("Failed to attach perf event on CPU {}", cpu))?;

            self.links.push(link);
        }

        Ok(())
    }

    fn perf_event_open(cpu: i32, freq: u64) -> Result<Counter> {
        let mut builder = Builder::new()
            .kind(Software::CPU_CLOCK)
            .any_pid()
            .one_cpu(cpu as usize);

        builder.sample_frequency(freq);

        builder.build().context("Failed to build perf event")
    }
}

pub(crate) struct ProfilerAgentBuilder {
    freq: u64,
}

impl Default for ProfilerAgentBuilder {
    fn default() -> Self {
        Self {
            freq: DEFAULT_SAMPLING_FREQ_HZ,
        }
    }
}

impl ProfilerAgentBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_freq(mut self, freq: u64) -> Self {
        self.freq = freq;
        self
    }

    pub(crate) fn try_build(self) -> Result<ProfilerAgent> {
        ProfilerAgent::try_new(self.freq)
    }
}
