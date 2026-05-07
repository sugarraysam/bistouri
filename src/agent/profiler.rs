use crate::agent::error::{AgentError, Result};
use crate::trigger::ProcessMatchEvent;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;
use perf_event::{events::Software, Builder, Counter};
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::sync::mpsc::Sender;
use tracing::warn;

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}

const DEFAULT_SAMPLING_FREQ_HZ: u64 = 19;

pub(crate) const MAX_STACK_DEPTH: usize = 127;
pub(crate) const TASK_COMM_LEN: usize = 16;

#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct BpfPerfEvent {
    pub tgid: u32,
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub kernel_stack_sz: i32,
    pub user_stack_sz: i32,
    pub kernel_stack: [u64; MAX_STACK_DEPTH],
    pub user_stack: [u64; MAX_STACK_DEPTH],
}

impl BpfPerfEvent {
    fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() == std::mem::size_of::<Self>() {
            Some(unsafe { &*data.as_ptr().cast::<Self>() })
        } else {
            None
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
struct BpfProcessMatchEvent {
    rule_id: u32,
    pid: u32,
    cgroup_id: u64,
    comm: [u8; TASK_COMM_LEN],
}

impl BpfProcessMatchEvent {
    fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() == std::mem::size_of::<Self>() {
            Some(unsafe { &*data.as_ptr().cast::<Self>() })
        } else {
            None
        }
    }
}

impl From<&BpfProcessMatchEvent> for ProcessMatchEvent {
    fn from(bpf: &BpfProcessMatchEvent) -> Self {
        let comm = String::from_utf8_lossy(&bpf.comm)
            .trim_matches(char::from(0))
            .to_string();
        ProcessMatchEvent {
            rule_id: bpf.rule_id,
            pid: bpf.pid,
            cgroup_id: bpf.cgroup_id,
            comm,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum SpaceKind {
    Kernel = 0,
    User = 1,
}

impl std::fmt::Display for SpaceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpaceKind::Kernel => write!(f, "kernel"),
            SpaceKind::User => write!(f, "user"),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ErrReserveStackRingbuf {
    tgid: u32,
    pid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ErrStackFetch {
    tgid: u32,
    pid: u32,
    ret_code: i32,
    space: SpaceKind,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ErrReserveTriggerRingbuf {
    rule_id: u32,
    pid: u32,
}

#[repr(C)]
union ErrorData {
    stack_reserve_err: ErrReserveStackRingbuf,
    stack_fetch_err: ErrStackFetch,
    trigger_reserve_err: ErrReserveTriggerRingbuf,
}

#[repr(C)]
struct ErrorEvent {
    kind: u32,
    data: ErrorData,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum ProfilerError {
    #[error("Failed to reserve stack ringbuffer for tgid: {tgid}, pid: {pid}")]
    ReserveStackRingbuf { tgid: u32, pid: u32 },
    #[error("Failed to fetch {space} stack for tgid: {tgid}, pid: {pid}. Code: {ret_code}")]
    StackFetch {
        tgid: u32,
        pid: u32,
        ret_code: i32,
        space: SpaceKind,
    },
    #[error("Failed to reserve trigger ringbuffer for rule: {rule_id}, pid: {pid}")]
    ReserveTriggerRingbuf { rule_id: u32, pid: u32 },
    #[error("Unknown error kind: {0}")]
    Unknown(u32),
}

impl ProfilerError {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() == std::mem::size_of::<ErrorEvent>() {
            let event = unsafe { &*data.as_ptr().cast::<ErrorEvent>() };
            match event.kind {
                1 => {
                    // SAFETY: We verify the tag `kind == 1` before accessing the union field.
                    let reserve = unsafe { event.data.stack_reserve_err };
                    Some(ProfilerError::ReserveStackRingbuf {
                        tgid: reserve.tgid,
                        pid: reserve.pid,
                    })
                }
                2 => {
                    // SAFETY: We verify the tag `kind == 2` before accessing the union field.
                    let fetch = unsafe { event.data.stack_fetch_err };
                    Some(ProfilerError::StackFetch {
                        tgid: fetch.tgid,
                        pid: fetch.pid,
                        ret_code: fetch.ret_code,
                        space: fetch.space,
                    })
                }
                3 => {
                    // SAFETY: We verify the tag `kind == 3` before accessing the union field.
                    let trigger = unsafe { event.data.trigger_reserve_err };
                    Some(ProfilerError::ReserveTriggerRingbuf {
                        rule_id: trigger.rule_id,
                        pid: trigger.pid,
                    })
                }
                k => Some(ProfilerError::Unknown(k)),
            }
        } else {
            None
        }
    }
}

struct RingBufferRunner(libbpf_rs::RingBuffer<'static>);
unsafe impl Send for RingBufferRunner {}

pub(crate) struct ProfilerAgent {
    freq: u64,
    ncpus: usize,
    trigger_tx: Option<Sender<ProcessMatchEvent>>,
}

impl ProfilerAgent {
    fn try_new(freq: u64, trigger_tx: Option<Sender<ProcessMatchEvent>>) -> Result<Self> {
        let ncpus = libbpf_rs::num_possible_cpus()
            .map_err(|e| AgentError::Bpf("failed to get possible CPUs".into(), e))?;
        Ok(Self {
            freq,
            ncpus,
            trigger_tx,
        })
    }

    pub(crate) fn load_and_attach(self) -> Result<LoadedProfilerAgent> {
        let mut object = Box::new(std::mem::MaybeUninit::uninit());
        let builder = bpf::ProfilerSkelBuilder::default();

        let open_skel = builder
            .open(&mut object)
            .map_err(|e| AgentError::Bpf("failed to open BPF skeleton".into(), e))?;

        let skel = open_skel
            .load()
            .map_err(|e| AgentError::Bpf("failed to load BPF skeleton".into(), e))?;

        // SAFETY: Erasing lifetime because `object` is Boxed and will outlive `skel` inside LoadedProfilerAgent.
        let skel: bpf::ProfilerSkel<'static> = unsafe { std::mem::transmute(skel) };

        let mut loaded = LoadedProfilerAgent {
            // The declaration order here is CRITICAL for Rust's Drop semantics.
            // Fields are dropped from top to bottom.
            ring_buffer: None,
            links: Vec::with_capacity(self.ncpus + 1),
            skel,
            object,
        };

        // Always attach match_comm_on_exec — the BPF program is a no-op when
        // the comm_lpm_trie is empty (bpf_map_lookup_elem returns NULL).
        // Trie population is handled by TriggerAgent which owns the config.
        let link =
            loaded.skel.progs.match_comm_on_exec.attach().map_err(|e| {
                AgentError::Bpf("failed to attach match_comm_on_exec prog".into(), e)
            })?;
        loaded.links.push(link);

        loaded.setup_ringbuffers(self.trigger_tx)?;
        loaded.attach_perf_events(self.ncpus, self.freq)?;

        Ok(loaded)
    }
}

pub(crate) struct LoadedProfilerAgent {
    ring_buffer: Option<libbpf_rs::RingBuffer<'static>>,
    links: Vec<libbpf_rs::Link>,
    skel: bpf::ProfilerSkel<'static>,
    #[allow(dead_code)]
    object: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
}

impl LoadedProfilerAgent {
    fn setup_ringbuffers(&mut self, trigger_tx: Option<Sender<ProcessMatchEvent>>) -> Result<()> {
        let mut builder = libbpf_rs::RingBufferBuilder::new();

        builder
            .add(&self.skel.maps.perf_events, |data| {
                if let Some(event) = BpfPerfEvent::from_bytes(data) {
                    // TODO: process stacktrace
                    let _ = event;
                }
                0
            })
            .map_err(|e| AgentError::Bpf("failed to add perf_events ringbuffer".into(), e))?;

        builder
            .add(&self.skel.maps.errors, |data| {
                if let Some(err) = ProfilerError::from_bytes(data) {
                    warn!(error = %err, "BPF error event received");
                }
                0
            })
            .map_err(|e| AgentError::Bpf("failed to add errors ringbuffer".into(), e))?;

        if let Some(tx) = trigger_tx {
            builder
                .add(&self.skel.maps.trigger_events, move |data| {
                    if let Some(bpf_event) = BpfProcessMatchEvent::from_bytes(data) {
                        let _ = tx.blocking_send(bpf_event.into());
                    }
                    0
                })
                .map_err(|e| {
                    AgentError::Bpf("failed to add trigger_events ringbuffer".into(), e)
                })?;
        }

        let ring_buffer = builder
            .build()
            .map_err(|e| AgentError::Bpf("failed to build ringbuffer".into(), e))?;
        self.ring_buffer = Some(ring_buffer);
        Ok(())
    }

    fn attach_perf_events(&mut self, ncpus: usize, freq: u64) -> Result<()> {
        for cpu in 0..ncpus {
            let event = Self::perf_event_open(cpu as i32, freq)?;
            let fd = event.as_raw_fd();
            let link = self
                .skel
                .progs
                .handle_perf
                .attach_perf_event(fd)
                .map_err(|e| {
                    AgentError::Bpf(format!("failed to attach perf event on CPU {}", cpu), e)
                })?;

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
        builder
            .build()
            .map_err(|e| AgentError::PerfEvent("failed to build perf event".into(), e))
    }

    /// Starts polling the ringbuffers on a blocking Tokio thread.
    /// Returns a JoinHandle and an AtomicBool flag to signal shutdown.
    pub(crate) fn start_polling(
        &mut self,
    ) -> Result<(tokio::task::JoinHandle<()>, Arc<AtomicBool>)> {
        let rb = self.ring_buffer.take().ok_or_else(|| {
            AgentError::InvalidState("ringbuffer not initialized or already polling".into())
        })?;
        let runner = RingBufferRunner(rb);

        let stop_flag = Arc::new(AtomicBool::new(false));
        let flag_clone = Arc::clone(&stop_flag);

        let handle = tokio::task::spawn_blocking(move || {
            // Note on epoll vs poll(): `libbpf_rs::RingBuffer` uses a single epoll FD internally
            // to listen to all registered BPF maps. The `poll()` call executes `epoll_wait`
            // under the hood, blocking until an event arrives or the timeout hits.
            // Using `spawn_blocking` is the idiomatic way to handle this without
            // starving Tokio's async reactor.
            while !flag_clone.load(Ordering::Relaxed) {
                if let Err(e) = runner.0.poll(std::time::Duration::from_millis(100)) {
                    // Only log the error but don't exit the loop.
                    // EINTR or timeout shouldn't crash the polling thread.
                    warn!(error = %e, "ringbuffer poll error");
                }
            }
        });

        Ok((handle, stop_flag))
    }

    /// Returns a standalone handle to the BPF `comm_lpm_trie` map.
    /// The handle duplicates the underlying FD and is safe to send across threads.
    pub(crate) fn comm_lpm_trie_handle(&self) -> Result<libbpf_rs::MapHandle> {
        libbpf_rs::MapHandle::try_from(&self.skel.maps.comm_lpm_trie)
            .map_err(|e| AgentError::Bpf("failed to create comm_lpm_trie MapHandle".into(), e))
    }

    #[allow(dead_code)]
    pub(crate) fn monitor_pid(&self, tgid: u32) -> Result<()> {
        let active: u8 = 1;
        self.skel
            .maps
            .pid_filter_map
            .update(
                &tgid.to_ne_bytes(),
                &active.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .map_err(|e| AgentError::Bpf("failed to add tgid to filter map".into(), e))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn unmonitor_pid(&self, tgid: u32) -> Result<()> {
        self.skel
            .maps
            .pid_filter_map
            .delete(&tgid.to_ne_bytes())
            .map_err(|e| AgentError::Bpf("failed to remove tgid from filter map".into(), e))?;
        Ok(())
    }
}

pub(crate) struct ProfilerAgentBuilder {
    freq: u64,
    trigger_tx: Option<Sender<ProcessMatchEvent>>,
}

impl Default for ProfilerAgentBuilder {
    fn default() -> Self {
        Self {
            freq: DEFAULT_SAMPLING_FREQ_HZ,
            trigger_tx: None,
        }
    }
}

impl ProfilerAgentBuilder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[allow(dead_code)]
    pub(crate) fn with_freq(mut self, freq: u64) -> Self {
        self.freq = freq;
        self
    }

    pub(crate) fn with_trigger_tx(mut self, tx: Sender<ProcessMatchEvent>) -> Self {
        self.trigger_tx = Some(tx);
        self
    }

    pub(crate) fn try_build(self) -> Result<ProfilerAgent> {
        ProfilerAgent::try_new(self.freq, self.trigger_tx)
    }
}
