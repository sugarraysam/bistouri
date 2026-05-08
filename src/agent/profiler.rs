use crate::agent::error::{AgentError, Result};
use crate::agent::ringbuf::AsyncRingBuffer;
use crate::capture::trace::StackSample;
use crate::trigger::ProcessMatchEvent;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;
use perf_event::{events::Software, Builder, Counter};
use std::os::fd::AsRawFd;
use tokio::sync::mpsc::{self, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

mod bpf {
    include!(concat!(env!("OUT_DIR"), "/profiler.skel.rs"));
}

const DEFAULT_SAMPLING_FREQ_HZ: u64 = 19;

pub(crate) const MAX_STACK_DEPTH: usize = 127;
pub(crate) const TASK_COMM_LEN: usize = 16;

const METRIC_STACK_RINGBUF_FULL: &str = "bistouri_profiler_stack_ringbuf_full";
const METRIC_STACK_FETCH_ERRORS: &str = "bistouri_profiler_stack_fetch_errors";
const METRIC_TRIGGER_RINGBUF_FULL: &str = "bistouri_profiler_trigger_ringbuf_full";
const METRIC_TRIGGER_CHANNEL_FULL: &str = "bistouri_profiler_trigger_channel_full";
const METRIC_STACK_CHANNEL_FULL: &str = "bistouri_profiler_stack_channel_full";
pub(super) const METRIC_RINGBUF_POLL_ERRORS: &str = "bistouri_profiler_ringbuf_poll_errors";

#[repr(C)]
#[derive(Debug, Clone)]
pub(crate) struct StackTraceEvent {
    pub pid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub kernel_stack_sz: i32,
    pub user_stack_sz: i32,
    pub kernel_stack: [u64; MAX_STACK_DEPTH],
    pub user_stack: [u64; MAX_STACK_DEPTH],
}

impl StackTraceEvent {
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
struct ProcessMatchBpfEvent {
    rule_id: u32,
    pid: u32,
    cgroup_id: u64,
    comm: [u8; TASK_COMM_LEN],
}

impl ProcessMatchBpfEvent {
    fn from_bytes(data: &[u8]) -> Option<&Self> {
        if data.len() == std::mem::size_of::<Self>() {
            Some(unsafe { &*data.as_ptr().cast::<Self>() })
        } else {
            None
        }
    }
}

impl From<&ProcessMatchBpfEvent> for ProcessMatchEvent {
    fn from(bpf: &ProcessMatchBpfEvent) -> Self {
        let comm = String::from_utf8_lossy(&bpf.comm)
            .trim_matches(char::from(0))
            .to_string();
        ProcessMatchEvent {
            rule_id: bpf.rule_id,
            pid: bpf.pid,
            cgroup_path: None,
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

// ---------------------------------------------------------------------------
// BPF error structs — tagged union matching profiler.h's error_event.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ErrReserveStackRingbuf {
    pid: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct ErrStackFetch {
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
    #[error("Failed to reserve stack ringbuffer for pid: {pid}")]
    ReserveStackRingbuf { pid: u32 },
    #[error("Failed to fetch {space} stack for pid: {pid}. Code: {ret_code}")]
    StackFetch {
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
                    Some(ProfilerError::ReserveStackRingbuf { pid: reserve.pid })
                }
                2 => {
                    // SAFETY: We verify the tag `kind == 2` before accessing the union field.
                    let fetch = unsafe { event.data.stack_fetch_err };
                    Some(ProfilerError::StackFetch {
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

    /// Increments the appropriate Prometheus counter for this error kind.
    /// BPF errors are never fatal — they indicate transient kernel-side
    /// resource contention. Operators monitor these via Prometheus alerts.
    fn record_metric(&self) {
        match self {
            ProfilerError::ReserveStackRingbuf { .. } => {
                metrics::counter!(METRIC_STACK_RINGBUF_FULL).increment(1);
            }
            ProfilerError::StackFetch { .. } => {
                metrics::counter!(METRIC_STACK_FETCH_ERRORS).increment(1);
            }
            ProfilerError::ReserveTriggerRingbuf { .. } => {
                metrics::counter!(METRIC_TRIGGER_RINGBUF_FULL).increment(1);
            }
            ProfilerError::Unknown(_) => {}
        }
    }
}

// ---------------------------------------------------------------------------
// ProfilerAgent — build → load → attach → poll lifecycle.
// ---------------------------------------------------------------------------

pub(crate) struct ProfilerAgent {
    freq: u64,
    ncpus: usize,
    trigger_tx: Option<Sender<ProcessMatchEvent>>,
    stack_tx: Sender<StackSample>,
}

impl ProfilerAgent {
    fn try_new(
        freq: u64,
        trigger_tx: Option<Sender<ProcessMatchEvent>>,
        stack_tx: Sender<StackSample>,
    ) -> Result<Self> {
        let ncpus = libbpf_rs::num_possible_cpus()
            .map_err(|e| AgentError::Bpf("failed to get possible CPUs".into(), e))?;
        Ok(Self {
            freq,
            ncpus,
            trigger_tx,
            stack_tx,
        })
    }

    pub(crate) fn load_and_attach(self) -> Result<LoadedProfilerAgent> {
        let mut object = Box::new(std::mem::MaybeUninit::uninit());
        let builder = bpf::ProfilerSkelBuilder::default();

        let open_skel = builder
            .open(&mut object)
            .map_err(|e| AgentError::Bpf("failed to open BPF skeleton".into(), e))?;

        let skel = open_skel.load().map_err(|e| {
            AgentError::Bpf(
                "failed to load BPF skeleton — ensure the kernel supports BPF ring buffers \
                 (Linux 5.8+) and that bistouri runs with CAP_BPF+CAP_PERFMON or as root"
                    .into(),
                e,
            )
        })?;

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

        loaded.setup_ringbuffers(self.trigger_tx, self.stack_tx)?;
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
    /// Registers callbacks for each BPF ring buffer map.
    ///
    /// **Design constraint:** Callbacks run inline during `consume()` on the
    /// async event loop. Keep them to O(1) operations (pointer casts, `try_send`).
    /// Heavy processing (symbolization, batching, network IO) belongs on a
    /// separate task fed via a channel.
    fn setup_ringbuffers(
        &mut self,
        trigger_tx: Option<Sender<ProcessMatchEvent>>,
        stack_tx: Sender<StackSample>,
    ) -> Result<()> {
        let mut builder = libbpf_rs::RingBufferBuilder::new();

        builder
            .add(&self.skel.maps.stack_events, move |data| {
                if let Some(event) = StackTraceEvent::from_bytes(data) {
                    let sample = StackSample::from_event(event);
                    if let Err(mpsc::error::TrySendError::Full(_)) = stack_tx.try_send(sample) {
                        error!(
                            "stack sample channel full, samples being dropped — \
                             consider doubling STACK_SAMPLE_CHANNEL_SIZE",
                        );
                        metrics::counter!(METRIC_STACK_CHANNEL_FULL).increment(1);
                    }
                }
                0
            })
            .map_err(|e| AgentError::Bpf("failed to add stack_events ringbuffer".into(), e))?;

        builder
            .add(&self.skel.maps.errors, |data| {
                if let Some(err) = ProfilerError::from_bytes(data) {
                    // BPF errors are never fatal — they indicate transient
                    // kernel-side resource contention (ring buffer full, stack
                    // fetch failure). We increment Prometheus counters for
                    // operators to alert on externally and log at debug level.
                    debug!(error = %err, "BPF error event");
                    err.record_metric();
                }
                0
            })
            .map_err(|e| AgentError::Bpf("failed to add errors ringbuffer".into(), e))?;

        if let Some(tx) = trigger_tx {
            builder
                .add(&self.skel.maps.trigger_events, move |data| {
                    if let Some(bpf_event) = ProcessMatchBpfEvent::from_bytes(data) {
                        // Trigger events are best-effort: dropping on channel-full
                        // is safe because proc_walk provides the completeness
                        // guarantee — all matching processes are discovered within
                        // one scan interval (eventual consistency).
                        if let Err(mpsc::error::TrySendError::Full(_)) =
                            tx.try_send(bpf_event.into())
                        {
                            metrics::counter!(METRIC_TRIGGER_CHANNEL_FULL).increment(1);
                        }
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

    /// Registers metric descriptions for all profiler counters.
    fn describe_metrics() {
        metrics::describe_counter!(
            METRIC_STACK_RINGBUF_FULL,
            "BPF stack ring buffer reservation failures (64MB buffer full)"
        );
        metrics::describe_counter!(
            METRIC_STACK_FETCH_ERRORS,
            "BPF bpf_get_stack() failures (transient, process likely exited)"
        );
        metrics::describe_counter!(
            METRIC_TRIGGER_RINGBUF_FULL,
            "BPF trigger ring buffer reservation failures (256KB buffer full)"
        );
        metrics::describe_counter!(
            METRIC_TRIGGER_CHANNEL_FULL,
            "Trigger events dropped due to full channel (proc_walk provides completeness)"
        );
        metrics::describe_counter!(
            METRIC_STACK_CHANNEL_FULL,
            "Stack samples dropped due to full channel (statistical loss at 19Hz)"
        );
        metrics::describe_counter!(
            METRIC_RINGBUF_POLL_ERRORS,
            "Epoll errors on ring buffer fd (unrecoverable, polling stops)"
        );
    }

    /// Starts asynchronous ring buffer polling using tokio's IO reactor.
    ///
    /// Wraps the ring buffer in `AsyncRingBuffer` which registers the internal
    /// epoll fd with tokio. Runs as a regular async task — no blocking thread needed.
    pub(crate) fn start_polling(
        &mut self,
        cancel: CancellationToken,
    ) -> Result<tokio::task::JoinHandle<()>> {
        Self::describe_metrics();

        let rb = self.ring_buffer.take().ok_or_else(|| {
            AgentError::InvalidState("ringbuffer not initialized or already polling".into())
        })?;

        let mut async_rb = AsyncRingBuffer::new(rb)?;

        let handle = tokio::spawn(async move {
            async_rb.run(cancel).await;
        });

        Ok(handle)
    }

    /// Returns a standalone handle to the BPF `comm_lpm_trie` map.
    /// The handle duplicates the underlying FD and is safe to send across threads.
    pub(crate) fn comm_lpm_trie_handle(&self) -> Result<libbpf_rs::MapHandle> {
        libbpf_rs::MapHandle::try_from(&self.skel.maps.comm_lpm_trie)
            .map_err(|e| AgentError::Bpf("failed to create comm_lpm_trie MapHandle".into(), e))
    }

    /// Returns a standalone handle to the BPF `pid_filter_map`.
    /// Used by `BpfPidFilter` to add/remove monitored PIDs.
    pub(crate) fn pid_filter_handle(&self) -> Result<libbpf_rs::MapHandle> {
        libbpf_rs::MapHandle::try_from(&self.skel.maps.pid_filter_map)
            .map_err(|e| AgentError::Bpf("failed to create pid_filter MapHandle".into(), e))
    }

    #[allow(dead_code)]
    pub(crate) fn monitor_pid(&self, pid: u32) -> Result<()> {
        let active: u8 = 1;
        self.skel
            .maps
            .pid_filter_map
            .update(
                &pid.to_ne_bytes(),
                &active.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .map_err(|e| AgentError::Bpf("failed to add pid to filter map".into(), e))?;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn unmonitor_pid(&self, pid: u32) -> Result<()> {
        self.skel
            .maps
            .pid_filter_map
            .delete(&pid.to_ne_bytes())
            .map_err(|e| AgentError::Bpf("failed to remove pid from filter map".into(), e))?;
        Ok(())
    }
}

pub(crate) struct ProfilerAgentBuilder {
    freq: u64,
    trigger_tx: Option<Sender<ProcessMatchEvent>>,
    stack_tx: Option<Sender<StackSample>>,
}

impl Default for ProfilerAgentBuilder {
    fn default() -> Self {
        Self {
            freq: DEFAULT_SAMPLING_FREQ_HZ,
            trigger_tx: None,
            stack_tx: None,
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

    pub(crate) fn with_stack_tx(mut self, tx: Sender<StackSample>) -> Self {
        self.stack_tx = Some(tx);
        self
    }

    pub(crate) fn try_build(self) -> Result<ProfilerAgent> {
        let stack_tx = self
            .stack_tx
            .ok_or_else(|| AgentError::InvalidState("stack_tx is required".into()))?;
        ProfilerAgent::try_new(self.freq, self.trigger_tx, stack_tx)
    }
}
