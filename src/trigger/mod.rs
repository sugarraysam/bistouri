pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod matcher;
pub(crate) mod proc;
pub(crate) mod watcher;

use crate::agent::profiler::TASK_COMM_LEN;
use crate::sys::cgroup::SharedCgroupCache;
use config::{MatchRule, PsiResource, TriggerConfig};
use error::{Result, TriggerError};
use libbpf_rs::MapCore;
use matcher::CommMatcher;
use proc::ProcWalker;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

/// Fixed PSI time window: all thresholds are expressed as a percentage of this.
const TIME_WINDOW_MS: u64 = 1_000;

/// Interval between periodic proc_walk scans. Each scan discovers matching
/// processes that BPF exec tracing may have missed (duplicate-comm rules where
/// the BPF LPM trie stores only one rule_id, or fork-without-exec workers).
/// The BPF path is the fast path (immediate on exec); proc_walk is the
/// completeness guarantee (all rules covered within one interval).
const PROC_WALK_INTERVAL: Duration = Duration::from_secs(30);

/// A process matched a trigger rule — the clean Rust-typed event used on channels.
/// Both ProcWalker and BPF ringbuffer callbacks produce this type.
pub(crate) struct ProcessMatchEvent {
    pub rule_id: u32,
    pub pid: u32,
    pub cgroup_id: u64,
    pub comm: String,
}

/// Layout-compatible with the BPF `struct comm_lpm_key` in profiler.h.
#[repr(C)]
struct CommLpmKey {
    prefixlen: u32,
    comm: [u8; TASK_COMM_LEN],
}

impl CommLpmKey {
    fn to_bytes(&self) -> &[u8] {
        // SAFETY: CommLpmKey is #[repr(C)] with no padding ambiguity.
        // The struct is trivially copyable and the returned slice borrows self.
        unsafe {
            std::slice::from_raw_parts(
                (self as *const CommLpmKey) as *const u8,
                std::mem::size_of::<CommLpmKey>(),
            )
        }
    }

    fn from_rule(rule: &MatchRule) -> Self {
        let mut key = CommLpmKey {
            prefixlen: 0,
            comm: [0; TASK_COMM_LEN],
        };
        match rule {
            MatchRule::Exact { comm } => {
                let bytes = comm.as_bytes();
                key.comm[..bytes.len()].copy_from_slice(bytes);
                // +1 accounts for the NUL terminator position, differentiating
                // "node" from "nodejs" at the bit-prefix level.
                key.prefixlen = ((bytes.len() + 1) * 8) as u32;
            }
            MatchRule::Prefix { comm } => {
                let bytes = comm.as_bytes();
                key.comm[..bytes.len()].copy_from_slice(bytes);
                key.prefixlen = (bytes.len() * 8) as u32;
            }
        }
        key
    }
}

/// Owns a `MapHandle` to the BPF `comm_lpm_trie` map and tracks inserted
/// keys on the Rust side to avoid relying on kernel-side LPM trie iteration.
struct BpfTrie {
    map: libbpf_rs::MapHandle,
    inserted_keys: Vec<Vec<u8>>,
}

impl BpfTrie {
    fn new(map: libbpf_rs::MapHandle) -> Self {
        Self {
            map,
            inserted_keys: Vec::new(),
        }
    }

    /// Clears all existing entries and repopulates from the given config.
    fn repopulate(&mut self, config: &TriggerConfig) -> Result<()> {
        // Delete previously inserted keys. Ignore ENOENT — the entry may
        // have been removed by a concurrent BPF program (harmless race).
        for key in self.inserted_keys.drain(..) {
            let _ = self.map.delete(&key);
        }

        for target in &config.targets {
            let key = CommLpmKey::from_rule(&target.rule);
            let key_bytes = key.to_bytes();

            self.map
                .update(
                    key_bytes,
                    &target.rule_id.to_ne_bytes(),
                    libbpf_rs::MapFlags::ANY,
                )
                .map_err(TriggerError::BpfTrieUpdate)?;

            self.inserted_keys.push(key_bytes.to_vec());
        }

        Ok(())
    }
}

/// Control messages for the TriggerAgent event loop.
pub(crate) enum TriggerControl {
    /// Hot-reload with a new configuration. Nukes PSI watchers, rebuilds matcher
    /// and proc_walk from scratch.
    Reload(Arc<TriggerConfig>),
}

/// Returned by `TriggerAgent::start` to give the caller handles for lifecycle management.
pub(crate) struct TriggerAgentHandle {
    pub(crate) task_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: oneshot::Sender<()>,
    control_tx: mpsc::Sender<TriggerControl>,
}

impl TriggerAgentHandle {
    /// Signals the event loop to stop and returns the task handle for the caller to await.
    pub(crate) fn shutdown(self) -> tokio::task::JoinHandle<()> {
        let _ = self.shutdown_tx.send(());
        self.task_handle
    }

    /// Returns a clone of the control channel sender for external producers
    /// (e.g., config file watcher).
    pub(crate) fn control_tx(&self) -> mpsc::Sender<TriggerControl> {
        self.control_tx.clone()
    }
}

/// Aggregates non-fatal operational event counts for periodic summary logging.
/// Prevents per-occurrence log spam while surfacing sustained failure patterns.
struct ErrorCounters {
    cgroup_resolve_failures: u64,
    psi_fd_build_failures: u64,
    stale_events: u64,
    duplicate_psi_skips: u64,
}

impl ErrorCounters {
    fn new() -> Self {
        Self {
            cgroup_resolve_failures: 0,
            psi_fd_build_failures: 0,
            stale_events: 0,
            duplicate_psi_skips: 0,
        }
    }

    fn has_counts(&self) -> bool {
        self.cgroup_resolve_failures > 0
            || self.psi_fd_build_failures > 0
            || self.stale_events > 0
            || self.duplicate_psi_skips > 0
    }

    /// Logs aggregated counts and resets. Called once per PROC_WALK_INTERVAL.
    fn report_and_reset(&mut self) {
        if self.has_counts() {
            warn!(
                cgroup_resolve_failures = self.cgroup_resolve_failures,
                psi_fd_build_failures = self.psi_fd_build_failures,
                stale_events = self.stale_events,
                duplicate_psi_skips = self.duplicate_psi_skips,
                "trigger agent event summary since last report",
            );
            self.cgroup_resolve_failures = 0;
            self.psi_fd_build_failures = 0;
            self.stale_events = 0;
            self.duplicate_psi_skips = 0;
        }
    }
}

pub(crate) struct TriggerAgent {
    config: Arc<TriggerConfig>,
    matcher: CommMatcher,
    bpf_trie: BpfTrie,
    cache: SharedCgroupCache,
    psi_registry: HashMap<(u64, PsiResource), tokio::task::JoinHandle<()>>,
    proc_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_token: CancellationToken,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    event_rx: mpsc::Receiver<ProcessMatchEvent>,
    control_rx: mpsc::Receiver<TriggerControl>,
    shutdown_rx: oneshot::Receiver<()>,
    error_counters: ErrorCounters,
    report_interval: tokio::time::Interval,
}

impl TriggerAgent {
    /// Creates and starts the trigger agent. Returns a handle for shutdown and control.
    pub(crate) async fn start(
        config: Arc<TriggerConfig>,
        comm_lpm_trie_handle: libbpf_rs::MapHandle,
        cache: SharedCgroupCache,
        event_tx: mpsc::Sender<ProcessMatchEvent>,
        event_rx: mpsc::Receiver<ProcessMatchEvent>,
    ) -> Result<TriggerAgentHandle> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (control_tx, control_rx) = mpsc::channel::<TriggerControl>(8);

        let matcher = CommMatcher::new(&config);
        let mut bpf_trie = BpfTrie::new(comm_lpm_trie_handle);
        bpf_trie.repopulate(&config)?;
        let cancel_token = CancellationToken::new();

        let proc_handle = Self::spawn_proc_walk(
            &config,
            Arc::clone(&cache),
            event_tx.clone(),
            cancel_token.clone(),
        );

        let mut agent = TriggerAgent {
            config,
            matcher,
            bpf_trie,
            cache,
            psi_registry: HashMap::new(),
            proc_handle: Some(proc_handle),
            cancel_token,
            event_tx,
            event_rx,
            control_rx,
            shutdown_rx,
            error_counters: ErrorCounters::new(),
            report_interval: tokio::time::interval(PROC_WALK_INTERVAL),
        };

        let task_handle = tokio::spawn(async move {
            agent.run().await;
        });

        Ok(TriggerAgentHandle {
            task_handle,
            shutdown_tx,
            control_tx,
        })
    }

    /// Main event loop — processes events and control messages until shutdown.
    async fn run(&mut self) {
        // Consume the first immediate tick so the interval starts counting
        // from now rather than firing a spurious report on the first select.
        self.report_interval.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = &mut self.shutdown_rx => break,
                ctrl = self.control_rx.recv() => match ctrl {
                    Some(TriggerControl::Reload(new_config)) => self.reload(new_config).await,
                    None => break,
                },
                event = self.event_rx.recv() => match event {
                    None => break,
                    Some(e) => self.handle_process_event(e),
                },
                _ = self.report_interval.tick() => {
                    self.error_counters.report_and_reset();
                },
            }
        }
        self.shutdown_watchers();
    }

    fn handle_process_event(&mut self, event: ProcessMatchEvent) {
        let cgroup_id = event.cgroup_id;
        let cgroup_path = match self
            .cache
            .write()
            .unwrap()
            .resolve_cgroup_fallback(cgroup_id, event.pid)
        {
            Ok(path) => path,
            Err(e) => {
                debug!(
                    pid = event.pid,
                    cgroup_id = cgroup_id,
                    error = %e,
                    "cgroup resolution failed, skipping event",
                );
                self.error_counters.cgroup_resolve_failures += 1;
                return;
            }
        };

        // Re-validate: confirm the comm still matches the rule in the current config.
        // Filters out stale events from a pre-reload BPF trie state.
        if !self
            .matcher
            .match_comm(&event.comm)
            .contains(&event.rule_id)
        {
            debug!(
                rule_id = event.rule_id,
                comm = %event.comm,
                pid = event.pid,
                "stale event filtered: rule_id no longer matches current config",
            );
            self.error_counters.stale_events += 1;
            return;
        }

        let target = self.config.target_for_rule(event.rule_id);
        let registry_key = (cgroup_id, target.resource);

        // One PSI fd per (cgroup, resource) — first matching event wins.
        // Subsequent PIDs in the same cgroup for the same resource are no-ops
        // (expected: multiple PIDs with the same comm often coexist in a cgroup).
        if self.psi_registry.contains_key(&registry_key) {
            debug!(
                rule_id = event.rule_id,
                comm = %event.comm,
                cgroup_id = cgroup_id,
                resource = ?target.resource,
                "PSI watcher already registered for this cgroup+resource, skipping",
            );
            self.error_counters.duplicate_psi_skips += 1;
            return;
        }

        let async_fd =
            match Self::build_psi_async_fd(&cgroup_path, target.resource, target.threshold) {
                Ok(fd) => fd,
                Err(e) => {
                    // Non-fatal: the cgroup may have been removed between resolution
                    // and PSI fd creation (TOCTOU race). The registry key stays
                    // absent so a future event can retry.
                    debug!(
                        cgroup = %cgroup_path.display(),
                        error = %e,
                        "failed to build PSI fd, skipping",
                    );
                    self.error_counters.psi_fd_build_failures += 1;
                    return;
                }
            };

        info!(
            rule_id = event.rule_id,
            comm = %event.comm,
            resource = ?target.resource,
            threshold = target.threshold,
            cgroup = %cgroup_path.display(),
            "registered PSI trigger",
        );

        let watcher = Self::spawn_psi_watcher(async_fd, event.rule_id, cgroup_path);
        self.psi_registry.insert(registry_key, watcher);
    }

    fn build_psi_async_fd(
        cgroup_path: &Path,
        resource: PsiResource,
        threshold: u8,
    ) -> Result<AsyncFd<presutaoru::PsiFd>> {
        let entry = presutaoru::PsiEntry::Cgroup(resource.into(), cgroup_path);
        let stall_amount = Duration::from_millis((threshold as u64 * TIME_WINDOW_MS) / 100);

        let psi_fd = presutaoru::PsiFdBuilder::default()
            .entry(entry)
            .stall_type(presutaoru::StallType::Some)
            .time_window(Duration::from_millis(TIME_WINDOW_MS))
            .stall_amount(stall_amount)
            .build()
            .map_err(|e| TriggerError::PsiFdBuild {
                path: cgroup_path.to_path_buf(),
                source: e,
            })?;

        let async_fd = AsyncFd::new(psi_fd).map_err(TriggerError::AsyncFd)?;
        Ok(async_fd)
    }

    fn spawn_psi_watcher(
        async_fd: AsyncFd<presutaoru::PsiFd>,
        rule_id: u32,
        cgroup_path: PathBuf,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            while let Ok(mut guard) = async_fd.readable().await {
                guard.clear_ready();
                info!(
                    rule_id = rule_id,
                    cgroup = %cgroup_path.display(),
                    "PSI threshold exceeded",
                );
                // TODO: forward trigger event to the profiler sampling
                // module (not yet implemented).
            }
        })
    }

    /// Hot-reload: cancel current walk, nuke PSI watchers, rebuild with new config.
    ///
    /// Runs inline in the event loop rather than in `spawn_blocking` because every
    /// step is cheap: `cancel()` flips an atomic, `handle.await` returns near-instantly
    /// since `walk()` checks cancellation between PIDs, PSI handle aborts are O(1),
    /// and trie construction is trivially fast for realistic config sizes.
    /// Moving this to a background task would require `Arc<Mutex<>>` on the PSI
    /// registry for no measurable benefit.
    async fn reload(&mut self, new_config: Arc<TriggerConfig>) {
        // 1. Cancel running proc_walk
        self.cancel_token.cancel();
        if let Some(handle) = self.proc_handle.take() {
            let _ = handle.await;
        }

        // 2. Nuke PSI registry — abort all watcher tasks
        self.shutdown_watchers();

        // 3. Rebuild matcher and BPF trie with new config.
        //    If the BPF trie update fails, roll back entirely to avoid
        //    split-brain (userspace matcher on new config, BPF trie on old).
        let new_matcher = CommMatcher::new(&new_config);
        if let Err(e) = self.bpf_trie.repopulate(&new_config) {
            error!(
                error = %e,
                "failed to repopulate BPF trie, rolling back to previous config",
            );
            // Restore old trie state — if this also fails we are in an
            // unrecoverable state with an inconsistent BPF trie.
            if let Err(e) = self.bpf_trie.repopulate(&self.config) {
                panic!("fatal: failed to restore previous BPF trie state: {}", e);
            }
        } else {
            self.matcher = new_matcher;
            self.config = new_config;
        }

        // 4. Spawn new proc_walk with whatever config we ended up with.
        self.cancel_token = CancellationToken::new();
        let handle = Self::spawn_proc_walk(
            &self.config,
            Arc::clone(&self.cache),
            self.event_tx.clone(),
            self.cancel_token.clone(),
        );
        self.proc_handle = Some(handle);
    }

    /// Spawns a periodic proc_walk loop. The first scan runs immediately,
    /// then repeats every `PROC_WALK_INTERVAL`. Each individual walk runs
    /// in `spawn_blocking` to protect the event loop.
    fn spawn_proc_walk(
        config: &Arc<TriggerConfig>,
        cache: SharedCgroupCache,
        tx: mpsc::Sender<ProcessMatchEvent>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let config = Arc::clone(config);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROC_WALK_INTERVAL);
            // First tick fires immediately; subsequent ticks maintain cadence
            // even if a walk overruns (Delay is the default, no ticks are skipped).
            loop {
                interval.tick().await;
                if cancel.is_cancelled() {
                    break;
                }
                let cfg = Arc::clone(&config);
                let c = cache.clone();
                let t = tx.clone();
                let ct = cancel.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let walker = ProcWalker::new(&cfg, c);
                    walker.walk(&t, &ct);
                })
                .await;
            }
        })
    }

    fn shutdown_watchers(&mut self) {
        for (_, handle) in self.psi_registry.drain() {
            handle.abort();
        }
    }
}

impl From<PsiResource> for presutaoru::CgroupEntryType {
    fn from(resource: PsiResource) -> Self {
        match resource {
            PsiResource::Memory => presutaoru::CgroupEntryType::Memory,
            PsiResource::Cpu => presutaoru::CgroupEntryType::Cpu,
            PsiResource::Io => presutaoru::CgroupEntryType::Io,
        }
    }
}
