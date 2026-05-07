pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod matcher;
pub(crate) mod proc;
mod psi;
mod trie;
pub(crate) mod watcher;

use crate::sys::cgroup::SharedCgroupCache;
use config::TriggerConfig;
use error::Result;
use matcher::CommMatcher;
use proc::ProcWalker;
use psi::{PsiRegisterResult, PsiRegistry};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use trie::BpfTrie;

/// Interval between periodic proc_walk scans. Each scan discovers matching
/// processes that BPF exec tracing may have missed (duplicate-comm rules where
/// the BPF LPM trie stores only one rule_id, or fork-without-exec workers).
/// The BPF path is the fast path (immediate on exec); proc_walk is the
/// completeness guarantee (all rules covered within one interval).
const PROC_WALK_INTERVAL: Duration = Duration::from_secs(30);

/// Buffer size for the internal trigger event channel (BPF → TriggerAgent).
/// 1024 is generous for most deployments — events are consumed quickly by the
/// event loop, so backpressure is unlikely. Sized to absorb brief bursts from
/// concurrent proc_walk + BPF ringbuffer callbacks without dropping.
const TRIGGER_CHANNEL_SIZE: usize = 1024;

/// A process matched a trigger rule — the clean Rust-typed event used on channels.
/// Both ProcWalker and BPF ringbuffer callbacks produce this type.
pub(crate) struct ProcessMatchEvent {
    pub rule_id: u32,
    pub pid: u32,
    pub cgroup_id: u64,
    pub comm: String,
}

/// Control messages for the TriggerAgent event loop.
pub(super) enum TriggerControl {
    /// Hot-reload with a new configuration. Nukes PSI watchers, rebuilds matcher
    /// and proc_walk from scratch.
    Reload(Arc<TriggerConfig>),
}

/// Returned by `TriggerAgent::start` to give the caller handles for lifecycle management.
pub(crate) struct TriggerAgentHandle {
    pub(crate) task_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: oneshot::Sender<()>,
}

impl TriggerAgentHandle {
    /// Signals the event loop to stop and returns the task handle for the caller to await.
    pub(crate) fn shutdown(self) -> tokio::task::JoinHandle<()> {
        let _ = self.shutdown_tx.send(());
        self.task_handle
    }
}

// ---------------------------------------------------------------------------
// Metric counter names — constants prevent typos and centralize naming.
// ---------------------------------------------------------------------------

const METRIC_CGROUP_RESOLVE_FAILURES: &str = "bistouri_trigger_cgroup_resolve_failures";
const METRIC_PSI_FD_BUILD_FAILURES: &str = "bistouri_trigger_psi_fd_build_failures";
const METRIC_STALE_EVENTS: &str = "bistouri_trigger_stale_events";
const METRIC_DUPLICATE_PSI_SKIPS: &str = "bistouri_trigger_duplicate_psi_skips";
const METRIC_CONFIG_RELOADS: &str = "bistouri_trigger_config_reloads";
const METRIC_CONFIG_RELOAD_FAILURES: &str = "bistouri_trigger_config_reload_failures";

/// Registers metric descriptions with the `metrics` facade. Called once
/// during `prepare()` so that Prometheus help text is available before
/// any counters are incremented.
fn describe_metrics() {
    metrics::describe_counter!(
        METRIC_CGROUP_RESOLVE_FAILURES,
        "Number of cgroup resolution failures during event processing"
    );
    metrics::describe_counter!(
        METRIC_PSI_FD_BUILD_FAILURES,
        "Number of PSI file descriptor build failures"
    );
    metrics::describe_counter!(
        METRIC_STALE_EVENTS,
        "Number of stale events filtered after config reload"
    );
    metrics::describe_counter!(
        METRIC_DUPLICATE_PSI_SKIPS,
        "Number of duplicate PSI watcher registration attempts skipped"
    );
    metrics::describe_counter!(
        METRIC_CONFIG_RELOADS,
        "Number of successful configuration hot-reloads"
    );
    metrics::describe_counter!(
        METRIC_CONFIG_RELOAD_FAILURES,
        "Number of failed configuration hot-reload attempts"
    );
}

// ---------------------------------------------------------------------------
// Two-phase init
// ---------------------------------------------------------------------------

/// Intermediate state after channel + config are ready but before the BPF trie
/// handle is available. Resolves the circular dependency between ProfilerAgent
/// (needs the Sender) and TriggerAgent (needs the MapHandle).
pub(crate) struct PreparedTriggerAgent {
    config: Arc<TriggerConfig>,
    config_path: PathBuf,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    event_rx: Option<mpsc::Receiver<ProcessMatchEvent>>,
    cache: SharedCgroupCache,
}

impl PreparedTriggerAgent {
    /// Phase 1: Load config, create channel. No BPF dependency yet.
    pub(crate) async fn prepare(config_path: PathBuf, cache: SharedCgroupCache) -> Self {
        describe_metrics();
        let config = TriggerConfig::load_or_default(&config_path).await;
        let (event_tx, event_rx) = mpsc::channel::<ProcessMatchEvent>(TRIGGER_CHANNEL_SIZE);

        Self {
            config,
            config_path,
            event_tx,
            event_rx: Some(event_rx),
            cache,
        }
    }

    /// Returns a clone of the Sender for ProfilerAgent to use.
    pub(crate) fn trigger_tx(&self) -> mpsc::Sender<ProcessMatchEvent> {
        self.event_tx.clone()
    }

    /// Phase 2: Consume self, inject BPF handle, start the event loop.
    pub(crate) async fn start(
        mut self,
        comm_lpm_trie_handle: libbpf_rs::MapHandle,
    ) -> Result<TriggerAgentHandle> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (control_tx, control_rx) = mpsc::channel::<TriggerControl>(8);

        let matcher = CommMatcher::new(&self.config);
        let mut bpf_trie = BpfTrie::new(comm_lpm_trie_handle);
        bpf_trie.repopulate(&self.config)?;
        let cancel_token = CancellationToken::new();

        let proc_handle = TriggerAgent::spawn_proc_walk(
            &self.config,
            Arc::clone(&self.cache),
            self.event_tx.clone(),
            cancel_token.clone(),
        );

        // Spawn config file watcher — sends Reload messages on config changes.
        // Watcher setup failures are fatal: hot-reload is an inherent part of the system.
        let watcher_handle =
            TriggerAgent::spawn_config_watcher(self.config_path.clone(), control_tx);

        let event_rx = self
            .event_rx
            .take()
            .expect("event_rx consumed before start");

        let mut agent = TriggerAgent {
            config: self.config,
            matcher,
            bpf_trie,
            cache: self.cache,
            psi_registry: PsiRegistry::new(),
            proc_handle: Some(proc_handle),
            watcher_handle: Some(watcher_handle),
            cancel_token,
            event_tx: self.event_tx,
            event_rx,
            control_rx,
            shutdown_rx,
        };

        let task_handle = tokio::spawn(async move {
            agent.run().await;
        });

        Ok(TriggerAgentHandle {
            task_handle,
            shutdown_tx,
        })
    }
}

// ---------------------------------------------------------------------------
// TriggerAgent (private event loop)
// ---------------------------------------------------------------------------

struct TriggerAgent {
    config: Arc<TriggerConfig>,
    matcher: CommMatcher,
    bpf_trie: BpfTrie,
    cache: SharedCgroupCache,
    psi_registry: PsiRegistry,
    proc_handle: Option<tokio::task::JoinHandle<()>>,
    watcher_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_token: CancellationToken,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    event_rx: mpsc::Receiver<ProcessMatchEvent>,
    control_rx: mpsc::Receiver<TriggerControl>,
    shutdown_rx: oneshot::Receiver<()>,
}

impl TriggerAgent {
    /// Main event loop — processes events and control messages until shutdown.
    async fn run(&mut self) {
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
            }
        }
        self.shutdown();
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
                metrics::counter!(METRIC_CGROUP_RESOLVE_FAILURES).increment(1);
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
            metrics::counter!(METRIC_STALE_EVENTS).increment(1);
            return;
        }

        let target = self.config.target_for_rule(event.rule_id);

        match self.psi_registry.register(
            cgroup_id,
            &cgroup_path,
            target.resource,
            target.threshold,
            event.rule_id,
        ) {
            PsiRegisterResult::Registered => {
                info!(
                    rule_id = event.rule_id,
                    comm = %event.comm,
                    resource = ?target.resource,
                    threshold = target.threshold,
                    cgroup = %cgroup_path.display(),
                    "registered PSI trigger",
                );
            }
            PsiRegisterResult::AlreadyExists => {
                debug!(
                    rule_id = event.rule_id,
                    comm = %event.comm,
                    cgroup_id = cgroup_id,
                    resource = ?target.resource,
                    "PSI watcher already registered for this cgroup+resource, skipping",
                );
                metrics::counter!(METRIC_DUPLICATE_PSI_SKIPS).increment(1);
            }
            PsiRegisterResult::BuildFailed => {
                debug!(
                    cgroup = %cgroup_path.display(),
                    rule_id = event.rule_id,
                    "failed to build PSI fd, skipping",
                );
                metrics::counter!(METRIC_PSI_FD_BUILD_FAILURES).increment(1);
            }
        }
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
        self.psi_registry.shutdown();

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
            metrics::counter!(METRIC_CONFIG_RELOAD_FAILURES).increment(1);
        } else {
            self.matcher = new_matcher;
            self.config = new_config;
            metrics::counter!(METRIC_CONFIG_RELOADS).increment(1);
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

    fn spawn_config_watcher(
        config_path: PathBuf,
        control_tx: mpsc::Sender<TriggerControl>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = watcher::config_watcher_task(config_path, control_tx).await {
                error!(error = %e, "config watcher failed");
            }
        })
    }

    fn shutdown(&mut self) {
        self.psi_registry.shutdown();
        if let Some(handle) = self.watcher_handle.take() {
            handle.abort();
        }
    }
}
