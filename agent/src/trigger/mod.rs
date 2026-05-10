pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod matcher;
pub(crate) mod proc;
mod psi;
mod trie;
pub(crate) mod watcher;

use crate::capture::session::CaptureRequest;
use crate::capture::vdso::VdsoCache;
use crate::sys::cgroup::{cgroup_path_to_id, find_cgroup2_mount, resolve_cgroup_path};
use crate::telemetry::{
    METRIC_CGROUP_RESOLVE_FAILURES, METRIC_CONFIG_RELOADS, METRIC_CONFIG_RELOAD_FAILURES,
    METRIC_PSI_FD_BUILD_FAILURES, METRIC_STALE_EVENTS,
};
use config::TriggerConfig;
use error::Result;
use matcher::CommMatcher;
use proc::ProcWalker;
use psi::{PsiRegisterResult, PsiRegistry};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
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
    /// Pre-resolved by proc_walk (`Some`), or needs inline resolution for BPF
    /// events (`None`) via `/proc/<pid>/cgroup`.
    pub cgroup_path: Option<PathBuf>,
    pub comm: String,
}

/// Control messages for the TriggerAgent event loop.
pub(super) enum TriggerControl {
    /// Hot-reload with a new configuration. Nukes PSI watchers, rebuilds matcher
    /// and proc_walk from scratch.
    Reload(Arc<TriggerConfig>),
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
    cgroup2_mount: PathBuf,
    proc_path: PathBuf,
}

impl PreparedTriggerAgent {
    /// Phase 1: Load config, create channel, resolve cgroup2 mount. No BPF dependency yet.
    ///
    /// `proc_path` should point to procfs (e.g. `/host/proc` in container
    /// deployments). `cgroup_path` overrides auto-detection from the mount
    /// table when set.
    pub(crate) async fn prepare(
        config_path: PathBuf,
        proc_path: PathBuf,
        cgroup_path: Option<PathBuf>,
    ) -> Result<Self> {
        let config = TriggerConfig::load_or_default(&config_path).await;
        let (event_tx, event_rx) = mpsc::channel::<ProcessMatchEvent>(TRIGGER_CHANNEL_SIZE);

        let cgroup2_mount = match cgroup_path {
            Some(path) => path,
            None => find_cgroup2_mount(&proc_path).map_err(|e| {
                error!(
                    error = %e,
                "cgroup2 is not mounted — bistouri requires cgroup2 for PSI triggers. \
                 Mount with: mount -t cgroup2 none /sys/fs/cgroup",
                );
                error::TriggerError::Cgroup2NotMounted(e)
            })?,
        };

        info!(
            proc_path = %proc_path.display(),
            cgroup2_mount = %cgroup2_mount.display(),
            "resolved filesystem paths",
        );

        Ok(Self {
            config,
            config_path,
            event_tx,
            event_rx: Some(event_rx),
            cgroup2_mount,
            proc_path,
        })
    }

    /// Returns a clone of the Sender for ProfilerAgent to use.
    pub(crate) fn trigger_tx(&self) -> mpsc::Sender<ProcessMatchEvent> {
        self.event_tx.clone()
    }

    /// Phase 2: Consume self, inject BPF handle, capture channel, and
    /// cancellation token, then start the event loop.
    pub(crate) async fn start(
        mut self,
        comm_lpm_trie_handle: libbpf_rs::MapHandle,
        capture_tx: mpsc::Sender<CaptureRequest>,
        cancel: CancellationToken,
        vdso_cache: Arc<Mutex<VdsoCache>>,
    ) -> Result<JoinHandle<()>> {
        let (control_tx, control_rx) = mpsc::channel::<TriggerControl>(8);

        let matcher = CommMatcher::new(&self.config);
        let mut bpf_trie = BpfTrie::new(comm_lpm_trie_handle);
        bpf_trie.repopulate(&self.config)?;

        // proc_walk uses a child token: the parent (daemon) cancel reaches it,
        // but config reload can also cancel just the walk independently.
        let proc_walk_cancel = cancel.child_token();

        let proc_handle = TriggerAgent::spawn_proc_walk(
            &self.config,
            &self.cgroup2_mount,
            &self.proc_path,
            self.event_tx.clone(),
            proc_walk_cancel.clone(),
            vdso_cache.clone(),
        );

        // Spawn config file watcher with the daemon's cancel token.
        let watcher_handle = TriggerAgent::spawn_config_watcher(
            self.config_path.clone(),
            control_tx,
            cancel.clone(),
        );

        let event_rx = self
            .event_rx
            .take()
            .expect("event_rx consumed before start");

        let mut agent = TriggerAgent {
            config: self.config,
            matcher,
            bpf_trie,
            cgroup2_mount: self.cgroup2_mount,
            proc_path: self.proc_path,
            psi_registry: PsiRegistry::new(capture_tx),
            proc_handle: Some(proc_handle),
            watcher_handle: Some(watcher_handle),
            cancel,
            proc_walk_cancel,
            event_tx: self.event_tx,
            event_rx,
            control_rx,
            vdso_cache,
        };

        let task_handle = tokio::spawn(async move {
            agent.run().await;
        });

        Ok(task_handle)
    }
}

// ---------------------------------------------------------------------------
// TriggerAgent (private event loop)
// ---------------------------------------------------------------------------

struct TriggerAgent {
    config: Arc<TriggerConfig>,
    matcher: CommMatcher,
    bpf_trie: BpfTrie,
    cgroup2_mount: PathBuf,
    proc_path: PathBuf,
    psi_registry: PsiRegistry,
    proc_handle: Option<tokio::task::JoinHandle<()>>,
    watcher_handle: Option<tokio::task::JoinHandle<()>>,
    /// Daemon-level cancel token — triggers full shutdown.
    cancel: CancellationToken,
    /// Child token for proc_walk — cancelled on reload AND on daemon shutdown.
    proc_walk_cancel: CancellationToken,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    event_rx: mpsc::Receiver<ProcessMatchEvent>,
    control_rx: mpsc::Receiver<TriggerControl>,
    vdso_cache: Arc<Mutex<VdsoCache>>,
}

impl TriggerAgent {
    /// Main event loop — processes events and control messages until cancelled.
    async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
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
        self.cleanup();
    }

    fn handle_process_event(&mut self, event: ProcessMatchEvent) {
        let cgroup_path = match event.cgroup_path {
            // proc_walk already resolved the path.
            Some(path) => path,
            // BPF event: inline /proc/<pid>/cgroup read (~10-50µs).
            None => match resolve_cgroup_path(&self.cgroup2_mount, &self.proc_path, event.pid) {
                Ok(path) => path,
                Err(e) => {
                    error!(
                        pid = event.pid,
                        error = %e,
                        "cgroup resolution failed for BPF event, skipping",
                    );
                    metrics::counter!(METRIC_CGROUP_RESOLVE_FAILURES).increment(1);
                    return;
                }
            },
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
        let cgroup_id = cgroup_path_to_id(&cgroup_path);

        for res_cfg in &target.resources {
            match self.psi_registry.register(
                cgroup_id,
                &cgroup_path,
                res_cfg.resource,
                res_cfg.threshold,
                event.pid,
                event.comm.clone(),
            ) {
                PsiRegisterResult::Registered => {
                    info!(
                        rule_id = event.rule_id,
                        comm = %event.comm,
                        resource = ?res_cfg.resource,
                        threshold = res_cfg.threshold,
                        cgroup = %cgroup_path.display(),
                        "registered PSI trigger",
                    );
                }
                PsiRegisterResult::AlreadyExists => {
                    debug!(
                        rule_id = event.rule_id,
                        comm = %event.comm,
                        cgroup_id = cgroup_id,
                        resource = ?res_cfg.resource,
                        "PSI watcher already registered for this cgroup+resource, skipping",
                    );
                }
                PsiRegisterResult::BuildFailed => {
                    debug!(
                        cgroup = %cgroup_path.display(),
                        rule_id = event.rule_id,
                        resource = ?res_cfg.resource,
                        "failed to build PSI fd, skipping",
                    );
                    metrics::counter!(METRIC_PSI_FD_BUILD_FAILURES).increment(1);
                }
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
        // 1. Cancel running proc_walk via child token
        self.proc_walk_cancel.cancel();
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

        // 4. Spawn new proc_walk with a fresh child token.
        self.proc_walk_cancel = self.cancel.child_token();
        let handle = Self::spawn_proc_walk(
            &self.config,
            &self.cgroup2_mount,
            &self.proc_path,
            self.event_tx.clone(),
            self.proc_walk_cancel.clone(),
            self.vdso_cache.clone(),
        );
        self.proc_handle = Some(handle);
    }

    /// Spawns a periodic proc_walk loop. The first scan runs immediately,
    /// then repeats every `PROC_WALK_INTERVAL`. Each individual walk runs
    /// in `spawn_blocking` to protect the event loop.
    fn spawn_proc_walk(
        config: &Arc<TriggerConfig>,
        cgroup2_mount: &Path,
        proc_path: &Path,
        tx: mpsc::Sender<ProcessMatchEvent>,
        cancel: CancellationToken,
        vdso_cache: Arc<Mutex<VdsoCache>>,
    ) -> tokio::task::JoinHandle<()> {
        let config = Arc::clone(config);
        let mount = cgroup2_mount.to_path_buf();
        let proc_path = proc_path.to_path_buf();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROC_WALK_INTERVAL);
            // First tick fires immediately; subsequent ticks maintain cadence
            // even if a walk overruns (Delay is the default, no ticks are skipped).
            loop {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = interval.tick() => {},
                }
                let config = Arc::clone(&config);
                let mount = mount.clone();
                let proc_path = proc_path.clone();
                let tx = tx.clone();
                let cancel = cancel.clone();
                let vdso_cache = vdso_cache.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let walker = ProcWalker::new(&config, &mount, &proc_path);
                    walker.walk(&tx, &cancel, &vdso_cache);
                })
                .await;
            }
        })
    }

    fn spawn_config_watcher(
        config_path: PathBuf,
        control_tx: mpsc::Sender<TriggerControl>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {},
                result = watcher::config_watcher_task(config_path, control_tx) => {
                    if let Err(e) = result {
                        error!(error = %e, "config watcher failed");
                    }
                },
            }
        })
    }

    /// Cleanup on shutdown — abort PSI watchers and config watcher.
    fn cleanup(&mut self) {
        self.psi_registry.shutdown();
        if let Some(handle) = self.watcher_handle.take() {
            handle.abort();
        }
    }
}
