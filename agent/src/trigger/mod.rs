pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod matcher;
pub(crate) mod proc;
mod psi;
mod trie;
pub(crate) mod watcher;

use std::collections::HashMap;

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
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};
use trie::BpfTrie;
use watcher::ConfigWatcher;

/// Interval between periodic proc_walk scans.
const PROC_WALK_INTERVAL: Duration = Duration::from_secs(30);

const TRIGGER_CHANNEL_SIZE: usize = 1024;

/// A process matched a trigger rule.
pub(crate) struct ProcessMatchEvent {
    pub rule_id: u32,
    pub pid: u32,
    pub cgroup_path: Option<PathBuf>,
    pub comm: String,
}

pub(super) enum TriggerControl {
    Reload(Arc<TriggerConfig>),
}

/// Shared context for proc_walk spawning and TriggerAgent fields
/// that are always passed together.
struct ProcWalkContext {
    cgroup2_mount: PathBuf,
    proc_path: PathBuf,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    vdso_cache: Arc<Mutex<VdsoCache>>,
}

/// Intermediate state after channel + config are ready but before the BPF trie
/// handle is available.
pub(crate) struct PreparedTriggerAgent {
    config: Arc<TriggerConfig>,
    watcher: Box<dyn ConfigWatcher>,
    event_rx: Option<mpsc::Receiver<ProcessMatchEvent>>,
    walk_ctx: ProcWalkContext,
    tenant_id: String,
    /// Agent-level labels (merged with per-target labels at capture time).
    agent_labels: HashMap<String, String>,
}

impl PreparedTriggerAgent {
    /// Phase 1: Load initial config, create channel, resolve cgroup2 mount.
    pub(crate) async fn prepare(
        mut watcher: Box<dyn ConfigWatcher>,
        proc_path: PathBuf,
        cgroup_path: Option<PathBuf>,
        tenant_id: String,
        agent_labels: HashMap<String, String>,
    ) -> Result<Self> {
        let config = watcher.load_initial().await;
        let (event_tx, event_rx) = mpsc::channel::<ProcessMatchEvent>(TRIGGER_CHANNEL_SIZE);

        let cgroup2_mount = match cgroup_path {
            Some(path) => path,
            None => find_cgroup2_mount(&proc_path).map_err(|e| {
                error!(error = %e, "cgroup2 not mounted");
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
            watcher,
            event_rx: Some(event_rx),
            walk_ctx: ProcWalkContext {
                cgroup2_mount,
                proc_path,
                event_tx,
                vdso_cache: Arc::new(Mutex::new(VdsoCache::new())),
            },
            tenant_id,
            agent_labels,
        })
    }

    pub(crate) fn trigger_tx(&self) -> mpsc::Sender<ProcessMatchEvent> {
        self.walk_ctx.event_tx.clone()
    }

    /// Phase 2: Consume self, inject BPF handle + capture channel, start event loop.
    pub(crate) async fn start(
        mut self,
        comm_lpm_trie_handle: libbpf_rs::MapHandle,
        capture_tx: mpsc::Sender<CaptureRequest>,
        cancel: CancellationToken,
        vdso_cache: Arc<Mutex<VdsoCache>>,
        request_cooldown: Duration,
    ) -> Result<JoinHandle<()>> {
        let (control_tx, control_rx) = mpsc::channel::<TriggerControl>(8);

        let matcher = CommMatcher::new(&self.config);
        let mut bpf_trie = BpfTrie::new(comm_lpm_trie_handle);
        bpf_trie.repopulate(&self.config)?;

        // Replace the internally-created vdso_cache with the shared one from daemon.
        self.walk_ctx.vdso_cache = vdso_cache;

        let proc_walk_cancel = cancel.child_token();
        let proc_handle =
            TriggerAgent::spawn_proc_walk(&self.config, &self.walk_ctx, proc_walk_cancel.clone());

        let watcher_cancel = cancel.clone();
        let watcher_control_tx = control_tx.clone();
        let watcher_handle = tokio::spawn(async move {
            self.watcher.watch(watcher_control_tx, watcher_cancel).await;
        });

        let event_rx = self
            .event_rx
            .take()
            .expect("event_rx consumed before start");

        let mut agent = TriggerAgent {
            config: self.config,
            matcher,
            bpf_trie,
            psi_registry: PsiRegistry::new(capture_tx, request_cooldown),
            proc_handle: Some(proc_handle),
            watcher_handle: Some(watcher_handle),
            cancel,
            proc_walk_cancel,
            walk_ctx: self.walk_ctx,
            event_rx,
            control_rx,
            tenant_id: self.tenant_id,
            agent_labels: self.agent_labels,
        };

        let task_handle = tokio::spawn(async move {
            agent.run().await;
        });

        Ok(task_handle)
    }
}

struct TriggerAgent {
    config: Arc<TriggerConfig>,
    matcher: CommMatcher,
    bpf_trie: BpfTrie,
    psi_registry: PsiRegistry,
    proc_handle: Option<tokio::task::JoinHandle<()>>,
    watcher_handle: Option<tokio::task::JoinHandle<()>>,
    cancel: CancellationToken,
    proc_walk_cancel: CancellationToken,
    walk_ctx: ProcWalkContext,
    event_rx: mpsc::Receiver<ProcessMatchEvent>,
    control_rx: mpsc::Receiver<TriggerControl>,
    tenant_id: String,
    agent_labels: HashMap<String, String>,
}

impl TriggerAgent {
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
            Some(path) => path,
            None => match resolve_cgroup_path(
                &self.walk_ctx.cgroup2_mount,
                &self.walk_ctx.proc_path,
                event.pid,
            ) {
                Ok(path) => path,
                Err(e) => {
                    error!(pid = event.pid, error = %e, "cgroup resolution failed, skipping");
                    metrics::counter!(METRIC_CGROUP_RESOLVE_FAILURES).increment(1);
                    return;
                }
            },
        };

        if !self
            .matcher
            .match_comm(&event.comm)
            .contains(&event.rule_id)
        {
            debug!(
                rule_id = event.rule_id, comm = %event.comm, pid = event.pid,
                "stale event filtered",
            );
            metrics::counter!(METRIC_STALE_EVENTS).increment(1);
            return;
        }

        let target = self.config.target_for_rule(event.rule_id);
        let cgroup_id = cgroup_path_to_id(&cgroup_path);

        // Merge agent-level labels with target-level labels.
        // Target labels win on conflict.
        let mut merged_labels = self.agent_labels.clone();
        for (k, v) in &target.labels {
            merged_labels.insert(k.clone(), v.clone());
        }

        for res_cfg in &target.resources {
            match self.psi_registry.register(
                cgroup_id,
                &cgroup_path,
                res_cfg.resource,
                res_cfg.threshold,
                event.pid,
                event.comm.clone(),
                self.tenant_id.clone(),
                target.service_id.clone(),
                merged_labels.clone(),
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
    async fn reload(&mut self, new_config: Arc<TriggerConfig>) {
        self.proc_walk_cancel.cancel();
        if let Some(handle) = self.proc_handle.take() {
            let _ = handle.await;
        }

        self.psi_registry.shutdown();

        let new_matcher = CommMatcher::new(&new_config);
        if let Err(e) = self.bpf_trie.repopulate(&new_config) {
            error!(error = %e, "failed to repopulate BPF trie, rolling back");
            if let Err(e) = self.bpf_trie.repopulate(&self.config) {
                panic!("fatal: failed to restore previous BPF trie state: {}", e);
            }
            metrics::counter!(METRIC_CONFIG_RELOAD_FAILURES).increment(1);
        } else {
            self.matcher = new_matcher;
            self.config = new_config;
            metrics::counter!(METRIC_CONFIG_RELOADS).increment(1);
        }

        self.proc_walk_cancel = self.cancel.child_token();
        let handle =
            Self::spawn_proc_walk(&self.config, &self.walk_ctx, self.proc_walk_cancel.clone());
        self.proc_handle = Some(handle);
    }

    fn spawn_proc_walk(
        config: &Arc<TriggerConfig>,
        ctx: &ProcWalkContext,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let config = Arc::clone(config);
        let mount = ctx.cgroup2_mount.clone();
        let proc_path = ctx.proc_path.clone();
        let tx = ctx.event_tx.clone();
        let vdso_cache = ctx.vdso_cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(PROC_WALK_INTERVAL);
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

    fn cleanup(&mut self) {
        self.psi_registry.shutdown();
        if let Some(handle) = self.watcher_handle.take() {
            handle.abort();
        }
    }
}
