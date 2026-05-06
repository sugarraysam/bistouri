pub(crate) mod config;
pub(crate) mod error;
pub(crate) mod matcher;
pub(crate) mod proc;

use crate::sys::cgroup::SharedCgroupCache;
use config::{PsiResource, TriggerConfig};
use error::{Result, TriggerError};
use matcher::CommMatcher;
use proc::{ProcWalker, RealProcSource};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Fixed PSI time window: all thresholds are expressed as a percentage of this.
const TIME_WINDOW_MS: u64 = 1_000;

/// A process matched a trigger rule — the clean Rust-typed event used on channels.
/// Both ProcWalker and BPF ringbuffer callbacks produce this type.
pub(crate) struct ProcessMatchEvent {
    pub rule_id: u32,
    pub pid: u32,
    pub cgroup_id: u64,
    pub comm: String,
}

/// Control messages for the TriggerAgent event loop.
#[allow(dead_code)]
pub(crate) enum TriggerControl {
    /// Hot-reload with a new configuration. Nukes PSI watchers, rebuilds matcher
    /// and proc_walk from scratch.
    Reload(Arc<TriggerConfig>),
}

/// Returned by `TriggerAgent::start` to give the caller handles for lifecycle management.
pub(crate) struct TriggerAgentHandle {
    pub(crate) task_handle: tokio::task::JoinHandle<()>,
    shutdown_tx: oneshot::Sender<()>,
    #[allow(dead_code)]
    control_tx: mpsc::Sender<TriggerControl>,
}

impl TriggerAgentHandle {
    /// Signals the event loop to stop and returns the task handle for the caller to await.
    pub(crate) fn shutdown(self) -> tokio::task::JoinHandle<()> {
        let _ = self.shutdown_tx.send(());
        self.task_handle
    }
}

pub(crate) struct TriggerAgent {
    config: Arc<TriggerConfig>,
    matcher: CommMatcher,
    cache: SharedCgroupCache,
    psi_registry: HashMap<(u64, PsiResource), tokio::task::JoinHandle<()>>,
    proc_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_token: CancellationToken,
    event_tx: mpsc::Sender<ProcessMatchEvent>,
    event_rx: mpsc::Receiver<ProcessMatchEvent>,
    control_rx: mpsc::Receiver<TriggerControl>,
    shutdown_rx: oneshot::Receiver<()>,
}

impl TriggerAgent {
    /// Creates and starts the trigger agent. Returns a handle for shutdown and control.
    pub(crate) async fn start(
        config: Arc<TriggerConfig>,
        cache: SharedCgroupCache,
        event_tx: mpsc::Sender<ProcessMatchEvent>,
        event_rx: mpsc::Receiver<ProcessMatchEvent>,
    ) -> Result<TriggerAgentHandle> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (control_tx, control_rx) = mpsc::channel::<TriggerControl>(8);

        let matcher = CommMatcher::new(&config);
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
            cache,
            psi_registry: HashMap::new(),
            proc_handle: Some(proc_handle),
            cancel_token,
            event_tx,
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
            control_tx,
        })
    }

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
            Err(_) => return,
        };

        // Re-validate: confirm the comm still matches a rule in the current config.
        // Filters out stale events from a pre-reload BPF trie state.
        if self.matcher.match_comm(&event.comm) != Some(event.rule_id) {
            return;
        }

        let target = self.config.target_for_rule(event.rule_id);
        let registry_key = (cgroup_id, target.resource);

        // One PSI fd per (cgroup, resource) — first matching event wins.
        // Subsequent PIDs in the same cgroup for the same resource are silent no-ops
        // (expected: multiple PIDs with the same comm often coexist in a cgroup).
        if self.psi_registry.contains_key(&registry_key) {
            return;
        }

        let async_fd =
            match Self::build_psi_async_fd(&cgroup_path, target.resource, target.threshold) {
                Ok(fd) => fd,
                Err(e) => {
                    // Non-fatal: the cgroup may have been removed between resolution
                    // and PSI fd creation (TOCTOU race). The registry key stays
                    // absent so a future event can retry.
                    // TODO: implement structured retry logic for transient failures.
                    eprintln!(
                        "Failed to register PSI watcher for {:?}: {}",
                        cgroup_path, e
                    );
                    return;
                }
            };

        println!(
            "Registered PSI trigger for rule {} (comm: {}, resource: {:?}, threshold: {}%) on cgroup {}",
            event.rule_id,
            event.comm,
            target.resource,
            target.threshold,
            cgroup_path.display()
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
                println!(
                    "PSI threshold exceeded for rule {} on cgroup {:?}",
                    rule_id, cgroup_path
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

        // 3. Rebuild matcher with new config
        self.matcher = CommMatcher::new(&new_config);
        self.config = new_config;

        // 4. Spawn new proc_walk
        // TODO: also clear and repopulate BPF LPM trie (requires access to
        // LoadedProfilerAgent which is not yet plumbed through).
        self.cancel_token = CancellationToken::new();
        let handle = Self::spawn_proc_walk(
            &self.config,
            Arc::clone(&self.cache),
            self.event_tx.clone(),
            self.cancel_token.clone(),
        );
        self.proc_handle = Some(handle);
    }

    fn spawn_proc_walk(
        config: &Arc<TriggerConfig>,
        cache: SharedCgroupCache,
        tx: mpsc::Sender<ProcessMatchEvent>,
        cancel: CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let config = Arc::clone(config);
        tokio::task::spawn_blocking(move || {
            let walker = ProcWalker::new(&config, cache, RealProcSource);
            walker.walk(&tx, &cancel);
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
