use crate::capture::session::{CaptureRequest, CaptureSource};
use crate::telemetry::{METRIC_ACTIVE_PSI_WATCHERS, METRIC_CAPTURE_CHANNEL_FULL};
use crate::trigger::config::PsiResource;
use crate::trigger::error::{Result, TriggerError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{Interest, Ready};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

/// Fixed PSI time window: all thresholds are expressed as a percentage of this.
const TIME_WINDOW_MS: f64 = 1_000.0;

/// How often each PSI watcher verifies the watched PID is still alive.
///
/// When Kubernetes OOM-kills a container, the cgroup persists (k8s manages
/// it at pod level) so the PSI fd remains valid and AsyncFd::ready() never
/// errors. Without this liveness probe, dead watchers accumulate forever
/// and the gauge is permanently inflated.
const PSI_LIVENESS_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// Registry key identifying a unique PSI watcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct WatcherKey {
    pub cgroup_id: u64,
    pub resource: PsiResource,
}

/// Result of attempting to register a PSI watcher for a (cgroup, resource) pair.
pub(crate) enum PsiRegisterResult {
    /// A new PSI watcher was successfully created and spawned.
    Registered,
    /// A watcher for this (cgroup, resource) already exists — no-op.
    AlreadyExists,
    /// Failed to build the PSI file descriptor (TOCTOU race, kernel issue).
    BuildFailed,
}

/// Diagnostic metadata for a registered PSI watcher.
struct WatcherMeta {
    pid: u32,
    comm: String,
    cgroup_path: PathBuf,
}

/// Owns the set of active PSI watchers, keyed by (cgroup_id, resource).
///
/// Event-driven reaping: each watcher holds a clone of `watcher_exit_tx`
/// and sends its registry key when the AsyncFd loop exits (process died,
/// cgroup deleted). The `TriggerAgent` selects on `watcher_exit_rx` to
/// remove dead entries immediately — the gauge is always accurate.
pub(crate) struct PsiRegistry {
    watchers: HashMap<WatcherKey, (tokio::task::JoinHandle<()>, WatcherMeta)>,
    capture_tx: mpsc::Sender<CaptureRequest>,
    request_cooldown: Duration,
    /// Watcher exit notification channel — sender cloned into each watcher.
    watcher_exit_tx: mpsc::UnboundedSender<WatcherKey>,
}

impl PsiRegistry {
    pub(crate) fn new(
        capture_tx: mpsc::Sender<CaptureRequest>,
        request_cooldown: Duration,
    ) -> (Self, mpsc::UnboundedReceiver<WatcherKey>) {
        let (watcher_exit_tx, watcher_exit_rx) = mpsc::unbounded_channel();
        (
            Self {
                watchers: HashMap::new(),
                capture_tx,
                request_cooldown,
                watcher_exit_tx,
            },
            watcher_exit_rx,
        )
    }

    /// Attempts to register a PSI watcher for the given (cgroup, resource) pair.
    ///
    /// The caller pre-builds the `CaptureRequest` that should fire when the PSI
    /// threshold is exceeded. The watcher clones it on each fire — it never needs
    /// to know how to construct one.
    pub(crate) fn register(
        &mut self,
        cgroup_id: u64,
        cgroup_path: &Path,
        threshold: f64,
        request: CaptureRequest,
    ) -> PsiRegisterResult {
        let CaptureSource::Psi(resource) = request.source;

        let key = WatcherKey {
            cgroup_id,
            resource,
        };

        if self.watchers.contains_key(&key) {
            return PsiRegisterResult::AlreadyExists;
        }

        let async_fd = match Self::build_async_fd(cgroup_path, resource, threshold) {
            Ok(fd) => fd,
            Err(_) => return PsiRegisterResult::BuildFailed,
        };

        let meta = WatcherMeta {
            pid: request.pid,
            comm: request.comm.clone(),
            cgroup_path: cgroup_path.to_path_buf(),
        };

        let watcher = Self::spawn_watcher(
            async_fd,
            key,
            request,
            cgroup_path.to_path_buf(),
            self.capture_tx.clone(),
            self.request_cooldown,
            self.watcher_exit_tx.clone(),
        );
        self.watchers.insert(key, (watcher, meta));
        metrics::gauge!(METRIC_ACTIVE_PSI_WATCHERS).set(self.watchers.len() as f64);

        PsiRegisterResult::Registered
    }

    /// Aborts all active PSI watcher tasks.
    pub(crate) fn shutdown(&mut self) {
        for (handle, _) in self.watchers.drain().map(|(_, v)| v) {
            handle.abort();
        }
        metrics::gauge!(METRIC_ACTIVE_PSI_WATCHERS).set(0.0);
    }

    /// Removes a specific watcher by registry key. Called by the
    /// `TriggerAgent` when it receives a watcher exit notification.
    pub(crate) fn remove(&mut self, key: &WatcherKey) {
        if self.watchers.remove(key).is_some() {
            debug!(
                cgroup_id = key.cgroup_id,
                resource = ?key.resource,
                remaining = self.watchers.len(),
                "reaped dead PSI watcher",
            );
            metrics::gauge!(METRIC_ACTIVE_PSI_WATCHERS).set(self.watchers.len() as f64);
        }
    }

    /// Logs all active PSI watchers. Triggered by SIGUSR1 for live diagnostics.
    pub(crate) fn dump(&self) {
        info!(total = self.watchers.len(), "PSI watcher dump (SIGUSR1)",);
        for (key, (_, meta)) in &self.watchers {
            info!(
                cgroup_id = key.cgroup_id,
                resource = ?key.resource,
                pid = meta.pid,
                comm = %meta.comm,
                cgroup = %meta.cgroup_path.display(),
                "  active watcher",
            );
        }
    }

    fn build_async_fd(
        cgroup_path: &Path,
        resource: PsiResource,
        threshold: f64,
    ) -> Result<AsyncFd<presutaoru::PsiFd>> {
        let entry =
            presutaoru::PsiEntry::Cgroup(psi_resource_to_cgroup_entry(resource), cgroup_path);
        let stall_amount = Duration::from_millis((threshold / 100.0 * TIME_WINDOW_MS) as u64);

        let psi_fd = presutaoru::PsiFdBuilder::default()
            .entry(entry)
            .stall_type(presutaoru::StallType::Some)
            .time_window(Duration::from_millis(TIME_WINDOW_MS as u64))
            .stall_amount(stall_amount)
            .build()
            .map_err(|e| {
                error!(cgroup = %cgroup_path.display(), resource = ?resource, error = %e, "PSI fd build failed");
                TriggerError::PsiFdBuild {
                    path: cgroup_path.to_path_buf(),
                    source: e,
                }
            })?;

        // PSI triggers via POLLPRI, not POLLIN.
        let async_fd =
            AsyncFd::with_interest(psi_fd, Interest::PRIORITY).map_err(TriggerError::AsyncFd)?;
        Ok(async_fd)
    }

    /// Spawns an async task that polls the PSI fd and fires the pre-built
    /// `CaptureRequest` whenever the threshold is exceeded.
    fn spawn_watcher(
        async_fd: AsyncFd<presutaoru::PsiFd>,
        key: WatcherKey,
        request: CaptureRequest,
        cgroup_path: PathBuf,
        capture_tx: mpsc::Sender<CaptureRequest>,
        request_cooldown: Duration,
        exit_tx: mpsc::UnboundedSender<WatcherKey>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let pid = request.pid;
            let comm = request.comm.clone();
            let resource = key.resource;
            let mut last_sent: Option<std::time::Instant> = None;
            let mut liveness = tokio::time::interval(PSI_LIVENESS_CHECK_INTERVAL);
            liveness.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    biased;
                    result = async_fd.ready(Interest::PRIORITY) => {
                        match result {
                            Ok(mut guard) => {
                                guard.clear_ready_matching(Ready::PRIORITY);
                                if last_sent.is_some_and(|t| t.elapsed() < request_cooldown) {
                                    continue;
                                }
                                info!(
                                    pid = pid, comm = %comm, resource = ?resource,
                                    cgroup = %cgroup_path.display(),
                                    "PSI threshold exceeded, requesting capture",
                                );
                                if capture_tx.try_send(request.clone()).is_err() {
                                    error!("capture request channel full, PSI event dropped");
                                    metrics::counter!(
                                        METRIC_CAPTURE_CHANNEL_FULL,
                                        "resource" => resource.to_string(),
                                        "comm" => comm.clone(),
                                    )
                                    .increment(1);
                                } else {
                                    last_sent = Some(std::time::Instant::now());
                                }
                            }
                            Err(_) => break, // fd invalid, cgroup deleted
                        }
                    }
                    _ = liveness.tick() => {
                        if !is_pid_alive(pid, &comm) {
                            info!(
                                pid = pid, comm = %comm, resource = ?resource,
                                cgroup = %cgroup_path.display(),
                                "watched process died or was recycled, reaping PSI watcher",
                            );
                            break;
                        }
                    }
                }
            }

            // Watcher loop exited — notify registry for cleanup.
            info!(
                pid = pid,
                comm = %comm,
                resource = ?resource,
                cgroup = %cgroup_path.display(),
                "PSI watcher exiting",
            );
            let _ = exit_tx.send(key);
        })
    }
}

/// Checks if a process is still alive and matches the expected comm name.
///
/// Uses `/proc/{pid}/comm` — a procfs virtual file that returns instantly
/// (kernel-serviced, no disk I/O). Safe to call from async context without
/// `spawn_blocking`.
///
/// Returns `false` if the PID doesn't exist (process died) or if the comm
/// doesn't match (PID was recycled for a different process).
fn is_pid_alive(pid: u32, expected_comm: &str) -> bool {
    let path = format!("/proc/{pid}/comm");
    match std::fs::read_to_string(&path) {
        Ok(actual) => actual.trim() == expected_comm,
        Err(_) => false,
    }
}

fn psi_resource_to_cgroup_entry(resource: PsiResource) -> presutaoru::CgroupEntryType {
    match resource {
        PsiResource::Memory => presutaoru::CgroupEntryType::Memory,
        PsiResource::Cpu => presutaoru::CgroupEntryType::Cpu,
        PsiResource::Io => presutaoru::CgroupEntryType::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::session::CaptureRequest;
    use rstest::rstest;
    use std::path::PathBuf;
    use std::time::Duration;

    /// Creates a PsiRegistry with a dummy capture channel.
    fn make_registry() -> (PsiRegistry, mpsc::UnboundedReceiver<WatcherKey>) {
        let (capture_tx, _capture_rx) = mpsc::channel::<CaptureRequest>(8);
        PsiRegistry::new(capture_tx, Duration::from_secs(5))
    }

    /// Inserts a mock watcher entry directly into the registry's HashMap.
    /// We can't call `register()` without real cgroup PSI fds, so we
    /// bypass `build_async_fd` by inserting a no-op JoinHandle + metadata.
    fn insert_mock_watcher(
        registry: &mut PsiRegistry,
        cgroup_id: u64,
        resource: PsiResource,
        pid: u32,
        comm: &str,
        cgroup_path: &str,
    ) {
        let handle = tokio::spawn(async {}); // no-op task
        let meta = WatcherMeta {
            pid,
            comm: comm.to_string(),
            cgroup_path: PathBuf::from(cgroup_path),
        };
        let key = WatcherKey {
            cgroup_id,
            resource,
        };
        registry.watchers.insert(key, (handle, meta));
    }

    // -----------------------------------------------------------------------
    // dump — should not panic, covers empty and populated registries
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::empty(vec![], 0, "empty registry produces zero-line dump")]
    #[case::single_watcher(
        vec![(100, PsiResource::Cpu, 42, "stress", "/sys/fs/cgroup/k8s/stress")],
        1,
        "single watcher dumps one entry"
    )]
    #[case::multiple_watchers(
        vec![
            (100, PsiResource::Cpu, 42, "stress", "/sys/fs/cgroup/k8s/stress"),
            (100, PsiResource::Memory, 42, "stress", "/sys/fs/cgroup/k8s/stress"),
            (200, PsiResource::Cpu, 99, "worker", "/sys/fs/cgroup/k8s/worker"),
        ],
        3,
        "multiple watchers across cgroups and resources"
    )]
    #[tokio::test]
    async fn dump_does_not_panic(
        #[case] watchers: Vec<(u64, PsiResource, u32, &str, &str)>,
        #[case] expected_count: usize,
        #[case] description: &str,
    ) {
        let (mut registry, _exit_rx) = make_registry();
        for (cgroup_id, resource, pid, comm, cgroup_path) in &watchers {
            insert_mock_watcher(
                &mut registry,
                *cgroup_id,
                *resource,
                *pid,
                comm,
                cgroup_path,
            );
        }

        assert_eq!(
            registry.watchers.len(),
            expected_count,
            "{description}: watcher count before dump"
        );

        // Must not panic regardless of registry contents.
        registry.dump();
    }

    // -----------------------------------------------------------------------
    // remove — reaping dead watchers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn remove_existing_key_shrinks_registry() {
        let (mut registry, _exit_rx) = make_registry();
        insert_mock_watcher(
            &mut registry,
            100,
            PsiResource::Cpu,
            42,
            "stress",
            "/cgroup/a",
        );
        insert_mock_watcher(
            &mut registry,
            100,
            PsiResource::Memory,
            42,
            "stress",
            "/cgroup/a",
        );
        assert_eq!(registry.watchers.len(), 2);

        registry.remove(&WatcherKey {
            cgroup_id: 100,
            resource: PsiResource::Cpu,
        });
        assert_eq!(registry.watchers.len(), 1);

        // Dump still works after removal.
        registry.dump();
    }

    #[tokio::test]
    async fn remove_nonexistent_key_is_noop() {
        let (mut registry, _exit_rx) = make_registry();
        insert_mock_watcher(
            &mut registry,
            100,
            PsiResource::Cpu,
            42,
            "stress",
            "/cgroup/a",
        );

        registry.remove(&WatcherKey {
            cgroup_id: 999,
            resource: PsiResource::Io,
        });
        assert_eq!(registry.watchers.len(), 1);
    }

    // -----------------------------------------------------------------------
    // shutdown — drains all watchers
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn shutdown_drains_all_watchers() {
        let (mut registry, _exit_rx) = make_registry();
        insert_mock_watcher(
            &mut registry,
            100,
            PsiResource::Cpu,
            42,
            "stress",
            "/cgroup/a",
        );
        insert_mock_watcher(
            &mut registry,
            200,
            PsiResource::Memory,
            99,
            "worker",
            "/cgroup/b",
        );
        assert_eq!(registry.watchers.len(), 2);

        registry.shutdown();
        assert!(registry.watchers.is_empty());

        // Dump on empty registry after shutdown is safe.
        registry.dump();
    }

    // -----------------------------------------------------------------------
    // is_pid_alive — PID liveness + comm matching
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::current_process_is_alive(std::process::id(), "is_pid_alive", true)]
    #[case::nonexistent_pid(u32::MAX, "ghost", false)]
    fn is_pid_alive_cases(#[case] pid: u32, #[case] _description: &str, #[case] expected: bool) {
        // For the current process case, read the actual comm name.
        if pid == std::process::id() {
            let actual_comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap()
                .trim()
                .to_string();
            assert_eq!(super::is_pid_alive(pid, &actual_comm), expected);
        } else {
            assert_eq!(super::is_pid_alive(pid, "ghost"), expected);
        }
    }

    #[test]
    fn is_pid_alive_comm_mismatch_returns_false() {
        // Our own PID exists, but with a wrong comm name → should return false.
        let pid = std::process::id();
        assert!(!super::is_pid_alive(pid, "definitely_not_our_comm"));
    }
}
