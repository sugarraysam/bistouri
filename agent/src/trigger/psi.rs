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
use tracing::{error, info};

/// Fixed PSI time window: all thresholds are expressed as a percentage of this.
const TIME_WINDOW_MS: f64 = 1_000.0;

/// Result of attempting to register a PSI watcher for a (cgroup, resource) pair.
pub(crate) enum PsiRegisterResult {
    /// A new PSI watcher was successfully created and spawned.
    Registered,
    /// A watcher for this (cgroup, resource) already exists — no-op.
    AlreadyExists,
    /// Failed to build the PSI file descriptor (TOCTOU race, kernel issue).
    BuildFailed,
}

/// Owns the set of active PSI watchers, keyed by (cgroup_id, resource).
/// Encapsulates the full PSI lifecycle: fd creation, async watcher spawning,
/// registry tracking, and shutdown.
pub(crate) struct PsiRegistry {
    watchers: HashMap<(u64, PsiResource), tokio::task::JoinHandle<()>>,
    capture_tx: mpsc::Sender<CaptureRequest>,
    /// Minimum interval between successive capture requests from a single
    /// watcher. Initialized from the capture duration so that a watcher
    /// cannot emit more than one request per profiling window. Each watcher
    /// enforces this locally — no shared state required.
    request_cooldown: Duration,
}

impl PsiRegistry {
    pub(crate) fn new(
        capture_tx: mpsc::Sender<CaptureRequest>,
        request_cooldown: Duration,
    ) -> Self {
        Self {
            watchers: HashMap::new(),
            capture_tx,
            request_cooldown,
        }
    }

    /// Attempts to register a PSI watcher for the given (cgroup, resource) pair.
    /// Returns the outcome so the caller can update counters accordingly.
    ///
    /// When the PSI threshold is exceeded, the watcher sends a `CaptureRequest`
    /// for the given `pid` and `comm` to the `CaptureOrchestrator`.
    pub(crate) fn register(
        &mut self,
        cgroup_id: u64,
        cgroup_path: &Path,
        resource: PsiResource,
        threshold: f64,
        pid: u32,
        comm: String,
    ) -> PsiRegisterResult {
        let registry_key = (cgroup_id, resource);

        // One PSI fd per (cgroup, resource) — first matching event wins.
        // Subsequent PIDs in the same cgroup for the same resource are no-ops
        // (expected: multiple PIDs with the same comm often coexist in a cgroup).
        if self.watchers.contains_key(&registry_key) {
            return PsiRegisterResult::AlreadyExists;
        }

        let async_fd = match Self::build_async_fd(cgroup_path, resource, threshold) {
            Ok(fd) => fd,
            Err(_) => return PsiRegisterResult::BuildFailed,
        };

        let watcher = Self::spawn_watcher(
            async_fd,
            pid,
            comm,
            resource,
            cgroup_path.to_path_buf(),
            self.capture_tx.clone(),
            self.request_cooldown,
        );
        self.watchers.insert(registry_key, watcher);
        metrics::gauge!(METRIC_ACTIVE_PSI_WATCHERS).set(self.watchers.len() as f64);

        PsiRegisterResult::Registered
    }

    /// Aborts all active PSI watcher tasks and clears the registry.
    pub(crate) fn shutdown(&mut self) {
        for handle in self.watchers.drain().map(|(_, h)| h) {
            handle.abort();
        }
        metrics::gauge!(METRIC_ACTIVE_PSI_WATCHERS).set(0.0);
    }

    fn build_async_fd(
        cgroup_path: &Path,
        resource: PsiResource,
        threshold: f64,
    ) -> Result<AsyncFd<presutaoru::PsiFd>> {
        let entry = presutaoru::PsiEntry::Cgroup(resource.into(), cgroup_path);
        let stall_amount = Duration::from_millis((threshold / 100.0 * TIME_WINDOW_MS) as u64);

        let psi_fd = presutaoru::PsiFdBuilder::default()
            .entry(entry)
            .stall_type(presutaoru::StallType::Some)
            .time_window(Duration::from_millis(TIME_WINDOW_MS as u64))
            .stall_amount(stall_amount)
            .build()
            .map_err(|e| {
                error!(
                    cgroup = %cgroup_path.display(),
                    resource = ?resource,
                    error = %e,
                    "PSI fd build failed — if this persists for all cgroups, \
                     verify CONFIG_PSI=y in your kernel config \
                     (grep CONFIG_PSI /boot/config-$(uname -r))",
                );
                TriggerError::PsiFdBuild {
                    path: cgroup_path.to_path_buf(),
                    source: e,
                }
            })?;

        // PSI triggers signal threshold crossings via POLLPRI, not POLLIN.
        // Using AsyncFd::new() (READABLE) would return immediately every time
        // because PSI fds are always POLLIN-ready as readable stat files.
        let async_fd =
            AsyncFd::with_interest(psi_fd, Interest::PRIORITY).map_err(TriggerError::AsyncFd)?;
        Ok(async_fd)
    }

    fn spawn_watcher(
        async_fd: AsyncFd<presutaoru::PsiFd>,
        pid: u32,
        comm: String,
        resource: PsiResource,
        cgroup_path: PathBuf,
        capture_tx: mpsc::Sender<CaptureRequest>,
        request_cooldown: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // PSI triggers fire via POLLPRI, not POLLIN. We must use
            // .ready(Interest::PRIORITY) — .readable() waits for POLLIN
            // which is always set on PSI fds (they are stat-like files).
            //
            // Cooldown: after sending a capture request, suppress further sends
            // for `request_cooldown`. This reduces noise from repeated PSI fires
            // during an active capture window. The orchestrator's inflight_guard
            // remains the authoritative correctness backstop; the cooldown is a
            // best-effort rate limiter that lives entirely within this task.
            let mut last_sent: Option<std::time::Instant> = None;
            while let Ok(mut guard) = async_fd.ready(Interest::PRIORITY).await {
                guard.clear_ready_matching(Ready::PRIORITY);
                if last_sent.is_some_and(|t| t.elapsed() < request_cooldown) {
                    continue;
                }
                info!(
                    pid = pid,
                    comm = %comm,
                    resource = ?resource,
                    cgroup = %cgroup_path.display(),
                    "PSI threshold exceeded, requesting capture",
                );
                let req = CaptureRequest {
                    pid,
                    comm: comm.clone(),
                    source: CaptureSource::Psi(resource),
                };
                // Best-effort: if the capture channel is full, the orchestrator's
                // dedup guard will reject a repeat when the next PSI fires.
                if capture_tx.try_send(req).is_err() {
                    error!(
                        "capture request channel full, PSI event dropped — \
                         consider doubling CAPTURE_REQUEST_CHANNEL_SIZE",
                    );
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
        })
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
