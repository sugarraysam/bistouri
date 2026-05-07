use crate::trigger::config::PsiResource;
use crate::trigger::error::{Result, TriggerError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{unix::AsyncFd, Interest};
use tracing::info;

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
}

impl PsiRegistry {
    pub(crate) fn new() -> Self {
        Self {
            watchers: HashMap::new(),
        }
    }

    /// Attempts to register a PSI watcher for the given (cgroup, resource) pair.
    /// Returns the outcome so the caller can update counters accordingly.
    pub(crate) fn register(
        &mut self,
        cgroup_id: u64,
        cgroup_path: &Path,
        resource: PsiResource,
        threshold: f64,
        rule_id: u32,
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

        let watcher = Self::spawn_watcher(async_fd, rule_id, cgroup_path.to_path_buf());
        self.watchers.insert(registry_key, watcher);

        PsiRegisterResult::Registered
    }

    /// Aborts all active PSI watcher tasks and clears the registry.
    pub(crate) fn shutdown(&mut self) {
        for (_, handle) in self.watchers.drain() {
            handle.abort();
        }
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
            .map_err(|e| TriggerError::PsiFdBuild {
                path: cgroup_path.to_path_buf(),
                source: e,
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
