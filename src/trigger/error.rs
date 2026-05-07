use crate::sys::cgroup::error::CgroupError;
use std::path::PathBuf;
use thiserror::Error;
use tracing::warn;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub(crate) enum TriggerError {
    #[error("Failed to resolve cgroup for pid {pid}: {source}")]
    CgroupResolve {
        pid: u32,
        #[source]
        source: CgroupError,
    },

    #[error("Failed to build PSI file descriptor for cgroup {path:?}: {source}")]
    PsiFdBuild {
        path: PathBuf,
        #[source]
        source: presutaoru::PsiFdBuilderError,
    },

    #[error("Failed to register PSI fd with async reactor: {0}")]
    AsyncFd(#[source] std::io::Error),

    #[error("Proc walk task panicked: {0}")]
    ProcWalk(String),

    #[error("At least one target rule is required")]
    EmptyTargets,

    #[error("Comm string '{comm}' exceeds 15 characters kernel limit")]
    CommTooLong { comm: String },

    #[error("Threshold {threshold} for comm '{comm}' must be in the range (0, 100) exclusive")]
    InvalidThreshold { threshold: f64, comm: String },

    #[error("Failed to parse config: {0}")]
    ConfigParse(#[source] serde_yml::Error),

    #[error("Failed to read config file: {0}")]
    ConfigIo(#[source] std::io::Error),

    #[error("BPF comm_lpm_trie update failed: {0}")]
    BpfTrieUpdate(#[source] libbpf_rs::Error),

    #[error("Config watcher setup failed: {0}")]
    ConfigWatcher(#[source] std::io::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TriggerError>;

/// Aggregates non-fatal operational event counts for periodic summary logging.
/// Prevents per-occurrence log spam while surfacing sustained failure patterns.
pub(super) struct ErrorCounters {
    pub(super) cgroup_resolve_failures: u64,
    pub(super) psi_fd_build_failures: u64,
    pub(super) stale_events: u64,
    pub(super) duplicate_psi_skips: u64,
}

impl ErrorCounters {
    pub(super) fn new() -> Self {
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
    pub(super) fn report_and_reset(&mut self) {
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
