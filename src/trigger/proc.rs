use crate::sys::cgroup::SharedCgroupCache;
use crate::trigger::config::TriggerConfig;
use crate::trigger::matcher::CommMatcher;
use crate::trigger::ProcessMatchEvent;
use std::fs;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Abstraction over /proc for testability.
pub(crate) trait ProcSource: Send + 'static {
    fn pids(&self) -> Vec<u32>;
    fn comm(&self, pid: u32) -> Option<String>;
}

/// Reads process information from /proc.
pub(crate) struct RealProcSource;

impl ProcSource for RealProcSource {
    fn pids(&self) -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .collect()
    }

    fn comm(&self, pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim_end().to_string())
    }
}

/// Walks processes, matches comms against configured rules, and emits events.
pub(crate) struct ProcWalker<P: ProcSource> {
    matcher: CommMatcher,
    cache: SharedCgroupCache,
    proc_source: P,
}

impl<P: ProcSource> ProcWalker<P> {
    pub(crate) fn new(config: &TriggerConfig, cache: SharedCgroupCache, proc_source: P) -> Self {
        Self {
            matcher: CommMatcher::new(config),
            cache,
            proc_source,
        }
    }

    /// Walks all processes and sends matching events. Checks cancellation between PIDs.
    pub(crate) fn walk(&self, tx: &mpsc::Sender<ProcessMatchEvent>, cancel: &CancellationToken) {
        for pid in self.proc_source.pids() {
            if cancel.is_cancelled() {
                return;
            }

            let Some(comm) = self.proc_source.comm(pid) else {
                continue;
            };

            let Some(rule_id) = self.matcher.match_comm(&comm) else {
                continue;
            };

            let cgroup_id = match self.cache.write().unwrap().resolve_cgroup_by_pid(pid) {
                Ok((id, _path)) => id,
                Err(_) => {
                    // Non-fatal: process likely exited between /proc scan and
                    // cgroup resolution — skip this pid and continue the walk.
                    continue;
                }
            };

            let event = ProcessMatchEvent {
                rule_id,
                pid,
                cgroup_id,
                comm,
            };

            let _ = tx.blocking_send(event);
        }
    }
}
