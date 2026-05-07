use crate::sys::cgroup::SharedCgroupCache;
use crate::trigger::config::TriggerConfig;
use crate::trigger::matcher::CommMatcher;
use crate::trigger::ProcessMatchEvent;
use std::fs;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Walks /proc, matches process comms against configured rules, and emits events.
pub(crate) struct ProcWalker {
    matcher: CommMatcher,
    cache: SharedCgroupCache,
}

impl ProcWalker {
    pub(crate) fn new(config: &TriggerConfig, cache: SharedCgroupCache) -> Self {
        Self {
            matcher: CommMatcher::new(config),
            cache,
        }
    }

    /// Walks all processes and sends matching events. Checks cancellation between PIDs.
    pub(crate) fn walk(&self, tx: &mpsc::Sender<ProcessMatchEvent>, cancel: &CancellationToken) {
        let pids = Self::pids();
        debug!(pid_count = pids.len(), "proc_walk started");

        for pid in pids {
            if cancel.is_cancelled() {
                return;
            }

            let Some(comm) = Self::comm(pid) else {
                continue;
            };

            let rule_ids = self.matcher.match_comm(&comm);
            if rule_ids.is_empty() {
                continue;
            }

            let cgroup_id = match self.cache.write().unwrap().resolve_cgroup_by_pid(pid) {
                Ok((id, _path)) => id,
                Err(_) => {
                    // Non-fatal: process likely exited between /proc scan and
                    // cgroup resolution — skip this pid and continue the walk.
                    continue;
                }
            };

            for rule_id in &rule_ids {
                debug!(
                    pid = pid,
                    comm = %comm,
                    rule_id = rule_id,
                    cgroup_id = cgroup_id,
                    "proc_walk matched process",
                );
                let event = ProcessMatchEvent {
                    rule_id: *rule_id,
                    pid,
                    cgroup_id,
                    comm: comm.clone(),
                };
                let _ = tx.blocking_send(event);
            }
        }
        debug!("proc_walk completed");
    }

    fn pids() -> Vec<u32> {
        let Ok(entries) = fs::read_dir("/proc") else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .collect()
    }

    fn comm(pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|s| s.trim_end().to_string())
    }
}
