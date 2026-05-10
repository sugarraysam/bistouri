use crate::sys::cgroup::resolve_cgroup_path;
use crate::telemetry::{METRIC_PROC_WALK_DURATION, METRIC_PROC_WALK_MATCHES};
use crate::trigger::config::TriggerConfig;
use crate::trigger::matcher::CommMatcher;
use crate::trigger::ProcessMatchEvent;
use std::fs;
use std::path::Path;
use std::time::Instant;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

/// Walks /proc, matches process comms against configured rules, and emits events.
pub(crate) struct ProcWalker {
    matcher: CommMatcher,
    cgroup2_mount: Box<Path>,
    proc_path: Box<Path>,
}

impl ProcWalker {
    pub(crate) fn new(config: &TriggerConfig, cgroup2_mount: &Path, proc_path: &Path) -> Self {
        Self {
            matcher: CommMatcher::new(config),
            cgroup2_mount: cgroup2_mount.into(),
            proc_path: proc_path.into(),
        }
    }

    /// Walks all processes and sends matching events. Checks cancellation between PIDs.
    pub(crate) fn walk(&self, tx: &mpsc::Sender<ProcessMatchEvent>, cancel: &CancellationToken) {
        let start = Instant::now();
        let pids = self.pids();
        debug!(pid_count = pids.len(), "proc_walk started");
        let mut match_count: u64 = 0;

        for pid in pids {
            if cancel.is_cancelled() {
                return;
            }

            let Some(comm) = self.comm(pid) else {
                continue;
            };

            let rule_ids = self.matcher.match_comm(&comm);
            if rule_ids.is_empty() {
                continue;
            }

            let cgroup_path = match resolve_cgroup_path(&self.cgroup2_mount, &self.proc_path, pid) {
                Ok(path) => path,
                Err(e) => {
                    // Non-fatal: process likely exited between /proc scan and
                    // cgroup resolution — skip this pid and continue the walk.
                    debug!(
                        pid = pid,
                        error = %e,
                        "proc_walk: cgroup resolution failed, skipping pid",
                    );
                    continue;
                }
            };

            for rule_id in &rule_ids {
                debug!(
                    pid = pid,
                    comm = %comm,
                    rule_id = rule_id,
                    cgroup = %cgroup_path.display(),
                    "proc_walk matched process",
                );
                match_count += 1;
                let event = ProcessMatchEvent {
                    rule_id: *rule_id,
                    pid,
                    cgroup_path: Some(cgroup_path.clone()),
                    comm: comm.clone(),
                };
                let _ = tx.blocking_send(event);
            }
        }

        let elapsed = start.elapsed();
        metrics::histogram!(METRIC_PROC_WALK_DURATION).record(elapsed.as_secs_f64());
        metrics::counter!(METRIC_PROC_WALK_MATCHES).increment(match_count);
        debug!(
            duration_ms = elapsed.as_millis(),
            matches = match_count,
            "proc_walk completed"
        );
    }

    fn pids(&self) -> Vec<u32> {
        let Ok(entries) = fs::read_dir(&self.proc_path) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_string_lossy().parse::<u32>().ok())
            .collect()
    }

    fn comm(&self, pid: u32) -> Option<String> {
        fs::read_to_string(self.proc_path.join(format!("{}/comm", pid)))
            .ok()
            .map(|s| s.trim_end().to_string())
    }
}
