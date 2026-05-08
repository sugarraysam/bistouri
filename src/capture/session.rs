use std::collections::HashMap;
use std::time::Instant;

use uuid::Uuid;

use super::trace::StackTrace;
use crate::trigger::config::PsiResource;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SessionId(Uuid);

impl SessionId {
    pub(crate) fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Trigger event requesting stack capture for a single PID.
///
/// Intentionally trigger-agnostic: today these come from PSI watchers,
/// but the interface supports future sources (CLI, UI, API).
pub(crate) struct CaptureRequest {
    pub pid: u32,
    pub comm: String,
    pub resource: PsiResource,
    // TODO: stall_total_usec — read from <cgroup>/resource.pressure at trigger
    //       time to quantify PSI violation severity.
}

/// Active capture session: one PID, one resource, bounded duration.
///
/// Per-session dictionary encoding: unique `StackTrace`s are stored once in
/// `traces`, and `counts[i]` records how many samples matched `traces[i]`.
pub(crate) struct CaptureSession {
    id: SessionId,
    pid: u32,
    comm: String,
    resource: PsiResource,
    started_at: Instant,
    traces: Vec<StackTrace>,
    /// Maps trace content → index in `traces` vec. Uses derived `Hash`+`Eq`
    /// on `StackTrace` — Rust's HashMap handles hashing internally (SipHash).
    dedup: HashMap<StackTrace, usize>,
    counts: Vec<u64>,
    total_samples: u64,
}

impl CaptureSession {
    pub(crate) fn new(pid: u32, comm: String, resource: PsiResource) -> Self {
        Self {
            id: SessionId::new(),
            pid,
            comm,
            resource,
            started_at: Instant::now(),
            traces: Vec::new(),
            dedup: HashMap::new(),
            counts: Vec::new(),
            total_samples: 0,
        }
    }

    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn resource(&self) -> PsiResource {
        self.resource
    }

    /// Records a stack trace sample. Deduplicates: if the same trace was
    /// already seen, increments its count. Otherwise stores a new entry.
    /// Clone cost: one `StackTrace` clone per unique trace (first occurrence only).
    pub(crate) fn record(&mut self, trace: StackTrace) {
        if let Some(&idx) = self.dedup.get(&trace) {
            self.counts[idx] += 1;
        } else {
            let idx = self.traces.len();
            self.dedup.insert(trace.clone(), idx);
            self.traces.push(trace);
            self.counts.push(1);
        }
        self.total_samples += 1;
    }

    /// Consumes the session and produces a `CompletedSession` ready for
    /// downstream delivery.
    pub(crate) fn finalize(self) -> CompletedSession {
        let profile: HashMap<usize, u64> = self
            .counts
            .into_iter()
            .enumerate()
            .filter(|(_, count)| *count > 0)
            .collect();

        CompletedSession {
            session_id: self.id,
            resource: self.resource,
            pid: self.pid,
            comm: self.comm,
            started_at: self.started_at,
            stack_traces: self.traces,
            profile,
            total_samples: self.total_samples,
        }
    }
}

/// Finalized capture result, ready for downstream delivery (symbolizer, storage).
///
/// Contains dictionary-encoded stack traces: `stack_traces[i]` holds the unique
/// trace, and `profile[i]` holds how many times it was sampled. Kernel and user
/// frames are stored separately within each `StackTrace` (different symbol
/// sources: kallsyms for kernel, ELF for user).
pub(crate) struct CompletedSession {
    pub session_id: SessionId,
    pub resource: PsiResource,
    /// PID is host-local and ephemeral, but needed for local correlation
    /// (/proc/<pid>/exe, /proc/<pid>/maps). For cross-host correlation,
    /// use `build_id` (TODO) and `comm`.
    pub pid: u32,
    /// Stable, human-readable process identifier. Unlike PID, meaningful
    /// across hosts running the same binary.
    pub comm: String,
    pub started_at: Instant,
    // TODO: build_id (ELF .note.gnu.build-id) — needed by symbolizer for
    //       cross-host correlation. Requires ELF parser crate. Separate follow-up.
    // TODO: stall_total_usec delta — PSI violation severity.
    pub stack_traces: Vec<StackTrace>,
    /// Dictionary-encoded profile: stack_traces index → sample count.
    pub profile: HashMap<usize, u64>,
    pub total_samples: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace(kernel: &[u64], user: &[u64]) -> StackTrace {
        StackTrace {
            kernel_frames: kernel.to_vec(),
            user_frames: user.to_vec(),
        }
    }

    #[test]
    fn record_deduplicates_identical_traces() {
        let mut session = CaptureSession::new(42, "test".into(), PsiResource::Memory);
        let trace = make_trace(&[0x1000, 0x2000], &[0x3000]);

        session.record(trace.clone());
        session.record(trace.clone());
        session.record(trace);

        assert_eq!(session.traces.len(), 1, "only one unique trace stored");
        assert_eq!(session.counts[0], 3, "count reflects all samples");
        assert_eq!(session.total_samples, 3);
    }

    #[test]
    fn record_distinguishes_different_traces() {
        let mut session = CaptureSession::new(42, "test".into(), PsiResource::Cpu);
        let trace_a = make_trace(&[0x1000], &[0x2000]);
        let trace_b = make_trace(&[0x1000], &[0x3000]);

        session.record(trace_a);
        session.record(trace_b);

        assert_eq!(session.traces.len(), 2);
        assert_eq!(session.counts[0], 1);
        assert_eq!(session.counts[1], 1);
        assert_eq!(session.total_samples, 2);
    }

    #[test]
    fn finalize_produces_correct_profile() {
        let mut session = CaptureSession::new(42, "myapp".into(), PsiResource::Io);
        let hot_path = make_trace(&[0xA], &[0xB]);
        let cold_path = make_trace(&[0xC], &[0xD]);

        for _ in 0..10 {
            session.record(hot_path.clone());
        }
        session.record(cold_path);

        let completed = session.finalize();

        assert_eq!(completed.total_samples, 11);
        assert_eq!(completed.stack_traces.len(), 2);
        assert_eq!(completed.profile[&0], 10, "hot path count");
        assert_eq!(completed.profile[&1], 1, "cold path count");
        assert_eq!(completed.pid, 42);
        assert_eq!(completed.comm, "myapp");
        assert_eq!(completed.resource, PsiResource::Io);
    }

    #[test]
    fn empty_session_finalizes_cleanly() {
        let session = CaptureSession::new(1, "idle".into(), PsiResource::Memory);
        let completed = session.finalize();

        assert_eq!(completed.total_samples, 0);
        assert!(completed.stack_traces.is_empty());
        assert!(completed.profile.is_empty());
    }

    #[test]
    fn session_id_is_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }
}
