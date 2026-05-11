use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use super::trace::{SampleKind, StackTrace};
use crate::sys::kernel::KernelMeta;
use crate::trigger::config::PsiResource;
use bistouri_api::v1 as proto;

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum CaptureSource {
    Psi(PsiResource),
}

/// Trigger event requesting stack capture for a single PID.
///
/// Intentionally trigger-agnostic: today these come from PSI watchers,
/// but the interface supports future sources (CLI, UI, API).
pub(crate) struct CaptureRequest {
    pub pid: u32,
    pub comm: String,
    pub source: CaptureSource,
    // TODO: stall_total_usec — read from <cgroup>/resource.pressure at trigger
    //       time to quantify PSI violation severity.
}

/// Active capture session: one PID, one resource, bounded duration.
///
/// Per-session dictionary encoding: unique `StackTrace`s are stored once in
/// `traces`. Each trace has two independent sample counters:
///   - `on_cpu_counts[i]`  — fired by the `perf_event` program (process on CPU)
///   - `off_cpu_counts[i]` — fired by `sched_switch` (process entering D state)
///
/// Keeping separate counters instead of a parallel `kind` vec avoids
/// dictionary-encoding a 2-value flag. The symbolizer uses the counts
/// directly: sum both for a combined flamegraph, use each independently
/// for on-CPU vs off-CPU split views.
pub(crate) struct CaptureSession {
    id: SessionId,
    pid: u32,
    comm: String,
    source: CaptureSource,
    kernel_meta: Arc<KernelMeta>,
    started_at: Instant,
    traces: Vec<StackTrace>,
    /// Maps trace content → index in `traces` vec.
    dedup: HashMap<StackTrace, usize>,
    /// On-CPU sample count per unique trace (perf_event, process running).
    on_cpu_counts: Vec<u64>,
    /// Off-CPU sample count per unique trace (sched_switch, process in D state).
    off_cpu_counts: Vec<u64>,
    total_samples: u64,
}

impl CaptureSession {
    pub(crate) fn new(
        pid: u32,
        comm: String,
        source: CaptureSource,
        kernel_meta: Arc<KernelMeta>,
    ) -> Self {
        Self {
            id: SessionId::new(),
            pid,
            comm,
            source,
            kernel_meta,
            started_at: Instant::now(),
            traces: Vec::new(),
            dedup: HashMap::new(),
            on_cpu_counts: Vec::new(),
            off_cpu_counts: Vec::new(),
            total_samples: 0,
        }
    }

    pub(crate) fn id(&self) -> SessionId {
        self.id
    }

    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn source(&self) -> &CaptureSource {
        &self.source
    }

    /// Records a stack trace sample into the appropriate count bucket.
    /// Deduplicates by trace content: the same call path from on-CPU and
    /// off-CPU both map to the same trace entry, keeping separate counters.
    pub(crate) fn record(&mut self, trace: StackTrace, kind: SampleKind) {
        let idx = if let Some(&idx) = self.dedup.get(&trace) {
            idx
        } else {
            let idx = self.traces.len();
            self.dedup.insert(trace.clone(), idx);
            self.traces.push(trace);
            self.on_cpu_counts.push(0);
            self.off_cpu_counts.push(0);
            idx
        };
        match kind {
            SampleKind::OnCpu => self.on_cpu_counts[idx] += 1,
            SampleKind::OffCpu => self.off_cpu_counts[idx] += 1,
        }
        self.total_samples += 1;
    }

    /// Consumes the session and produces a `CompletedSession` ready for
    /// downstream delivery.
    pub(crate) fn finalize(self) -> CompletedSession {
        CompletedSession {
            session_id: self.id,
            source: self.source,
            pid: self.pid,
            comm: self.comm,
            kernel_meta: self.kernel_meta,
            started_at: self.started_at,
            stack_traces: self.traces,
            on_cpu_counts: self.on_cpu_counts,
            off_cpu_counts: self.off_cpu_counts,
            total_samples: self.total_samples,
        }
    }
}

/// Finalized capture result, ready for downstream delivery (symbolizer, storage).
///
/// `stack_traces[i]` holds the unique trace. Two parallel count vecs give
/// separate on-CPU and off-CPU sample weights per trace — the symbolizer
/// sums them for a combined flamegraph, or uses each independently.
pub(crate) struct CompletedSession {
    pub session_id: SessionId,
    pub source: CaptureSource,
    pub pid: u32,
    pub comm: String,
    pub kernel_meta: Arc<KernelMeta>,
    #[allow(dead_code)] // consumed by symbolizer (TODO)
    pub started_at: Instant,
    // TODO: stall_total_usec delta — PSI violation severity.
    pub stack_traces: Vec<StackTrace>,
    /// On-CPU sample count per trace (`perf_event`, process was running).
    pub on_cpu_counts: Vec<u64>,
    /// Off-CPU sample count per trace (`sched_switch` D-state, process blocked).
    pub off_cpu_counts: Vec<u64>,
    pub total_samples: u64,
}

impl CompletedSession {
    pub(crate) fn into_grpc_payload(
        self,
    ) -> std::result::Result<proto::SessionPayload, bincode::Error> {
        let traces_payload = bincode::serialize(&self.stack_traces)?;
        let on_cpu_counts_payload = bincode::serialize(&self.on_cpu_counts)?;
        let off_cpu_counts_payload = bincode::serialize(&self.off_cpu_counts)?;
        let total_samples = self.total_samples;

        let source = match self.source {
            CaptureSource::Psi(res) => {
                let resource_type = match res {
                    PsiResource::Memory => proto::PsiResourceType::Memory,
                    PsiResource::Cpu => proto::PsiResourceType::Cpu,
                    PsiResource::Io => proto::PsiResourceType::Io,
                };
                proto::capture_source::Source::Psi(proto::PsiTrigger {
                    resource: resource_type as i32,
                })
            }
        };

        let metadata = proto::Metadata {
            pid: self.pid,
            comm: self.comm,
            kernel_meta: Some(proto::KernelMeta {
                release: self.kernel_meta.release.clone(),
                build_id: self.kernel_meta.build_id.to_vec(),
                kaslr_offset: self.kernel_meta.kaslr_offset,
            }),
        };

        Ok(proto::SessionPayload {
            session_id: self.session_id.to_string(),
            source: Some(proto::CaptureSource {
                source: Some(source),
            }),
            metadata: Some(metadata),
            traces_payload,
            on_cpu_counts_payload,
            off_cpu_counts_payload,
            total_samples,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::profiler::BUILD_ID_SIZE;
    use crate::capture::trace::UserFrame;
    use rstest::rstest;

    fn mock_kernel_meta() -> Arc<KernelMeta> {
        Arc::new(KernelMeta {
            build_id: [0xAA; 20],
            kaslr_offset: 0xffffffff81000000,
            release: "6.8.0-test".into(),
        })
    }

    /// Convenience: build_id filled with a single repeated byte.
    fn bid(byte: u8) -> [u8; BUILD_ID_SIZE] {
        [byte; BUILD_ID_SIZE]
    }

    fn make_trace(kernel: &[u64], user: &[UserFrame]) -> StackTrace {
        StackTrace::new(kernel.to_vec(), user.to_vec())
    }

    /// Shorthand for a resolved user frame.
    fn frame(bid_byte: u8, offset: u64) -> UserFrame {
        UserFrame::Resolved {
            build_id: bid(bid_byte),
            file_offset: offset,
        }
    }

    // -----------------------------------------------------------------------
    // Deduplication — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::all_identical(
        vec![
            make_trace(&[0x1000, 0x2000], &[frame(0xAA, 0x3000)]),
            make_trace(&[0x1000, 0x2000], &[frame(0xAA, 0x3000)]),
            make_trace(&[0x1000, 0x2000], &[frame(0xAA, 0x3000)]),
        ],
        1,  // unique traces
        3,  // total samples
        "three identical traces dedup to one entry"
    )]
    #[case::all_distinct(
        vec![
            make_trace(&[0x1000], &[frame(0xAA, 0x2000)]),
            make_trace(&[0x1000], &[frame(0xBB, 0x3000)]),
            make_trace(&[0x4000], &[frame(0xAA, 0x2000)]),
        ],
        3,  // unique traces
        3,  // total samples
        "three distinct traces stored separately"
    )]
    #[case::mixed(
        vec![
            make_trace(&[0xA], &[frame(0x01, 0xB)]),
            make_trace(&[0xC], &[frame(0x02, 0xD)]),
            make_trace(&[0xA], &[frame(0x01, 0xB)]),
        ],
        2,  // unique traces
        3,  // total samples
        "mixed unique and duplicate traces"
    )]
    fn deduplication(
        #[case] traces: Vec<StackTrace>,
        #[case] expected_unique: usize,
        #[case] expected_total: u64,
        #[case] description: &str,
    ) {
        let mut session = CaptureSession::new(
            42,
            "test".into(),
            CaptureSource::Psi(PsiResource::Memory),
            mock_kernel_meta(),
        );
        for trace in traces {
            session.record(trace, SampleKind::OnCpu);
        }
        assert_eq!(
            session.traces.len(),
            expected_unique,
            "{description}: unique trace count"
        );
        assert_eq!(
            session.total_samples, expected_total,
            "{description}: total sample count"
        );
    }

    // -----------------------------------------------------------------------
    // Finalize lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn finalize_produces_correct_profile() {
        let mut session = CaptureSession::new(
            42,
            "myapp".into(),
            CaptureSource::Psi(PsiResource::Io),
            mock_kernel_meta(),
        );
        let hot_path = make_trace(&[0xA], &[frame(0x01, 0xB)]);
        let cold_path = make_trace(&[0xC], &[frame(0x02, 0xD)]);

        for _ in 0..10 {
            session.record(hot_path.clone(), SampleKind::OnCpu);
        }
        session.record(cold_path, SampleKind::OffCpu);

        let completed = session.finalize();

        assert_eq!(completed.total_samples, 11);
        assert_eq!(completed.stack_traces.len(), 2);
        // hot path: 10 on-CPU samples, 0 off-CPU
        assert_eq!(completed.on_cpu_counts[0], 10, "hot path on-cpu count");
        assert_eq!(completed.off_cpu_counts[0], 0, "hot path off-cpu count");
        // cold path: 0 on-CPU, 1 off-CPU
        assert_eq!(completed.on_cpu_counts[1], 0, "cold path on-cpu count");
        assert_eq!(completed.off_cpu_counts[1], 1, "cold path off-cpu count");
        assert_eq!(completed.pid, 42);
        assert_eq!(completed.comm, "myapp");
        assert_eq!(completed.source, CaptureSource::Psi(PsiResource::Io));
    }

    #[test]
    fn empty_session_finalizes_cleanly() {
        let session = CaptureSession::new(
            1,
            "idle".into(),
            CaptureSource::Psi(PsiResource::Memory),
            mock_kernel_meta(),
        );
        let completed = session.finalize();

        assert_eq!(completed.total_samples, 0);
        assert!(completed.stack_traces.is_empty());
        assert!(completed.on_cpu_counts.is_empty());
        assert!(completed.off_cpu_counts.is_empty());
    }

    #[test]
    fn session_id_is_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }
}
