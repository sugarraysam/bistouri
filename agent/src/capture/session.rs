use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use super::trace::StackTrace;
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
/// `traces`, and `counts[i]` records how many samples matched `traces[i]`.
pub(crate) struct CaptureSession {
    id: SessionId,
    pid: u32,
    comm: String,
    source: CaptureSource,
    kernel_meta: Arc<KernelMeta>,
    started_at: Instant,
    traces: Vec<StackTrace>,
    /// Maps trace content → index in `traces` vec. Uses pre-computed hash:
    /// `StackTrace` caches its content hash at construction, so HashMap lookups
    /// cost one `u64` hash instead of re-hashing all frames.
    dedup: HashMap<StackTrace, usize>,
    counts: Vec<u64>,
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

    pub(crate) fn source(&self) -> &CaptureSource {
        &self.source
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
        CompletedSession {
            session_id: self.id,
            source: self.source,
            pid: self.pid,
            comm: self.comm,
            kernel_meta: self.kernel_meta,
            started_at: self.started_at,
            stack_traces: self.traces,
            counts: self.counts,
            total_samples: self.total_samples,
        }
    }
}

/// Finalized capture result, ready for downstream delivery (symbolizer, storage).
///
/// Contains dictionary-encoded stack traces: `stack_traces[i]` holds the unique
/// trace, and `profile[i]` holds how many times it was sampled. Kernel frames
/// are raw IPs (symbolized via /proc/kallsyms). User frames carry per-frame
/// `(build_id, file_offset)` from `BPF_F_USER_BUILD_ID` — the symbolizer uses
/// these for cross-host correlation and symbol lookup without /proc/pid/maps.
pub(crate) struct CompletedSession {
    pub session_id: SessionId,
    pub source: CaptureSource,
    /// PID is host-local and ephemeral, but needed for local correlation.
    /// For cross-host correlation, the symbolizer groups by build_id
    /// (embedded per-frame in user stack entries).
    pub pid: u32,
    /// Stable, human-readable process identifier. Unlike PID, meaningful
    /// across hosts running the same binary.
    pub comm: String,
    /// Host kernel metadata for kernel stack symbolization.
    /// Shared across all sessions on this host (Arc = pointer bump).
    pub kernel_meta: Arc<KernelMeta>,
    #[allow(dead_code)] // consumed by symbolizer (TODO)
    pub started_at: Instant,
    // TODO: stall_total_usec delta — PSI violation severity.
    pub stack_traces: Vec<StackTrace>,
    /// Dictionary-encoded profile: `counts[i]` = sample count for `stack_traces[i]`.
    pub counts: Vec<u64>,
    pub total_samples: u64,
}

impl CompletedSession {
    pub(crate) fn into_grpc_payload(
        self,
    ) -> std::result::Result<proto::SessionPayload, bincode::Error> {
        let traces_payload = bincode::serialize(&self.stack_traces)?;
        let counts_payload = bincode::serialize(&self.counts)?;
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
            counts_payload,
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
            session.record(trace);
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
            session.record(hot_path.clone());
        }
        session.record(cold_path);

        let completed = session.finalize();

        assert_eq!(completed.total_samples, 11);
        assert_eq!(completed.stack_traces.len(), 2);
        assert_eq!(completed.counts[0], 10, "hot path count");
        assert_eq!(completed.counts[1], 1, "cold path count");
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
        assert!(completed.counts.is_empty());
    }

    #[test]
    fn session_id_is_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }
}
