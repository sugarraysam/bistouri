use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use super::trace::{SampleKind, StackTrace, UserFrame};
use crate::agent::profiler::BUILD_ID_SIZE;
use crate::sys::kernel::KernelMeta;
use crate::trigger::config::PsiResource;
use bistouri_api::v1 as proto;

/// Initial capacity for mapping (build_id dedup) collections.
/// Most processes link <10 DSOs (libc, ld-linux, app binary, a few .so's).
const INITIAL_MAPPING_CAPACITY: usize = 8;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CaptureSource {
    Psi(PsiResource),
}

/// Trigger event requesting stack capture for a single PID.
pub(crate) struct CaptureRequest {
    pub pid: u32,
    pub comm: String,
    pub source: CaptureSource,
}

/// Converts a `CaptureSource` into the proto `capture_source::Source`.
fn to_proto_source(source: &CaptureSource) -> proto::capture_source::Source {
    match source {
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
    }
}

/// Converts a user-space stack frame into its proto representation,
/// incrementally building the `Mapping` table for build_id deduplication.
fn to_proto_frame(
    frame: &UserFrame,
    mapping_index: &mut HashMap<[u8; BUILD_ID_SIZE], u32>,
    mappings: &mut Vec<proto::Mapping>,
) -> proto::UserFrame {
    match frame {
        UserFrame::Resolved {
            build_id,
            file_offset,
        } => {
            let idx = *mapping_index.entry(*build_id).or_insert_with(|| {
                let idx = mappings.len() as u32;
                mappings.push(proto::Mapping {
                    build_id: build_id.to_vec(),
                });
                idx
            });
            proto::UserFrame {
                frame: Some(proto::user_frame::Frame::Resolved(proto::ResolvedFrame {
                    mapping_index: idx,
                    file_offset: *file_offset,
                })),
            }
        }
        UserFrame::Placeholder { label, ip } => proto::UserFrame {
            frame: Some(proto::user_frame::Frame::Placeholder(
                proto::PlaceholderFrame {
                    label: label.to_string(),
                    ip: *ip,
                },
            )),
        },
    }
}

/// Active capture session: one PID, one resource, bounded duration.
///
/// Builds the `SessionPayload` incrementally during `record()`. Unique
/// traces are deduped via a `HashMap<StackTrace, usize>` → index into
/// `payload.traces`. Duplicate traces are O(1) (lookup + counter bump).
/// Build IDs are deduped into `payload.mappings` via `mapping_index`.
pub(crate) struct CaptureSession {
    id: SessionId,
    pid: u32,
    source: CaptureSource,
    started_at: Instant,
    /// Maps trace content → index in `payload.traces`.
    /// Proto types don't implement `Hash`, so we keep the Rust `StackTrace`
    /// as the lookup key and discard it at finalize time.
    dedup: HashMap<StackTrace, usize>,
    /// Maps `[u8; BUILD_ID_SIZE]` → index in `payload.mappings`.
    /// Incrementally built during `record()` so each unique build_id
    /// is stored exactly once in the wire payload.
    mapping_index: HashMap<[u8; BUILD_ID_SIZE], u32>,
    /// The proto payload being built incrementally.
    payload: proto::SessionPayload,
}

impl CaptureSession {
    pub(crate) fn new(
        pid: u32,
        comm: String,
        source: CaptureSource,
        kernel_meta: Arc<KernelMeta>,
        sample_period_nanos: u64,
        trace_capacity: usize,
    ) -> Self {
        let metadata = proto::Metadata {
            pid,
            comm,
            kernel_meta: Some(proto::KernelMeta {
                release: kernel_meta.release.clone(),
                build_id: kernel_meta.build_id.to_vec(),
                kaslr_offset: kernel_meta.kaslr_offset,
            }),
        };

        let id = SessionId::new();
        // Pre-allocate based on the computed capacity hint (freq × capture_duration).
        // Trace capacity scales with the user's sampling configuration.
        // Mapping capacity is fixed — DSO count is independent of sampling rate.
        let payload = proto::SessionPayload {
            session_id: id.to_string(),
            source: Some(proto::CaptureSource {
                source: Some(to_proto_source(&source)),
            }),
            metadata: Some(metadata),
            traces: Vec::with_capacity(trace_capacity),
            total_samples: 0,
            capture_duration: None,
            sample_period_nanos,
            mappings: Vec::with_capacity(INITIAL_MAPPING_CAPACITY),
        };

        Self {
            id,
            pid,
            source,
            started_at: Instant::now(),
            dedup: HashMap::with_capacity(trace_capacity),
            mapping_index: HashMap::with_capacity(INITIAL_MAPPING_CAPACITY),
            payload,
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

    /// Returns the process comm from the proto metadata.
    pub(crate) fn comm(&self) -> &str {
        self.payload
            .metadata
            .as_ref()
            .map(|m| m.comm.as_str())
            .unwrap_or("<unknown>")
    }

    /// Records a stack trace sample, building the proto payload incrementally.
    ///
    pub(crate) fn record(&mut self, trace: StackTrace, kind: SampleKind) {
        let idx = if let Some(&idx) = self.dedup.get(&trace) {
            idx
        } else {
            let idx = self.payload.traces.len();
            // Clone kernel_frames: must exist in both proto and dedup key.
            let kernel_frames = trace.kernel_frames.clone();
            let user_frames: Vec<proto::UserFrame> = trace
                .user_frames
                .iter()
                .map(|f| to_proto_frame(f, &mut self.mapping_index, &mut self.payload.mappings))
                .collect();

            self.payload.traces.push(proto::CountedTrace {
                trace: Some(proto::StackTrace {
                    kernel_frames,
                    user_frames,
                }),
                on_cpu_count: 0,
                off_cpu_count: 0,
            });

            self.dedup.insert(trace, idx);
            idx
        };

        match kind {
            SampleKind::OnCpu => self.payload.traces[idx].on_cpu_count += 1,
            SampleKind::OffCpu => self.payload.traces[idx].off_cpu_count += 1,
        }
        self.payload.total_samples += 1;
    }

    /// Consumes the session, stamps capture duration, returns ready payload.
    pub(crate) fn finalize(mut self) -> FinalizedSession {
        let elapsed = self.started_at.elapsed();
        self.payload.capture_duration = Some(prost_types::Duration {
            seconds: elapsed.as_secs() as i64,
            nanos: elapsed.subsec_nanos() as i32,
        });

        FinalizedSession {
            session_id: self.id,
            pid: self.pid,
            source: self.source,
            payload: self.payload,
        }
    }
}

/// Finalized capture result, ready for downstream delivery.
/// Session metadata fields (`session_id`, `pid`, `source`) are kept
/// alongside for orchestrator logging and metric labels.
pub(crate) struct FinalizedSession {
    pub session_id: SessionId,
    pub pid: u32,
    pub source: CaptureSource,
    pub payload: proto::SessionPayload,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::profiler::BUILD_ID_SIZE;
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

    fn make_session() -> CaptureSession {
        CaptureSession::new(
            42,
            "test".into(),
            CaptureSource::Psi(PsiResource::Memory),
            mock_kernel_meta(),
            TEST_SAMPLE_PERIOD_NANOS,
            16, // matches compute_trace_capacity(19, 3)
        )
    }

    /// Default sample period for tests (19 Hz).
    const TEST_SAMPLE_PERIOD_NANOS: u64 = 1_000_000_000 / 19;

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
        let mut session = make_session();
        for trace in traces {
            session.record(trace, SampleKind::OnCpu);
        }
        assert_eq!(
            session.payload.traces.len(),
            expected_unique,
            "{description}: unique trace count"
        );
        assert_eq!(
            session.payload.total_samples, expected_total,
            "{description}: total sample count"
        );
    }

    // -----------------------------------------------------------------------
    // Finalize lifecycle — rstest table
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::with_samples(
        vec![
            (make_trace(&[0xA], &[frame(0x01, 0xB)]), SampleKind::OnCpu, 10),
            (make_trace(&[0xC], &[frame(0x02, 0xD)]), SampleKind::OffCpu, 1),
        ],
        11,  // total_samples
        2,   // unique traces
        "mixed on-cpu and off-cpu samples"
    )]
    #[case::empty_session(
        vec![],
        0,   // total_samples
        0,   // unique traces
        "empty session finalizes cleanly"
    )]
    #[case::single_hot_path(
        vec![
            (make_trace(&[0xA], &[frame(0x01, 0xB)]), SampleKind::OnCpu, 100),
        ],
        100,  // total_samples
        1,    // unique traces
        "single hot path with many samples"
    )]
    fn finalize_lifecycle(
        #[case] samples: Vec<(StackTrace, SampleKind, usize)>,
        #[case] expected_total: u64,
        #[case] expected_unique: usize,
        #[case] description: &str,
    ) {
        let mut session = make_session();
        for (trace, kind, count) in samples {
            for _ in 0..count {
                session.record(trace.clone(), kind);
            }
        }

        let finalized = session.finalize();

        assert_eq!(
            finalized.payload.total_samples, expected_total,
            "{description}: total_samples"
        );
        assert_eq!(
            finalized.payload.traces.len(),
            expected_unique,
            "{description}: unique traces"
        );
        assert!(
            finalized.payload.capture_duration.is_some(),
            "{description}: capture_duration must be set"
        );
        assert_eq!(finalized.pid, 42, "{description}: pid preserved");
    }

    #[test]
    fn finalize_preserves_count_split() {
        let mut session = make_session();
        let path = make_trace(&[0xA], &[frame(0x01, 0xB)]);

        for _ in 0..10 {
            session.record(path.clone(), SampleKind::OnCpu);
        }
        for _ in 0..3 {
            session.record(path.clone(), SampleKind::OffCpu);
        }

        let finalized = session.finalize();
        assert_eq!(finalized.payload.traces.len(), 1);
        assert_eq!(finalized.payload.traces[0].on_cpu_count, 10);
        assert_eq!(finalized.payload.traces[0].off_cpu_count, 3);
        assert_eq!(finalized.payload.total_samples, 13);
    }

    #[test]
    fn session_id_is_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Mapping table — build_id deduplication (rstest table)
    // -----------------------------------------------------------------------

    #[rstest]
    #[case::single_dso(
        vec![
            make_trace(&[0x1000], &[frame(0xAA, 0x100), frame(0xAA, 0x200)]),
        ],
        1,  // expected unique mappings
        "all frames from one DSO → one mapping entry"
    )]
    #[case::two_dsos(
        vec![
            make_trace(&[0x1000], &[frame(0xAA, 0x100), frame(0xBB, 0x200)]),
        ],
        2,  // expected unique mappings
        "two distinct build_ids → two mapping entries"
    )]
    #[case::cross_trace_dedup(
        vec![
            make_trace(&[0x1000], &[frame(0xAA, 0x100)]),
            make_trace(&[0x2000], &[frame(0xAA, 0x200), frame(0xBB, 0x300)]),
        ],
        2,  // expected unique mappings
        "same build_id across traces → deduplicated"
    )]
    #[case::no_resolved_frames(
        vec![
            make_trace(&[0x1000], &[UserFrame::Placeholder { label: "[vdso]", ip: 0x7000 }]),
        ],
        0,  // expected unique mappings
        "placeholder-only trace → no mappings"
    )]
    fn mapping_table_dedup(
        #[case] traces: Vec<StackTrace>,
        #[case] expected_mappings: usize,
        #[case] description: &str,
    ) {
        let mut session = make_session();
        for trace in traces {
            session.record(trace, SampleKind::OnCpu);
        }

        let finalized = session.finalize();
        assert_eq!(
            finalized.payload.mappings.len(),
            expected_mappings,
            "{description}"
        );
    }

    #[test]
    fn mapping_index_references_are_consistent() {
        let mut session = make_session();
        session.record(
            make_trace(&[0x1000], &[frame(0xAA, 0x100), frame(0xBB, 0x200)]),
            SampleKind::OnCpu,
        );

        let finalized = session.finalize();
        let trace = finalized.payload.traces[0].trace.as_ref().unwrap();

        // Each resolved frame's mapping_index must point to a valid mapping
        // with the correct build_id.
        for uf in &trace.user_frames {
            if let Some(proto::user_frame::Frame::Resolved(ref resolved)) = uf.frame {
                let mapping = &finalized.payload.mappings[resolved.mapping_index as usize];
                assert_eq!(mapping.build_id.len(), BUILD_ID_SIZE);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Payload metadata
    // -----------------------------------------------------------------------

    #[test]
    fn payload_includes_capture_metadata() {
        let session = CaptureSession::new(
            99,
            "meta-test".into(),
            CaptureSource::Psi(PsiResource::Io),
            mock_kernel_meta(),
            TEST_SAMPLE_PERIOD_NANOS,
            16,
        );

        let finalized = session.finalize();
        let payload = &finalized.payload;

        assert_eq!(payload.sample_period_nanos, TEST_SAMPLE_PERIOD_NANOS);
        assert!(payload.capture_duration.is_some());

        let meta = payload.metadata.as_ref().unwrap();
        assert_eq!(meta.pid, 99);
        assert_eq!(meta.comm, "meta-test");

        let kernel = meta.kernel_meta.as_ref().unwrap();
        assert_eq!(kernel.release, "6.8.0-test");
        assert_eq!(kernel.build_id, vec![0xAA; 20]);
        assert_eq!(kernel.kaslr_offset, 0xffffffff81000000);
    }
}
