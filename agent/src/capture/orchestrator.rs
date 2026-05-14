use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio_util::time::DelayQueue;
use tracing::{debug, info, warn};

use super::error::Result;
use super::pid_filter::BpfPidFilter;
use super::session::{CaptureRequest, CaptureSession, CaptureSource, SessionId};
use super::trace::StackSample;
use crate::sys::kernel::KernelMeta;
use crate::telemetry::{
    METRIC_ACTIVE_SESSIONS, METRIC_SAMPLES_INGESTED, METRIC_SAMPLES_UNMATCHED,
    METRIC_SESSIONS_COMPLETED, METRIC_SESSIONS_EMPTY, METRIC_SESSIONS_REJECTED_DUPLICATE,
    METRIC_SESSIONS_STARTED, METRIC_SESSION_SAMPLES, METRIC_SINK_FAILURES,
};
use crate::trigger::config::PsiResource;
use bistouri_api::v1 as proto;

/// Returns a static resource label for metric tags. Zero allocation.
fn source_label(source: &CaptureSource) -> &'static str {
    match source {
        CaptureSource::Psi(PsiResource::Memory) => "memory",
        CaptureSource::Psi(PsiResource::Cpu) => "cpu",
        CaptureSource::Psi(PsiResource::Io) => "io",
    }
}

/// Abstracts BPF `pid_filter_map` operations for testability.
pub(crate) trait PidFilter: Send {
    fn add_pid(&mut self, pid: u32) -> Result<()>;
    fn remove_pid(&mut self, pid: u32) -> Result<()>;
}

/// Session-independent orchestrator configuration.
pub(crate) struct OrchestratorConfig {
    pub capture_duration: Duration,
    pub sample_period_nanos: u64,
    pub kernel_meta: Arc<KernelMeta>,
    /// Pre-allocation hint for per-session trace/dedup collections.
    pub trace_capacity: usize,
}

const MIN_TRACE_CAPACITY: usize = 16;
const MAX_TRACE_CAPACITY: usize = 256;

/// Power-of-two capacity hint: `(freq × duration) / 4`, clamped to [16, 256].
fn compute_trace_capacity(freq: u64, capture_duration_secs: u64) -> usize {
    let raw = (freq * capture_duration_secs / 4) as usize;
    raw.clamp(MIN_TRACE_CAPACITY, MAX_TRACE_CAPACITY)
        .next_power_of_two()
}

/// Orchestrates `CaptureSession` lifecycles.
///
/// Biased select priority: timers → samples → requests.
/// Timers first to bound memory; samples next (high-volume); requests last (rare).
pub(crate) struct CaptureOrchestrator<F: PidFilter> {
    request_rx: mpsc::Receiver<CaptureRequest>,
    stack_rx: mpsc::Receiver<StackSample>,
    session_tx: mpsc::Sender<proto::SessionPayload>,
    pid_filter: F,
    config: OrchestratorConfig,
    cancel: CancellationToken,
    sessions: HashMap<SessionId, CaptureSession>,
    /// pid → active session IDs (O(1) fan-out for StackSamples).
    pid_sessions: HashMap<u32, Vec<SessionId>>,
    /// At most one inflight session per (pid, resource).
    inflight_guard: HashSet<(u32, CaptureSource)>,
    /// Ref-counted PID presence in BPF filter map.
    pid_refcount: HashMap<u32, usize>,
    timers: DelayQueue<SessionId>,
}

impl<F: PidFilter> CaptureOrchestrator<F> {
    pub(crate) fn new(
        request_rx: mpsc::Receiver<CaptureRequest>,
        stack_rx: mpsc::Receiver<StackSample>,
        session_tx: mpsc::Sender<proto::SessionPayload>,
        pid_filter: F,
        config: OrchestratorConfig,
        cancel: CancellationToken,
    ) -> Self {
        Self {
            request_rx,
            stack_rx,
            session_tx,
            pid_filter,
            config,
            cancel,
            sessions: HashMap::new(),
            pid_sessions: HashMap::new(),
            inflight_guard: HashSet::new(),
            pid_refcount: HashMap::new(),
            timers: DelayQueue::new(),
        }
    }

    pub(crate) async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                _ = self.cancel.cancelled() => break,
                Some(expired) = self.timers.next() => {
                    self.finalize_session(expired.into_inner()).await;
                },
                sample = self.stack_rx.recv() => match sample {
                    Some(s) => self.ingest_sample(s),
                    None => break,
                },
                req = self.request_rx.recv() => match req {
                    Some(request) => self.start_session(request),
                    None => break,
                },
            }
        }
    }

    fn start_session(&mut self, request: CaptureRequest) {
        let guard_key = (request.pid, request.source);

        if self.inflight_guard.contains(&guard_key) {
            debug!(pid = request.pid, source = ?request.source, "rejected duplicate capture session");
            metrics::counter!(METRIC_SESSIONS_REJECTED_DUPLICATE).increment(1);
            return;
        }

        let refcount = self.pid_refcount.entry(request.pid).or_insert(0);
        if *refcount == 0 {
            if let Err(e) = self.pid_filter.add_pid(request.pid) {
                warn!(pid = request.pid, error = %e, "failed to add pid to BPF filter");
                return;
            }
        }
        *refcount += 1;

        let resource_label = source_label(&request.source);
        let session = CaptureSession::new(
            request.pid,
            request.comm,
            request.source,
            self.config.kernel_meta.clone(),
            self.config.sample_period_nanos,
            self.config.trace_capacity,
            request.tenant_id,
            request.service_id,
            request.labels,
        );
        let session_id = session.id();

        self.inflight_guard.insert(guard_key);
        self.pid_sessions
            .entry(session.pid())
            .or_default()
            .push(session_id);
        self.timers.insert(session_id, self.config.capture_duration);

        info!(
            session_id = %session_id,
            pid = session.pid(),
            comm = session.comm(),
            duration_secs = self.config.capture_duration.as_secs(),
            "capture session started",
        );
        metrics::counter!(
            METRIC_SESSIONS_STARTED,
            "resource" => resource_label,
            "comm" => session.comm().to_owned(),
        )
        .increment(1);

        self.sessions.insert(session_id, session);
        metrics::gauge!(METRIC_ACTIVE_SESSIONS).set(self.sessions.len() as f64);
    }

    /// Routes a sample to all sessions for that PID.
    /// Common case (1 session): zero clones.
    fn ingest_sample(&mut self, sample: StackSample) {
        let Some(session_ids) = self.pid_sessions.get(&sample.pid) else {
            metrics::counter!(METRIC_SAMPLES_UNMATCHED).increment(1);
            return;
        };

        let kind = sample.kind;
        let trace = sample.trace;

        // Clone for all-but-last, move into last.
        let (last, rest) = session_ids.split_last().unwrap();
        for sid in rest {
            if let Some(session) = self.sessions.get_mut(sid) {
                metrics::counter!(METRIC_SAMPLES_INGESTED, "resource" => source_label(session.source())).increment(1);
                session.record(trace.clone(), kind);
            }
        }
        if let Some(session) = self.sessions.get_mut(last) {
            metrics::counter!(METRIC_SAMPLES_INGESTED, "resource" => source_label(session.source())).increment(1);
            session.record(trace, kind);
        }
    }

    async fn finalize_session(&mut self, session_id: SessionId) {
        let Some(session) = self.sessions.remove(&session_id) else {
            return;
        };

        let pid = session.pid();
        let source = *session.source();

        self.inflight_guard.remove(&(pid, source));
        if let Some(ids) = self.pid_sessions.get_mut(&pid) {
            ids.retain(|id| *id != session_id);
            if ids.is_empty() {
                self.pid_sessions.remove(&pid);
            }
        }

        if let Some(refcount) = self.pid_refcount.get_mut(&pid) {
            *refcount -= 1;
            if *refcount == 0 {
                self.pid_refcount.remove(&pid);
                if let Err(e) = self.pid_filter.remove_pid(pid) {
                    warn!(pid = pid, error = %e, "failed to remove pid from BPF filter");
                }
            }
        }

        let finalized = session.finalize();
        let total_samples = finalized.payload.total_samples;
        let unique_traces = finalized.payload.traces.len();
        let comm = finalized
            .payload
            .metadata
            .as_ref()
            .and_then(|m| m.labels.get("comm"))
            .map(|s| s.as_str())
            .unwrap_or("<unknown>");
        let resource_label = source_label(&finalized.source);

        info!(
            session_id = %finalized.session_id,
            pid = finalized.pid,
            comm = %comm,
            resource = resource_label,
            total_samples,
            unique_traces,
            "capture session completed",
        );

        metrics::counter!(
            METRIC_SESSIONS_COMPLETED,
            "resource" => resource_label,
            "comm" => comm.to_owned(),
        )
        .increment(1);
        metrics::histogram!(METRIC_SESSION_SAMPLES).record(total_samples as f64);
        if total_samples == 0 {
            metrics::counter!(
                METRIC_SESSIONS_EMPTY,
                "resource" => resource_label,
                "comm" => comm.to_owned(),
            )
            .increment(1);
        }
        metrics::gauge!(METRIC_ACTIVE_SESSIONS).set(self.sessions.len() as f64);

        if self.session_tx.send(finalized.payload).await.is_err() {
            warn!("downstream receiver dropped, completed session lost");
            metrics::counter!(METRIC_SINK_FAILURES).increment(1);
        }
    }
}

/// Channel buffer for PSI → CaptureOrchestrator capture requests.
/// PSI fires are rare; 128 absorbs any burst.
const CAPTURE_REQUEST_CHANNEL_SIZE: usize = 128;

/// Stack sample channel shared with daemon (created externally due to build order).
pub(crate) const STACK_SAMPLE_CHANNEL_SIZE: usize = 4096;

const SESSION_PAYLOAD_CHANNEL_SIZE: usize = 64;

/// Returned by `CaptureOrchestrator::start()`.
pub(crate) struct CaptureOrchestratorHandle {
    pub(crate) task_handle: tokio::task::JoinHandle<()>,
    pub(crate) capture_tx: mpsc::Sender<CaptureRequest>,
    pub(crate) payload_rx: mpsc::Receiver<proto::SessionPayload>,
}

impl CaptureOrchestrator<BpfPidFilter> {
    /// Production entry point: creates channels, spawns the event loop.
    pub(crate) fn start(
        pid_filter_handle: libbpf_rs::MapHandle,
        capture_duration_secs: u64,
        freq: u64,
        stack_rx: mpsc::Receiver<StackSample>,
        cancel: CancellationToken,
        kernel_meta: Arc<KernelMeta>,
    ) -> CaptureOrchestratorHandle {
        let pid_filter = BpfPidFilter::new(pid_filter_handle);
        let config = OrchestratorConfig {
            capture_duration: Duration::from_secs(capture_duration_secs),
            sample_period_nanos: 1_000_000_000 / freq,
            kernel_meta,
            trace_capacity: compute_trace_capacity(freq, capture_duration_secs),
        };

        let (capture_tx, request_rx) = mpsc::channel(CAPTURE_REQUEST_CHANNEL_SIZE);
        let (session_tx, payload_rx) = mpsc::channel(SESSION_PAYLOAD_CHANNEL_SIZE);

        let mut orch = Self::new(request_rx, stack_rx, session_tx, pid_filter, config, cancel);
        let task_handle = tokio::spawn(async move { orch.run().await });

        CaptureOrchestratorHandle {
            task_handle,
            capture_tx,
            payload_rx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::trace::{SampleKind, StackTrace, UserFrame};
    use super::*;
    use crate::agent::profiler::BUILD_ID_SIZE;
    use crate::trigger::config::PsiResource;
    use tokio::time;

    /// Mock PID filter that records add/remove operations for assertion.
    struct MockPidFilter {
        added: Vec<u32>,
        removed: Vec<u32>,
    }

    impl MockPidFilter {
        fn new() -> Self {
            Self {
                added: Vec::new(),
                removed: Vec::new(),
            }
        }
    }

    impl PidFilter for MockPidFilter {
        fn add_pid(&mut self, pid: u32) -> Result<()> {
            self.added.push(pid);
            Ok(())
        }

        fn remove_pid(&mut self, pid: u32) -> Result<()> {
            self.removed.push(pid);
            Ok(())
        }
    }

    fn make_sample(pid: u32, trace_id: u64) -> StackSample {
        StackSample {
            pid,
            kind: SampleKind::OnCpu,
            trace: StackTrace::new(
                vec![trace_id],
                vec![UserFrame::Resolved {
                    build_id: [trace_id as u8; BUILD_ID_SIZE],
                    file_offset: trace_id + 1,
                }],
            ),
        }
    }

    fn make_request(pid: u32, resource: PsiResource) -> CaptureRequest {
        CaptureRequest {
            pid,
            comm: format!("test-{}", pid),
            source: CaptureSource::Psi(resource),
            tenant_id: "test-tenant".into(),
            service_id: "test-service".into(),
            labels: HashMap::new(),
        }
    }

    fn mock_kernel_meta() -> Arc<KernelMeta> {
        Arc::new(KernelMeta {
            build_id: [0xAA; 20],
            text_addr: 0xffffffff81000000,
            release: "6.8.0-test".into(),
        })
    }

    fn mock_config(capture_duration: Duration) -> OrchestratorConfig {
        OrchestratorConfig {
            capture_duration,
            sample_period_nanos: 1_000_000_000 / 19,
            kernel_meta: mock_kernel_meta(),
            trace_capacity: compute_trace_capacity(19, capture_duration.as_secs()),
        }
    }

    fn setup(
        capture_duration: Duration,
    ) -> (
        CaptureOrchestrator<MockPidFilter>,
        mpsc::Sender<CaptureRequest>,
        mpsc::Sender<StackSample>,
        mpsc::Receiver<proto::SessionPayload>,
    ) {
        let (req_tx, req_rx) = mpsc::channel(16);
        let (stack_tx, stack_rx) = mpsc::channel(256);
        let (session_tx, session_rx) = mpsc::channel(16);

        let orch = CaptureOrchestrator::new(
            req_rx,
            stack_rx,
            session_tx,
            MockPidFilter::new(),
            mock_config(capture_duration),
            CancellationToken::new(),
        );

        (orch, req_tx, stack_tx, session_rx)
    }

    /// Helper: extract comm from a SessionPayload's metadata labels.
    fn payload_comm(p: &proto::SessionPayload) -> &str {
        p.metadata
            .as_ref()
            .and_then(|m| m.labels.get("comm"))
            .map(|s| s.as_str())
            .unwrap_or("")
    }

    #[tokio::test(start_paused = true)]
    async fn single_session_lifecycle() {
        let (mut orch, req_tx, stack_tx, mut session_rx) = setup(Duration::from_secs(3));
        let handle = tokio::spawn(async move { orch.run().await });

        req_tx
            .send(make_request(42, PsiResource::Memory))
            .await
            .unwrap();
        tokio::task::yield_now().await;

        for i in 0..10 {
            stack_tx.send(make_sample(42, i % 3)).await.unwrap();
        }

        time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;

        let payload = session_rx
            .recv()
            .await
            .expect("should receive session payload");
        assert_eq!(payload.metadata.as_ref().unwrap().pid, 42);
        assert_eq!(payload_comm(&payload), "test-42");
        assert_eq!(payload.total_samples, 10);
        assert_eq!(payload.traces.len(), 3);

        drop(req_tx);
        drop(stack_tx);
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn multi_session_same_pid_different_resource() {
        let (mut orch, req_tx, stack_tx, mut session_rx) = setup(Duration::from_secs(3));
        let handle = tokio::spawn(async move { orch.run().await });

        req_tx
            .send(make_request(42, PsiResource::Memory))
            .await
            .unwrap();
        req_tx
            .send(make_request(42, PsiResource::Cpu))
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // One sample fans out to both sessions
        stack_tx.send(make_sample(42, 0xA)).await.unwrap();

        time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;

        let s1 = session_rx.recv().await.unwrap();
        let s2 = session_rx.recv().await.unwrap();
        assert_eq!(s1.total_samples, 1);
        assert_eq!(s2.total_samples, 1);

        drop(req_tx);
        drop(stack_tx);
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_pid_resource_rejected() {
        let (mut orch, req_tx, stack_tx, mut session_rx) = setup(Duration::from_secs(3));
        let handle = tokio::spawn(async move { orch.run().await });

        req_tx
            .send(make_request(42, PsiResource::Cpu))
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // Second CPU request for same PID — rejected
        req_tx
            .send(make_request(42, PsiResource::Cpu))
            .await
            .unwrap();
        tokio::task::yield_now().await;

        time::advance(Duration::from_secs(4)).await;
        tokio::task::yield_now().await;

        let payload = session_rx.recv().await.unwrap();
        assert_eq!(payload.metadata.as_ref().unwrap().pid, 42);
        assert!(session_rx.try_recv().is_err(), "no second session");

        drop(req_tx);
        drop(stack_tx);
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn pid_refcount_manages_bpf_map() {
        let (mut orch, _req_tx, _stack_tx, mut session_rx) = setup(Duration::from_secs(3));

        orch.start_session(make_request(42, PsiResource::Memory));
        orch.start_session(make_request(42, PsiResource::Cpu));

        // PID added to BPF map only once
        assert_eq!(orch.pid_filter.added.len(), 1);
        assert_eq!(orch.pid_refcount[&42], 2);

        // Finalize first session — PID stays (refcount = 1)
        let first_id = *orch.sessions.keys().next().unwrap();
        orch.finalize_session(first_id).await;
        assert!(orch.pid_filter.removed.is_empty());
        assert_eq!(orch.pid_refcount[&42], 1);

        // Finalize second session — PID removed (refcount = 0)
        let second_id = *orch.sessions.keys().next().unwrap();
        orch.finalize_session(second_id).await;
        assert_eq!(orch.pid_filter.removed, vec![42]);
        assert!(!orch.pid_refcount.contains_key(&42));

        let _ = session_rx.recv().await;
        let _ = session_rx.recv().await;
    }

    #[tokio::test(start_paused = true)]
    async fn unmatched_samples_counted_not_crashed() {
        let (mut orch, req_tx, stack_tx, _session_rx) = setup(Duration::from_secs(3));
        let handle = tokio::spawn(async move { orch.run().await });

        stack_tx.send(make_sample(999, 0x1)).await.unwrap();
        tokio::task::yield_now().await;

        drop(req_tx);
        drop(stack_tx);
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn empty_session_finalizes_cleanly() {
        let (mut orch, req_tx, stack_tx, mut session_rx) = setup(Duration::from_secs(1));
        let handle = tokio::spawn(async move { orch.run().await });

        req_tx.send(make_request(7, PsiResource::Io)).await.unwrap();

        time::advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;

        let payload = session_rx.recv().await.unwrap();
        assert_eq!(payload.total_samples, 0);
        assert!(payload.traces.is_empty());

        drop(req_tx);
        drop(stack_tx);
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn max_three_sessions_per_pid() {
        let (mut orch, _req_tx, _stack_tx, _session_rx) = setup(Duration::from_secs(3));

        orch.start_session(make_request(42, PsiResource::Memory));
        orch.start_session(make_request(42, PsiResource::Cpu));
        orch.start_session(make_request(42, PsiResource::Io));
        assert_eq!(orch.sessions.len(), 3);

        // Fourth attempt — rejected (all 3 resource slots filled)
        orch.start_session(make_request(42, PsiResource::Memory));
        assert_eq!(orch.sessions.len(), 3, "no fourth session created");
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_drops_inflight_sessions() {
        let (mut orch, req_tx, stack_tx, mut session_rx) = setup(Duration::from_secs(60));

        req_tx
            .send(make_request(42, PsiResource::Memory))
            .await
            .unwrap();
        tokio::task::yield_now().await;

        // Drop senders → channels close → run() exits
        drop(req_tx);
        drop(stack_tx);

        let handle = tokio::spawn(async move { orch.run().await });
        let _ = handle.await;

        // No completed session — inflight sessions are dropped, not finalized
        assert!(
            session_rx.try_recv().is_err(),
            "incomplete sessions should be dropped"
        );
    }
}
