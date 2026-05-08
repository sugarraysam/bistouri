use std::collections::{HashMap, HashSet};
use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::mpsc;
use tokio_util::time::DelayQueue;
use tracing::{debug, info, warn};

use super::error::Result;
use super::session::{CaptureRequest, CaptureSession, CompletedSession, SessionId};
use super::trace::StackSample;
use crate::trigger::config::PsiResource;

const METRIC_SESSIONS_STARTED: &str = "bistouri_capture_sessions_started";
const METRIC_SESSIONS_COMPLETED: &str = "bistouri_capture_sessions_completed";
const METRIC_SESSIONS_REJECTED_DUPLICATE: &str = "bistouri_capture_sessions_rejected_duplicate";
const METRIC_SAMPLES_INGESTED: &str = "bistouri_capture_samples_ingested";
const METRIC_SAMPLES_UNMATCHED: &str = "bistouri_capture_samples_unmatched";
const METRIC_SINK_FAILURES: &str = "bistouri_capture_sink_failures";

fn describe_metrics() {
    metrics::describe_counter!(
        METRIC_SESSIONS_STARTED,
        "Capture sessions started after PSI trigger"
    );
    metrics::describe_counter!(
        METRIC_SESSIONS_COMPLETED,
        "Capture sessions finalized and sent downstream"
    );
    metrics::describe_counter!(
        METRIC_SESSIONS_REJECTED_DUPLICATE,
        "Capture requests rejected due to duplicate (pid, resource) inflight"
    );
    metrics::describe_counter!(
        METRIC_SAMPLES_INGESTED,
        "Stack samples ingested into active sessions"
    );
    metrics::describe_counter!(
        METRIC_SAMPLES_UNMATCHED,
        "Stack samples received for PIDs with no active session"
    );
    metrics::describe_counter!(
        METRIC_SINK_FAILURES,
        "Failures sending completed sessions downstream"
    );
}

/// Abstracts BPF `pid_filter_map` operations for testability.
///
/// Production implementation wraps a `MapHandle` to the BPF hash map.
/// Test implementation records operations for assertion.
pub(crate) trait PidFilter: Send {
    fn add_pid(&mut self, pid: u32) -> Result<()>;
    fn remove_pid(&mut self, pid: u32) -> Result<()>;
}

/// Orchestrates the lifecycle of `CaptureSession`s.
///
/// Receives `CaptureRequest`s from PSI watchers (via `request_rx`), starts
/// per-PID capture sessions, ingests `StackSample`s from the BPF ring buffer
/// (via `stack_rx`), and emits `CompletedSession`s downstream (via `session_tx`).
///
/// ## Event Loop Priority (biased select)
///
/// 1. **Timers** — finalize expired sessions first. Frees memory and removes
///    PIDs from the BPF filter map, reducing sample volume. Must run before
///    ingesting more samples to bound memory growth.
/// 2. **Samples** — high-volume path (~19Hz × monitored PIDs). Processed
///    before new requests so existing sessions are fed promptly. Each
///    `ingest_sample` is O(1) per session (HashMap lookup + increment).
/// 3. **Requests** — rare events (PSI fires are infrequent). Starting new
///    sessions last avoids delaying the high-throughput sample path.
///
/// In practice, the biased ordering only matters when multiple branches are
/// simultaneously ready. Timer expiry events are rare (~1 per session per 3s),
/// so samples are processed with minimal contention.
pub(crate) struct CaptureOrchestrator<F: PidFilter> {
    request_rx: mpsc::Receiver<CaptureRequest>,
    stack_rx: mpsc::Receiver<StackSample>,
    session_tx: mpsc::Sender<CompletedSession>,

    pid_filter: F,
    capture_duration: Duration,

    sessions: HashMap<SessionId, CaptureSession>,
    /// Reverse index: pid → active session IDs monitoring that pid.
    /// Enables O(1) fan-out when a StackSample arrives.
    pid_sessions: HashMap<u32, Vec<SessionId>>,
    /// Dedup guard: at most one inflight session per (pid, resource).
    /// Max 3 entries per pid (one per PsiResource variant).
    inflight_guard: HashSet<(u32, PsiResource)>,
    /// Ref-counted PID presence in BPF `pid_filter_map`.
    /// Incremented when a session starts, decremented when it finalizes.
    /// PID is removed from BPF map only when refcount reaches zero.
    pid_refcount: HashMap<u32, usize>,
    timers: DelayQueue<SessionId>,
}

impl<F: PidFilter> CaptureOrchestrator<F> {
    pub(crate) fn new(
        request_rx: mpsc::Receiver<CaptureRequest>,
        stack_rx: mpsc::Receiver<StackSample>,
        session_tx: mpsc::Sender<CompletedSession>,
        pid_filter: F,
        capture_duration: Duration,
    ) -> Self {
        describe_metrics();
        Self {
            request_rx,
            stack_rx,
            session_tx,
            pid_filter,
            capture_duration,
            sessions: HashMap::new(),
            pid_sessions: HashMap::new(),
            inflight_guard: HashSet::new(),
            pid_refcount: HashMap::new(),
            timers: DelayQueue::new(),
        }
    }

    /// Main event loop — runs until all input channels close.
    /// See struct-level docs for priority ordering rationale.
    pub(crate) async fn run(&mut self) {
        loop {
            tokio::select! {
                biased;
                // 1. Finalize expired sessions — frees resources before accumulating more.
                Some(expired) = self.timers.next() => {
                    let session_id = expired.into_inner();
                    self.finalize_session(session_id).await;
                },
                // 2. Ingest stack samples — high-volume, O(1) per session.
                sample = self.stack_rx.recv() => match sample {
                    Some(s) => self.ingest_sample(s),
                    None => break,
                },
                // 3. Start new capture sessions — rare, PSI-triggered.
                req = self.request_rx.recv() => match req {
                    Some(request) => self.start_session(request),
                    None => break,
                },
            }
        }
        // Inflight sessions are incomplete — drop them silently.
        // Partial captures are not useful to the symbolizer.
    }

    /// Creates a `CaptureSession` for the requested PID, unless a session
    /// with the same (pid, resource) is already inflight.
    fn start_session(&mut self, request: CaptureRequest) {
        let guard_key = (request.pid, request.resource);

        if self.inflight_guard.contains(&guard_key) {
            debug!(
                pid = request.pid,
                resource = ?request.resource,
                "rejected duplicate capture session",
            );
            metrics::counter!(METRIC_SESSIONS_REJECTED_DUPLICATE).increment(1);
            return;
        }

        // Register in BPF pid_filter_map (ref-counted)
        let refcount = self.pid_refcount.entry(request.pid).or_insert(0);
        if *refcount == 0 {
            if let Err(e) = self.pid_filter.add_pid(request.pid) {
                warn!(pid = request.pid, error = %e, "failed to add pid to BPF filter, skipping");
                return;
            }
        }
        *refcount += 1;

        let session = CaptureSession::new(request.pid, request.comm, request.resource);
        let session_id = session.id();

        self.inflight_guard.insert(guard_key);
        self.pid_sessions
            .entry(request.pid)
            .or_default()
            .push(session_id);
        self.timers.insert(session_id, self.capture_duration);

        info!(
            session_id = %session_id,
            pid = session.pid(),
            resource = ?request.resource,
            duration_secs = self.capture_duration.as_secs(),
            "capture session started",
        );
        metrics::counter!(METRIC_SESSIONS_STARTED).increment(1);

        self.sessions.insert(session_id, session);
    }

    /// Routes a stack sample to all active sessions monitoring that PID.
    ///
    /// Fan-out optimization: moves the trace into the last session (zero-copy),
    /// clones only for preceding sessions. Common case (1 session per PID):
    /// zero clones.
    fn ingest_sample(&mut self, sample: StackSample) {
        let Some(session_ids) = self.pid_sessions.get(&sample.pid) else {
            // Expected during a small race window after session expiry:
            // a few trailing samples may arrive before the PID is removed
            // from the BPF filter map. Not an error.
            debug!(
                pid = sample.pid,
                "stack sample for pid with no active session"
            );
            metrics::counter!(METRIC_SAMPLES_UNMATCHED).increment(1);
            return;
        };

        let ids = session_ids.clone();
        let trace = sample.trace;

        match ids.len() {
            0 => unreachable!("pid_sessions entry is never empty"),
            1 => {
                // Common case: single session per PID. Zero clones.
                if let Some(session) = self.sessions.get_mut(&ids[0]) {
                    session.record(trace);
                    metrics::counter!(METRIC_SAMPLES_INGESTED).increment(1);
                }
            }
            _ => {
                // Multiple sessions (e.g. mem + cpu): clone for all but last.
                for session_id in &ids[..ids.len() - 1] {
                    if let Some(session) = self.sessions.get_mut(session_id) {
                        session.record(trace.clone());
                        metrics::counter!(METRIC_SAMPLES_INGESTED).increment(1);
                    }
                }
                if let Some(session) = self.sessions.get_mut(ids.last().unwrap()) {
                    session.record(trace);
                    metrics::counter!(METRIC_SAMPLES_INGESTED).increment(1);
                }
            }
        }
    }

    /// Finalizes a session: removes from all indices, decrements PID refcount,
    /// and sends the `CompletedSession` downstream.
    async fn finalize_session(&mut self, session_id: SessionId) {
        let Some(session) = self.sessions.remove(&session_id) else {
            return;
        };

        let pid = session.pid();
        let resource = session.resource();

        // Clean up indices
        self.inflight_guard.remove(&(pid, resource));
        if let Some(ids) = self.pid_sessions.get_mut(&pid) {
            ids.retain(|id| *id != session_id);
            if ids.is_empty() {
                self.pid_sessions.remove(&pid);
            }
        }

        // Decrement PID refcount; remove from BPF map when zero
        if let Some(refcount) = self.pid_refcount.get_mut(&pid) {
            *refcount -= 1;
            if *refcount == 0 {
                self.pid_refcount.remove(&pid);
                if let Err(e) = self.pid_filter.remove_pid(pid) {
                    warn!(pid = pid, error = %e, "failed to remove pid from BPF filter");
                }
            }
        }

        let completed = session.finalize();

        info!(
            session_id = %completed.session_id,
            pid = completed.pid,
            comm = %completed.comm,
            resource = ?completed.resource,
            total_samples = completed.total_samples,
            unique_traces = completed.stack_traces.len(),
            "capture session completed",
        );
        metrics::counter!(METRIC_SESSIONS_COMPLETED).increment(1);

        if self.session_tx.send(completed).await.is_err() {
            warn!("downstream receiver dropped, completed session lost");
            metrics::counter!(METRIC_SINK_FAILURES).increment(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::trace::StackTrace;
    use super::*;
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
            trace: StackTrace {
                kernel_frames: vec![trace_id],
                user_frames: vec![trace_id + 1],
            },
        }
    }

    fn make_request(pid: u32, resource: PsiResource) -> CaptureRequest {
        CaptureRequest {
            pid,
            comm: format!("test-{}", pid),
            resource,
        }
    }

    fn setup(
        capture_duration: Duration,
    ) -> (
        CaptureOrchestrator<MockPidFilter>,
        mpsc::Sender<CaptureRequest>,
        mpsc::Sender<StackSample>,
        mpsc::Receiver<CompletedSession>,
    ) {
        let (req_tx, req_rx) = mpsc::channel(16);
        let (stack_tx, stack_rx) = mpsc::channel(256);
        let (session_tx, session_rx) = mpsc::channel(16);

        let orch = CaptureOrchestrator::new(
            req_rx,
            stack_rx,
            session_tx,
            MockPidFilter::new(),
            capture_duration,
        );

        (orch, req_tx, stack_tx, session_rx)
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

        let completed = session_rx
            .recv()
            .await
            .expect("should receive completed session");
        assert_eq!(completed.pid, 42);
        assert_eq!(completed.comm, "test-42");
        assert_eq!(completed.resource, PsiResource::Memory);
        assert_eq!(completed.total_samples, 10);
        assert_eq!(completed.stack_traces.len(), 3);

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

        let resources: HashSet<PsiResource> = [s1.resource, s2.resource].into_iter().collect();
        assert!(resources.contains(&PsiResource::Memory));
        assert!(resources.contains(&PsiResource::Cpu));

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

        let completed = session_rx.recv().await.unwrap();
        assert_eq!(completed.pid, 42);
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

        let completed = session_rx.recv().await.unwrap();
        assert_eq!(completed.total_samples, 0);
        assert!(completed.stack_traces.is_empty());

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
