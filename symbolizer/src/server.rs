//! gRPC service implementation for `CaptureService::ReportSession`.
//!
//! Fire-and-forget model: the handler accepts the payload, enqueues it
//! for background processing, and returns immediately. The agent does
//! not wait for DWARF resolution or downstream storage.
//!
//! ```text
//! Agent ──→ report_session() ──→ mpsc ──→ dispatcher ──→ Semaphore(N) ──→ tokio::spawn
//!            (returns fast)      (bounded)                                  ├── resolve()
//!                                                                           └── store()
//! ```

use std::sync::Arc;
use std::time::Instant;

use metrics::{counter, gauge};
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinHandle;
use tonic::{Request, Response, Status};
use tracing::{debug, error, warn};

use crate::telemetry::{
    METRIC_INFLIGHT_SESSIONS, METRIC_RESOLUTIONS_ERROR, METRIC_RESOLUTIONS_SUCCESS,
    METRIC_RESOLUTIONS_TOTAL, METRIC_RX_QUEUE_DEPTH, METRIC_SESSIONS_DROPPED,
    METRIC_SESSIONS_ENQUEUED,
};

use crate::resolve::SessionResolver;
use crate::sink::SessionSink;
use bistouri_api::v1 as proto;
use bistouri_api::v1::capture_service_server::CaptureService;

/// gRPC handler that receives `SessionPayload`s from agents and enqueues
/// them for asynchronous resolution + storage.
///
/// The handler only holds an `mpsc::Sender` — no Mutex, no contention.
/// Cloning is cheap (Arc'd internally by tokio).
pub(crate) struct SymbolizerService {
    tx: mpsc::Sender<proto::SessionPayload>,
    /// Fixed at construction for O(1) queue depth computation.
    queue_max_capacity: usize,
}

impl SymbolizerService {
    pub(crate) fn new(tx: mpsc::Sender<proto::SessionPayload>) -> Self {
        let queue_max_capacity = tx.max_capacity();
        Self {
            tx,
            queue_max_capacity,
        }
    }
}

#[tonic::async_trait]
impl CaptureService for SymbolizerService {
    async fn report_session(
        &self,
        request: Request<proto::SessionPayload>,
    ) -> std::result::Result<Response<()>, Status> {
        let payload = request.into_inner();

        let pid = payload.metadata.as_ref().map(|m| m.pid).unwrap_or(0);
        let trace_count = payload.traces.len();

        debug!(
            session_id = %payload.session_id,
            pid = pid,
            total_samples = payload.total_samples,
            traces = trace_count,
            mappings = payload.mappings.len(),
            "received session payload — enqueuing"
        );

        // Non-blocking enqueue: if the queue is full, shed the payload
        // and return RESOURCE_EXHAUSTED so the agent knows to back off.
        match self.tx.try_send(payload) {
            Ok(()) => {
                counter!(METRIC_SESSIONS_ENQUEUED).increment(1);
                // Record queue depth: items currently buffered.
                let depth = self.queue_max_capacity - self.tx.capacity();
                gauge!(METRIC_RX_QUEUE_DEPTH).set(depth as f64);
                Ok(Response::new(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    pid = pid,
                    traces = trace_count,
                    "processing queue full — dropping session"
                );
                counter!(METRIC_SESSIONS_DROPPED).increment(1);
                gauge!(METRIC_RX_QUEUE_DEPTH).set(self.queue_max_capacity as f64);
                Err(Status::resource_exhausted(
                    "symbolizer processing queue full",
                ))
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("processing worker has shut down");
                Err(Status::unavailable("symbolizer is shutting down"))
            }
        }
    }
}

// ── Background processing dispatcher ────────────────────────────────────

/// Handle to the background processing pipeline.
///
/// Created by [`ProcessingWorker::spawn`], used by the daemon for
/// coordinated shutdown.
pub(crate) struct ProcessingWorker {
    handle: JoinHandle<()>,
}

impl ProcessingWorker {
    /// Spawns the dispatcher and returns the sender half for the gRPC
    /// service, plus the worker handle for shutdown coordination.
    ///
    /// `max_concurrent` controls the semaphore — how many sessions can
    /// be resolved + stored in parallel. Independent of `queue_capacity`.
    pub(crate) fn spawn<S>(
        resolver: Arc<SessionResolver>,
        sink: Arc<S>,
        queue_capacity: usize,
        max_concurrent: usize,
    ) -> (mpsc::Sender<proto::SessionPayload>, Self)
    where
        S: SessionSink + 'static + ?Sized,
    {
        let (tx, rx) = mpsc::channel(queue_capacity);
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let handle = tokio::spawn(dispatcher_loop(resolver, sink, rx, semaphore));
        (tx, Self { handle })
    }

    /// Waits for the dispatcher task to complete.
    ///
    /// The caller must drop all `Sender` clones first so the dispatcher
    /// can drain and exit.
    pub(crate) async fn join(self) {
        let _ = self.handle.await;
    }
}

/// Dispatcher loop: pulls payloads from the channel and spawns a
/// semaphore-bounded task for each one, tracking handles via `JoinSet`.
///
/// When `max_concurrent` tasks are in flight, `semaphore.acquire()`
/// suspends the dispatcher — the channel fills — `try_send` fails —
/// agents get `RESOURCE_EXHAUSTED`. Backpressure propagates end-to-end.
///
/// On shutdown (channel closed), all in-flight tasks are joined before
/// the dispatcher exits — no orphaned handles.
async fn dispatcher_loop<S>(
    resolver: Arc<SessionResolver>,
    sink: Arc<S>,
    mut rx: mpsc::Receiver<proto::SessionPayload>,
    semaphore: Arc<Semaphore>,
) where
    S: SessionSink + 'static + ?Sized,
{
    let mut tasks = tokio::task::JoinSet::new();

    while let Some(payload) = rx.recv().await {
        // Reap completed task handles to prevent unbounded accumulation.
        // Without this, the JoinSet retains a completion entry for every
        // finished task until join_next() is called — which previously
        // only happened at shutdown.
        while let Some(result) = tasks.try_join_next() {
            if let Err(e) = result {
                error!(error = %e, "session processing task panicked");
            }
        }

        // Acquire a permit before spawning — blocks the dispatcher when
        // max_concurrent tasks are in flight, applying backpressure.
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => break, // Semaphore closed — shutting down.
        };

        let resolver = resolver.clone();
        let sink = sink.clone();

        tasks.spawn(async move {
            gauge!(METRIC_INFLIGHT_SESSIONS).increment(1.0);
            process_session(resolver, sink, payload).await;
            gauge!(METRIC_INFLIGHT_SESSIONS).decrement(1.0);
            drop(permit); // Release the semaphore slot.
        });
    }

    // Channel closed — join all in-flight tasks before exiting.
    while let Some(result) = tasks.join_next().await {
        if let Err(e) = result {
            error!(error = %e, "session processing task panicked during shutdown");
        }
    }

    debug!("processing dispatcher shut down — all tasks joined");
}

/// Processes a single session: resolve all frames, then store.
///
/// Metrics and errors are recorded here — the gRPC handler never sees
/// them (fire-and-forget).
async fn process_session<S>(
    resolver: Arc<SessionResolver>,
    sink: Arc<S>,
    payload: proto::SessionPayload,
) where
    S: SessionSink + 'static + ?Sized,
{
    let start_time = Instant::now();
    counter!(METRIC_RESOLUTIONS_TOTAL).increment(1);

    let session_id_for_log = payload.session_id.clone();

    // Phase 1+2: async prefetch + blocking DWARF walk.
    let resolved = resolver.resolve(payload).await;
    let session_id = resolved.session_id.clone();

    // Phase 3: store in downstream sink.
    if let Err(e) = sink.store(resolved).await {
        error!(
            session_id = %session_id,
            error = %e,
            "sink store failed"
        );
        counter!(METRIC_RESOLUTIONS_ERROR).increment(1);
        return;
    }

    counter!(METRIC_RESOLUTIONS_SUCCESS).increment(1);

    debug!(
        session_id = %session_id_for_log,
        elapsed_ms = start_time.elapsed().as_millis() as u64,
        "session processed"
    );
}
