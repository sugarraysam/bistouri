use bistouri_api::v1::capture_service_server::{CaptureService, CaptureServiceServer};
use bistouri_api::v1::SessionPayload;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::error::E2eError;

// Fixed port shared between the sink and the bistouri-agent YAML.
// The E2E suite owns the test machine — port contention is not a concern.
pub(crate) const SINK_PORT: u16 = 9500;

// ── Inner service impl ────────────────────────────────────────────────────

/// Tonic service implementation — the simplest `CaptureService` imaginable.
///
/// Appends every `SessionPayload` to a shared `Vec` and wakes any caller
/// waiting via `wait_for_sessions`. This is the E2E incarnation of
/// `SessionExporter`.
#[derive(Clone)]
struct SinkService {
    sessions: Arc<Mutex<Vec<SessionPayload>>>,
    notify: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl CaptureService for SinkService {
    async fn report_session(
        &self,
        request: Request<SessionPayload>,
    ) -> Result<Response<()>, Status> {
        let payload = request.into_inner();
        let comm = payload
            .metadata
            .as_ref()
            .and_then(|m| m.labels.get("comm"))
            .map(|s| s.as_str())
            .unwrap_or("<unknown>");

        tracing::debug!(
            session_id = %payload.session_id,
            comm = %comm,
            total_samples = payload.total_samples,
            "SessionSink: received completed session",
        );

        {
            let mut guard = self.sessions.lock().expect("sessions mutex poisoned");
            guard.push(payload);
        }
        self.notify.notify_waiters();

        Ok(Response::new(()))
    }
}

// ── Public handle ─────────────────────────────────────────────────────────

/// In-process gRPC server that collects `SessionPayload`s from the agent.
///
/// Start it before deploying the bistouri-agent; shut it down after assertions.
pub(crate) struct SessionSink {
    pub sessions: Arc<Mutex<Vec<SessionPayload>>>,
    notify: Arc<tokio::sync::Notify>,
    shutdown: CancellationToken,
}

impl SessionSink {
    /// Bind on `SINK_PORT` and start serving in a background tokio task.
    pub(crate) async fn start() -> Result<Self, E2eError> {
        let addr: SocketAddr = ([0, 0, 0, 0], SINK_PORT).into();

        // Bind eagerly so we can surface "port already in use" before we
        // deploy the daemonset.
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| E2eError::SinkBind {
                port: SINK_PORT,
                source: e,
            })?;

        let sessions: Arc<Mutex<Vec<SessionPayload>>> = Arc::new(Mutex::new(Vec::new()));
        let notify = Arc::new(tokio::sync::Notify::new());
        let shutdown = CancellationToken::new();

        let svc = SinkService {
            sessions: sessions.clone(),
            notify: notify.clone(),
        };

        let cancel = shutdown.clone();
        tokio::spawn(async move {
            info!(port = SINK_PORT, "SessionSink: listening for sessions");
            Server::builder()
                .add_service(CaptureServiceServer::new(svc))
                .serve_with_incoming_shutdown(
                    tokio_stream::wrappers::TcpListenerStream::new(listener),
                    cancel.cancelled(),
                )
                .await
                .expect("SessionSink server error");
            info!("SessionSink: shut down");
        });

        Ok(Self {
            sessions,
            notify,
            shutdown,
        })
    }

    /// Block until sessions have been received from **all** `expected_comms`,
    /// or until `timeout` elapses.
    ///
    /// Returns the full snapshot of received sessions on success.
    pub(crate) async fn wait_for_comms(
        &self,
        expected_comms: &[&str],
        timeout: Duration,
    ) -> Result<Vec<SessionPayload>, E2eError> {
        let expected: HashSet<&str> = expected_comms.iter().copied().collect();

        tokio::time::timeout(timeout, async {
            loop {
                {
                    let guard = self.sessions.lock().expect("sessions mutex poisoned");
                    let seen: HashSet<&str> = guard
                        .iter()
                        .filter_map(|s| {
                            s.metadata
                                .as_ref()
                                .and_then(|m| m.labels.get("comm"))
                                .map(|s| s.as_str())
                        })
                        .collect();
                    if expected.is_subset(&seen) {
                        return guard.clone();
                    }
                }
                // Wait for the next session to arrive before re-checking.
                self.notify.notified().await;
            }
        })
        .await
        .map_err(|_| E2eError::Timeout {
            what: format!(
                "sessions from comms {:?} via gRPC sink on port {SINK_PORT}",
                expected_comms
            ),
            timeout,
        })
    }

    /// Shut down the gRPC server gracefully.
    pub(crate) fn shutdown(&self) {
        self.shutdown.cancel();
    }
}
