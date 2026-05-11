use crate::capture::error::ExportError;
use async_trait::async_trait;
use bistouri_api::v1::capture_service_client::CaptureServiceClient;
use bistouri_api::v1::SessionPayload;
use tonic::transport::Channel;
use tracing::{info, warn};

/// Downstream delivery contract for session payloads.
///
/// This is the modularity boundary: the E2E `SessionSink`, the real
/// symbolizer service, and any future consumer all implement this trait.
/// `BistouriDaemon` depends only on `Box<dyn SessionExporter>` — swapping
/// implementations requires no changes to the agent core.
#[async_trait]
pub(crate) trait SessionExporter: Send + Sync + 'static {
    async fn export(&self, payload: SessionPayload) -> Result<(), ExportError>;
}

// ── Log-only exporter (default when no endpoint is configured) ────────────

/// Placeholder exporter that logs session payloads and discards them.
/// Used until a symbolizer endpoint is configured.
pub(crate) struct NullExporter;

#[async_trait]
impl SessionExporter for NullExporter {
    async fn export(&self, payload: SessionPayload) -> Result<(), ExportError> {
        let meta = payload.metadata.as_ref();
        info!(
            session_id = %payload.session_id,
            pid = meta.map(|m| m.pid).unwrap_or(0),
            comm = %meta.map(|m| m.comm.as_str()).unwrap_or("<unknown>"),
            total_samples = payload.total_samples,
            unique_traces = payload.traces.len(),
            "completed session ready for symbolization (no endpoint configured)",
        );
        Ok(())
    }
}

// ── gRPC exporter (production + E2E) ─────────────────────────────────────

/// Ships `SessionPayload`s to a downstream `CaptureService` gRPC endpoint.
///
/// The channel is created once and re-used across sessions — tonic manages
/// connection health and reconnects transparently. The TCP connection is
/// established lazily on the first RPC call, so the agent starts successfully
/// even if the downstream service is temporarily unavailable.
pub(crate) struct GrpcExporter {
    endpoint: String,
    client: CaptureServiceClient<Channel>,
}

impl GrpcExporter {
    /// Prepare a lazy gRPC channel to `endpoint` (e.g. `"http://localhost:9500"`).
    ///
    /// Does NOT open a TCP connection — the handshake is deferred to the first
    /// `ReportSession` call. This means the agent binary never fails to start
    /// due to a transiently unavailable symbolizer.
    pub(crate) fn connect(endpoint: String) -> Result<Self, ExportError> {
        let channel = Channel::from_shared(endpoint.clone())
            .expect("invalid endpoint URI")
            .connect_lazy();
        Ok(Self {
            endpoint,
            client: CaptureServiceClient::new(channel),
        })
    }
}

#[async_trait]
impl SessionExporter for GrpcExporter {
    async fn export(&self, payload: SessionPayload) -> Result<(), ExportError> {
        let session_id = payload.session_id.clone();
        let total_samples = payload.total_samples;

        // Read comm before moving payload into the RPC call.
        let comm = payload
            .metadata
            .as_ref()
            .map(|m| m.comm.clone())
            .unwrap_or_default();

        // CaptureServiceClient<Channel> is cheap to clone (inner Arc).
        let mut client = self.client.clone();
        match client.report_session(payload).await {
            Ok(_) => {
                info!(
                    session_id = %session_id,
                    comm = %comm,
                    total_samples,
                    "session forwarded to downstream service",
                );
                Ok(())
            }
            Err(status) => {
                warn!(
                    session_id = %session_id,
                    comm = %comm,
                    endpoint = %self.endpoint,
                    code = ?status.code(),
                    message = %status.message(),
                    "session export failed — dropping (best-effort delivery)",
                );
                Err(ExportError::Grpc(status))
            }
        }
    }
}
