//! gRPC service implementation for `CaptureService::ReportSession`.

use std::sync::Arc;

use tonic::{Request, Response, Status};
use tracing::{debug, warn};

use crate::debuginfod::DebuginfodClient;
use crate::resolve::SessionResolver;
use crate::sink::SessionSink;
use bistouri_api::v1 as proto;
use bistouri_api::v1::capture_service_server::CaptureService;

/// gRPC handler that receives `SessionPayload`s from agents,
/// resolves their frames, and stores the results via the sink.
///
/// Generic over both the debuginfod client and the sink to enable
/// static dispatch throughout the pipeline — no vtable overhead.
pub struct SymbolizerService<C: DebuginfodClient, S: SessionSink> {
    resolver: Arc<SessionResolver<C>>,
    sink: Arc<S>,
}

impl<C: DebuginfodClient + 'static, S: SessionSink + 'static> SymbolizerService<C, S> {
    pub fn new(resolver: Arc<SessionResolver<C>>, sink: Arc<S>) -> Self {
        Self { resolver, sink }
    }
}

#[tonic::async_trait]
impl<C: DebuginfodClient + 'static, S: SessionSink + 'static> CaptureService
    for SymbolizerService<C, S>
{
    async fn report_session(
        &self,
        request: Request<proto::SessionPayload>,
    ) -> std::result::Result<Response<()>, Status> {
        let payload = request.into_inner();

        // Extract lightweight metadata for logging before moving the payload.
        let session_id = payload.session_id.clone();
        let pid = payload.metadata.as_ref().map(|m| m.pid).unwrap_or(0);
        let total_samples = payload.total_samples;
        let trace_count = payload.traces.len();
        let mapping_count = payload.mappings.len();

        debug!(
            session_id = %session_id,
            pid = pid,
            total_samples = total_samples,
            traces = trace_count,
            mappings = mapping_count,
            "received session payload"
        );

        // Phase 1+2: resolve (async prefetch + blocking symbolization).
        // Payload is moved into the resolver — no expensive clone.
        let resolved = self.resolver.resolve(payload).await;

        // Phase 3: store via the configured sink.
        if let Err(e) = self.sink.store(resolved).await {
            warn!(
                session_id = %session_id,
                error = %e,
                "sink store failed"
            );
            return Err(Status::internal(format!("sink error: {e}")));
        }

        Ok(Response::new(()))
    }
}
