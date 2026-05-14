//! gRPC service implementation for `CaptureService::ReportSession`.

use std::sync::Arc;

use std::time::Instant;

use metrics::{counter, histogram};
use tonic::{Request, Response, Status};
use tracing::{debug, error};

use crate::telemetry::{
    METRIC_LATENCY_SECONDS, METRIC_RESOLUTIONS_ERROR, METRIC_RESOLUTIONS_SUCCESS,
    METRIC_RESOLUTIONS_TOTAL,
};

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
pub struct SymbolizerService<C: DebuginfodClient, S: SessionSink + ?Sized> {
    resolver: Arc<SessionResolver<C>>,
    sink: Arc<S>,
}

impl<C: DebuginfodClient + 'static, S: SessionSink + 'static + ?Sized> SymbolizerService<C, S> {
    pub fn new(resolver: Arc<SessionResolver<C>>, sink: Arc<S>) -> Self {
        Self { resolver, sink }
    }
}

#[tonic::async_trait]
impl<C: DebuginfodClient + 'static, S: SessionSink + 'static + ?Sized> CaptureService
    for SymbolizerService<C, S>
{
    async fn report_session(
        &self,
        request: Request<proto::SessionPayload>,
    ) -> std::result::Result<Response<()>, Status> {
        let start_time = Instant::now();
        counter!(METRIC_RESOLUTIONS_TOTAL).increment(1);

        let payload = request.into_inner();

        let pid = payload.metadata.as_ref().map(|m| m.pid).unwrap_or(0);
        let total_samples = payload.total_samples;
        let trace_count = payload.traces.len();
        let mapping_count = payload.mappings.len();

        debug!(
            session_id = %payload.session_id,
            pid = pid,
            total_samples = total_samples,
            traces = trace_count,
            mappings = mapping_count,
            "received session payload"
        );

        // Payload is moved into the resolver — no clone.
        let resolved = self.resolver.resolve(payload).await;

        let session_id = resolved.session_id.clone();

        if let Err(e) = self.sink.store(resolved).await {
            error!(
                session_id = %session_id,
                error = %e,
                "sink store failed"
            );
            counter!(METRIC_RESOLUTIONS_ERROR).increment(1);
            return Err(Status::internal(format!("sink error: {e}")));
        }

        histogram!(METRIC_LATENCY_SECONDS, "phase" => "total")
            .record(start_time.elapsed().as_secs_f64());
        counter!(METRIC_RESOLUTIONS_SUCCESS).increment(1);

        Ok(Response::new(()))
    }
}
