use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum E2eError {
    #[error("kubectl {args}: {message}")]
    Kubectl { args: String, message: String },

    #[error("timeout waiting for {what} (after {timeout:?})")]
    Timeout { what: String, timeout: Duration },

    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("gRPC transport: {0}")]
    Transport(#[from] tonic::transport::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("fixture error: {0}")]
    Fixture(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("kernel metadata: {0}")]
    KernelMeta(String),
}
