use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum E2eError {
    #[error("kubectl {args}: {message}")]
    Kubectl { args: String, message: String },

    #[error("timeout waiting for {what} (after {timeout:?})")]
    Timeout { what: String, timeout: Duration },

    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("failed to parse metrics: {0}")]
    MetricsParse(String),

    #[error("failed to bind gRPC sink on port {port}: {source}")]
    SinkBind { port: u16, source: std::io::Error },
}
