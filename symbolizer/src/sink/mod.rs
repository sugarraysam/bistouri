//! Session sink trait — the extensible connector layer.
//!
//! The sink receives fully-resolved sessions and stores/exports them
//! to the downstream system. Implementations are swappable at runtime.

pub(crate) mod log;

use async_trait::async_trait;

use crate::model::ResolvedSession;

/// Errors from sink implementations.
#[derive(thiserror::Error, Debug)]
pub(crate) enum SinkError {
    #[allow(dead_code)]
    #[error("sink write failed: {0}")]
    Write(String),
}

/// Trait for downstream session storage/export.
///
/// Implementations:
/// - `LogSink`: logs resolved sessions (dev/debug, always available)
/// - Future: ClickHouse TSDB, pprof export, etc.
#[async_trait]
pub(crate) trait SessionSink: Send + Sync {
    /// Stores a fully-resolved session.
    ///
    /// Implementations should be idempotent — the symbolizer may retry
    /// on transient failures.
    async fn store(&self, session: ResolvedSession) -> std::result::Result<(), SinkError>;
}
