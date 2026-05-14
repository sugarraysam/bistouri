//! Session sink trait — the extensible storage layer.
//!
//! The sink receives fully-resolved sessions and stores/exports them
//! to a downstream system. Implement `SessionSink` and plug it into
//! `SymbolizerService<C, S>` — no symbolizer code changes needed.

pub mod log;

use crate::model::ResolvedSession;

/// Errors from sink implementations.
#[derive(thiserror::Error, Debug)]
pub enum SinkError {
    #[error("sink write failed: {0}")]
    Write(String),
}

/// Trait for downstream session storage/export.
///
/// Implementations:
/// - `LogSink`: logs resolved sessions (dev/debug)
/// - Future: ClickHouse TSDB, pprof export, etc.
#[async_trait::async_trait]
pub trait SessionSink: Send + Sync {
    /// Stores a fully-resolved session.
    async fn store(&self, session: ResolvedSession) -> std::result::Result<(), SinkError>;
}
