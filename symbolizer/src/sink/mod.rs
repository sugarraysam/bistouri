//! Session sink trait — the extensible storage layer.
//!
//! The sink receives fully-resolved sessions and stores/exports them
//! to a downstream system. Implementations are swappable via the
//! generic `S: SessionSink` on `SymbolizerService`.
//!
//! To build a custom sink, implement `SessionSink` and wire it into
//! your own `main()` using the symbolizer library crate. No code
//! modification required.

pub mod log;

use async_trait::async_trait;

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
/// - `LogSink`: logs resolved sessions (dev/debug, always available)
/// - Future: ClickHouse TSDB, pprof export, etc.
///
/// External users implement this trait and plug it into
/// `SymbolizerService<C, S>` — no symbolizer code changes needed.
#[async_trait]
pub trait SessionSink: Send + Sync {
    /// Stores a fully-resolved session.
    ///
    /// Implementations should be idempotent — the symbolizer may retry
    /// on transient failures.
    async fn store(&self, session: ResolvedSession) -> std::result::Result<(), SinkError>;
}
