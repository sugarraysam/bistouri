//! Session sink trait — the extensible storage layer.
//!
//! The sink receives fully-resolved sessions and stores/exports them
//! to a downstream system. Implementations are swappable via the
//! generic `S: SessionSink` on `SymbolizerService`.
//!
//! **Implementing a custom sink:**
//!
//! 1. Add `bistouri-symbolizer` as a dependency in your private crate
//! 2. Implement `SessionSink` for your storage backend
//! 3. Wire it into your own `main()` via `SymbolizerDaemon::start()`
//!
//! See the crate-level docs for a complete example.

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
/// - `LogSink`: logs resolved sessions (dev/debug, always available)
///
/// External users implement this trait for their own storage backends
/// (ClickHouse, Postgres, S3 Parquet, Kafka, etc.) and plug it into
/// `SymbolizerDaemon::start()` — no symbolizer code changes needed.
#[async_trait::async_trait]
pub trait SessionSink: Send + Sync {
    /// Stores a fully-resolved session.
    async fn store(&self, session: ResolvedSession) -> std::result::Result<(), SinkError>;
}
