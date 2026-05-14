//! Bistouri symbolizer library.
//!
//! Provides the complete symbolization pipeline as a reusable library.
//! Build a custom symbolizer binary with your own `SessionSink` by
//! importing these modules — no code modification required.
//!
//! # Example: custom sink
//!
//! ```ignore
//! use std::sync::Arc;
//! use bistouri_symbolizer::daemon::{DaemonConfig, SymbolizerDaemon};
//! use bistouri_symbolizer::sink::{SessionSink, SinkError};
//! use bistouri_symbolizer::model::ResolvedSession;
//!
//! struct ClickHouseSink { /* ... */ }
//!
//! #[async_trait::async_trait]
//! impl SessionSink for ClickHouseSink {
//!     async fn store(&self, session: ResolvedSession) -> Result<(), SinkError> {
//!         // write to ClickHouse
//!         todo!()
//!     }
//! }
//!
//! // Wire it in — the symbolizer library handles everything:
//! let daemon = SymbolizerDaemon::start(config, client, Arc::new(ClickHouseSink { }), caches).await?;
//! tokio::signal::ctrl_c().await?;
//! daemon.shutdown().await;
//! ```

pub mod daemon;
pub mod debuginfod;
pub mod model;
pub mod resolve;
pub mod server;
pub mod sink;

pub mod error;
pub mod telemetry;
