//! Bistouri symbolizer library.
//!
//! Provides the complete symbolization pipeline as a reusable library.
//! Build a custom symbolizer binary with your own `SessionSink` by
//! importing these modules — no code modification required.
//!
//! # Example: custom sink
//!
//! ```ignore
//! use bistouri_symbolizer::sink::SessionSink;
//! use bistouri_symbolizer::server::SymbolizerService;
//!
//! struct ClickHouseSink { /* ... */ }
//!
//! #[async_trait::async_trait]
//! impl SessionSink for ClickHouseSink {
//!     async fn store(&self, session: ResolvedSession) -> Result<(), SinkError> {
//!         // write to ClickHouse
//!     }
//! }
//!
//! // Wire it in — the symbolizer code is unchanged:
//! let service = SymbolizerService::new(resolver, Arc::new(ClickHouseSink { /* ... */ }));
//! ```

pub mod debuginfod;
pub mod model;
pub mod resolve;
pub mod server;
pub mod sink;

pub mod error;
