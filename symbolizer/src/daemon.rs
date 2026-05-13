//! Top-level daemon lifecycle for the symbolizer service.
//!
//! Mirrors the `BistouriDaemon` pattern from the agent crate:
//! `SymbolizerDaemon::start()` boots all subsystems, `shutdown()`
//! tears them down. `main()` is a thin CLI shim that calls both.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::info;

use crate::debuginfod::DebuginfodClient;
use crate::resolve::cache::{ObjectCache, SymbolCache};
use crate::resolve::SessionResolver;
use crate::server::SymbolizerService;
use crate::sink::SessionSink;

/// Configuration for the symbolizer daemon.
///
/// Validated on construction — all capacities must be > 0.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// gRPC listen address.
    pub listen_addr: SocketAddr,
    /// Maximum number of parsed ELF objects to cache (L1).
    pub cache_size: usize,
    /// Maximum number of negative cache entries (404'd build IDs).
    pub negative_cache_size: usize,
    /// Maximum number of resolved symbols to cache (L2).
    pub symbol_cache_size: usize,
}

/// Top-level lifecycle manager for the symbolizer service.
///
/// Generic over `C` (debuginfod client) and `S` (sink) — all static dispatch.
/// Owns a `CancellationToken` for coordinated shutdown.
pub struct SymbolizerDaemon {
    cancel: CancellationToken,
    server_handle: JoinHandle<Result<(), tonic::transport::Error>>,
}

impl SymbolizerDaemon {
    /// Boots the symbolizer service and starts serving gRPC requests.
    ///
    /// Returns immediately with a running daemon. Call `shutdown()` to
    /// stop the server gracefully.
    pub async fn start<C, S>(
        config: DaemonConfig,
        client: Arc<C>,
        sink: Arc<S>,
    ) -> anyhow::Result<Self>
    where
        C: DebuginfodClient + 'static,
        S: SessionSink + 'static,
    {
        let cancel = CancellationToken::new();

        // Build the object cache (L1: parsed ELF objects).
        let cache = Arc::new(ObjectCache::new(
            config.cache_size,
            config.negative_cache_size,
        ));

        // Build the symbol cache (L2: resolved frames).
        let symbols = Arc::new(SymbolCache::new(config.symbol_cache_size));

        // Build the resolver.
        let resolver = Arc::new(SessionResolver::new(cache, client, symbols));

        // Build the gRPC service.
        let service = SymbolizerService::new(resolver, sink);

        let addr = config.listen_addr;
        info!(addr = %addr, "gRPC server listening");

        let signal = cancel.clone();
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(
                    bistouri_api::v1::capture_service_server::CaptureServiceServer::new(service),
                )
                .serve_with_shutdown(addr, async move {
                    signal.cancelled().await;
                })
                .await
        });

        Ok(Self {
            cancel,
            server_handle,
        })
    }

    /// Shuts down the gRPC server gracefully.
    pub async fn shutdown(self) {
        self.cancel.cancel();
        let _ = self.server_handle.await;
    }
}
