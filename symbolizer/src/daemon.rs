//! Top-level daemon lifecycle for the symbolizer service.
//!
//! `SymbolizerDaemon::start()` boots all subsystems, `shutdown()`
//! tears them down. `main()` is a thin CLI shim that calls both.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Server;
use tracing::info;

use crate::debuginfod::DebuginfodClient;
use crate::resolve::cache::CachePool;
use crate::resolve::SessionResolver;
use crate::server::SymbolizerService;
use crate::sink::SessionSink;

/// Configuration for the symbolizer daemon.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// gRPC listen address.
    pub listen_addr: SocketAddr,
}

/// Top-level lifecycle manager for the symbolizer service.
///
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
        caches: CachePool,
    ) -> anyhow::Result<Self>
    where
        C: DebuginfodClient + 'static,
        S: SessionSink + 'static,
    {
        let cancel = CancellationToken::new();

        let resolver = Arc::new(SessionResolver::new(caches, client));

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
