use std::sync::Arc;

use clap::Parser;
use tracing::info;

use bistouri_symbolizer::debuginfod::http::HttpDebuginfodClient;
use bistouri_symbolizer::resolve::cache::{ObjectCache, SymbolCache};
use bistouri_symbolizer::resolve::SessionResolver;
use bistouri_symbolizer::server::SymbolizerService;
use bistouri_symbolizer::sink::log::LogSink;

/// Bistouri symbolizer service — resolves raw stack traces from agents
/// into human-readable function names, source files, and line numbers.
#[derive(Parser, Debug)]
#[command(name = "bistouri-symbolizer", version)]
struct Args {
    /// gRPC listen address.
    #[arg(long, default_value = "0.0.0.0:50051", env = "SYMBOLIZER_LISTEN_ADDR")]
    listen_addr: String,

    /// Debuginfod server URL.
    #[arg(long, default_value = "http://localhost:8002", env = "DEBUGINFOD_URL")]
    debuginfod_url: String,

    /// Maximum number of parsed ELF objects to cache.
    #[arg(long, default_value_t = 256, env = "SYMBOLIZER_CACHE_SIZE")]
    cache_size: usize,

    /// Maximum number of negative cache entries (404'd build IDs).
    #[arg(long, default_value_t = 512, env = "SYMBOLIZER_NEGATIVE_CACHE_SIZE")]
    negative_cache_size: usize,

    /// Maximum number of resolved symbols to cache (L2 symbol cache).
    #[arg(long, default_value_t = 100_000, env = "SYMBOLIZER_SYMBOL_CACHE_SIZE")]
    symbol_cache_size: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(
        listen_addr = %args.listen_addr,
        debuginfod_url = %args.debuginfod_url,
        cache_size = args.cache_size,
        "starting bistouri-symbolizer"
    );

    // Build the debuginfod client.
    let client = Arc::new(
        HttpDebuginfodClient::new(args.debuginfod_url)
            .map_err(|e| anyhow::anyhow!("failed to create debuginfod client: {e:#}"))?,
    );

    // Build the object cache (L1: parsed ELF objects).
    let cache = Arc::new(ObjectCache::new(args.cache_size, args.negative_cache_size));

    // Build the symbol cache (L2: resolved frames).
    let symbols = Arc::new(SymbolCache::new(args.symbol_cache_size));

    // Build the resolver.
    let resolver = Arc::new(SessionResolver::new(cache, client, symbols));

    // Build the sink (LogSink for the default binary — external users
    // write their own main() with a custom SessionSink).
    let sink = Arc::new(LogSink);

    // Build and start the gRPC server.
    let service = SymbolizerService::new(resolver, sink);

    let addr = args.listen_addr.parse()?;
    info!(addr = %addr, "gRPC server listening");

    tonic::transport::Server::builder()
        .add_service(bistouri_api::v1::capture_service_server::CaptureServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
