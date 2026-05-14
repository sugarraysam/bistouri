//! Session-level resolution orchestrator.
//!
//! Two-phase design protecting the tokio event loop:
//! 1. **Fetch phase (async)**: ensure all required ELF objects are cached.
//! 2. **Resolve phase (blocking)**: symbolize frames in `spawn_blocking`.

pub mod build_id;
pub mod cache;
pub(crate) mod elf;
pub(crate) mod kernel;
pub(crate) mod user;

use std::collections::HashSet;
use std::sync::Arc;

use std::time::Instant;

use metrics::{counter, histogram};
use tracing::{debug, error, info};

use crate::telemetry::{METRIC_CACHE_HITS, METRIC_CACHE_MISSES, METRIC_LATENCY_SECONDS};

use self::build_id::{BuildId, BUILD_ID_SIZE};
use self::cache::{CachePool, ObjectCache, SymbolCache};
use self::kernel::KernelResolver;
use crate::debuginfod::DebuginfodClient;
use crate::model::{
    CaptureSourceInfo, ResolvedFrame, ResolvedSession, ResolvedTrace, SymbolInfo, RESOURCE_CPU,
    RESOURCE_IO, RESOURCE_MEMORY, RESOURCE_UNKNOWN,
};
use bistouri_api::v1 as proto;

/// Maximum number of concurrent debuginfod fetches during prefetch.
const MAX_CONCURRENT_FETCHES: usize = 16;

/// Orchestrates the full symbolization pipeline for a `SessionPayload`.
///
/// Generic over the debuginfod client type for static dispatch.
/// Caches are split into kernel and user-space pools so vmlinux objects
/// (200+ MB) are never evicted by user-space churn.
pub struct SessionResolver<C: DebuginfodClient> {
    caches: CachePool,
    client: Arc<C>,
    kernel: KernelResolver<C>,
}

impl<C: DebuginfodClient + 'static> SessionResolver<C> {
    pub fn new(caches: CachePool, client: Arc<C>) -> Self {
        let kernel = KernelResolver::new(
            caches.kernel_objects.clone(),
            caches.negative.clone(),
            client.clone(),
        );
        Self {
            caches,
            client,
            kernel,
        }
    }

    /// Resolves all frames in a `SessionPayload`.
    ///
    /// Takes ownership of the payload to avoid cloning it into
    /// `spawn_blocking`. Metadata needed for logging is extracted
    /// before the move.
    ///
    /// Phase 1 (async): prefetch all unique build IDs from debuginfod.
    /// Phase 2 (blocking): symbolize frames against cached ELF objects.
    pub(crate) async fn resolve(&self, payload: proto::SessionPayload) -> ResolvedSession {
        let kernel_meta = payload
            .metadata
            .as_ref()
            .and_then(|m| m.kernel_meta.as_ref());

        // Phase 1: Prefetch user + kernel build IDs concurrently.
        let user_prefetch = self.prefetch_user_build_ids(&payload);
        if let Some(km) = kernel_meta {
            let kernel_prefetch = self.kernel.ensure_cached(&km.build_id);
            tokio::join!(user_prefetch, kernel_prefetch);
        } else {
            user_prefetch.await;
        }

        // Pre-extract metadata before moving the payload into spawn_blocking.
        let session_id = payload.session_id.clone();
        let total_samples = payload.total_samples;
        let _comm = payload
            .metadata
            .as_ref()
            .and_then(|m| m.labels.get("comm"))
            .cloned()
            .unwrap_or_else(|| "<unknown>".into());

        // Phase 2: Symbolize in blocking context. Payload is moved, not cloned.
        // moka caches are Clone (internally Arc-wrapped) — cheap to move.
        let caches = self.caches.clone();
        match tokio::task::spawn_blocking(move || resolve_session_blocking(payload, &caches)).await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                error!(
                    session_id = %session_id,
                    error = %e,
                    "resolve task panicked or was cancelled"
                );
                ResolvedSession {
                    tenant_id: String::new(),
                    service_id: String::new(),
                    session_id,
                    capture_source: CaptureSourceInfo::Psi {
                        resource: RESOURCE_UNKNOWN,
                    },
                    labels: Default::default(),
                    capture_start_time: std::time::SystemTime::UNIX_EPOCH,
                    capture_duration: std::time::Duration::ZERO,
                    kernel_release: String::new(),
                    traces: Vec::new(),
                    total_samples,
                    sample_period_nanos: 0,
                }
            }
        }
    }

    /// Ensures all unique user-space build IDs are cached.
    ///
    /// Fetches are dispatched concurrently up to `MAX_CONCURRENT_FETCHES`
    /// to avoid overwhelming the debuginfod server.
    async fn prefetch_user_build_ids(&self, payload: &proto::SessionPayload) {
        let mut seen = HashSet::new();
        let unique_ids: Vec<BuildId> = payload
            .mappings
            .iter()
            .filter_map(|m| <&[u8; BUILD_ID_SIZE]>::try_from(m.build_id.as_slice()).ok())
            .copied()
            .filter(|bid| seen.insert(*bid))
            .collect();

        // Fetch concurrently in bounded batches.
        for chunk in unique_ids.chunks(MAX_CONCURRENT_FETCHES) {
            let mut set = tokio::task::JoinSet::new();
            for &bid in chunk {
                let cache = self.caches.user_objects.clone();
                let negative = self.caches.negative.clone();
                let client = self.client.clone();
                set.spawn(async move {
                    user::ensure_cached(&bid, &cache, &negative, client.as_ref()).await;
                });
            }
            // Await all in this batch before starting the next.
            while set.join_next().await.is_some() {}
        }

        debug!(
            unique_build_ids = unique_ids.len(),
            session_id = %payload.session_id,
            "user build IDs prefetched"
        );
    }
}

/// CPU-bound symbolization of all frames in a session.
///
/// Takes ownership of the payload — no cloning required.
fn resolve_session_blocking(payload: proto::SessionPayload, caches: &CachePool) -> ResolvedSession {
    // Pre-extract kernel metadata once, not per-frame.
    let metadata = payload.metadata.as_ref();
    let kernel_meta = metadata.and_then(|m| m.kernel_meta.as_ref());
    let runtime_text_addr = kernel_meta.map(|km| km.text_addr).unwrap_or(0);
    let kernel_bid = kernel_meta.and_then(|km| build_id::try_from_slice(&km.build_id));

    let traces: Vec<ResolvedTrace> = payload
        .traces
        .iter()
        .map(|ct| {
            let trace = ct.trace.as_ref();

            let kernel_frames: Vec<Arc<ResolvedFrame>> = trace
                .map(|t| {
                    t.kernel_frames
                        .iter()
                        .map(|&raw_ip| {
                            resolve_kernel_frame_blocking(
                                raw_ip,
                                runtime_text_addr,
                                kernel_bid,
                                &caches.kernel_objects,
                                &caches.kernel_symbols,
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            let user_frames: Vec<Arc<ResolvedFrame>> = trace
                .map(|t| {
                    t.user_frames
                        .iter()
                        .map(|uf| {
                            resolve_user_frame(
                                uf,
                                &payload.mappings,
                                &caches.user_objects,
                                &caches.user_symbols,
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            ResolvedTrace {
                kernel_frames,
                user_frames,
                on_cpu_count: ct.on_cpu_count,
                off_cpu_count: ct.off_cpu_count,
            }
        })
        .collect();

    // Move metadata out of the payload — no cloning.
    let metadata = payload.metadata.as_ref();
    let comm = metadata
        .and_then(|m| m.labels.get("comm"))
        .map(|s| s.as_str())
        .unwrap_or("<unknown>");
    let kernel_release = kernel_meta
        .map(|km| km.release.as_str())
        .unwrap_or_default();

    // Extract capture source from proto.
    let capture_source = payload
        .source
        .as_ref()
        .and_then(|s| s.source.as_ref())
        .map(|src| match src {
            proto::capture_source::Source::Psi(psi) => {
                let resource = proto::PsiResourceType::try_from(psi.resource)
                    .map(|r| match r {
                        proto::PsiResourceType::Memory => RESOURCE_MEMORY,
                        proto::PsiResourceType::Cpu => RESOURCE_CPU,
                        proto::PsiResourceType::Io => RESOURCE_IO,
                        _ => RESOURCE_UNKNOWN,
                    })
                    .unwrap_or(RESOURCE_UNKNOWN);
                CaptureSourceInfo::Psi { resource }
            }
        })
        .unwrap_or(CaptureSourceInfo::Psi {
            resource: RESOURCE_UNKNOWN,
        });

    // Convert proto Timestamp → Rust SystemTime.
    // The value was set by the agent at capture start — this is format
    // conversion, not recomputation.
    let capture_start_time = payload
        .capture_start_time
        .as_ref()
        .map(|ts| {
            std::time::UNIX_EPOCH + std::time::Duration::new(ts.seconds as u64, ts.nanos as u32)
        })
        .unwrap_or(std::time::UNIX_EPOCH);

    // Extract capture_duration from proto Duration.
    let capture_duration = payload
        .capture_duration
        .as_ref()
        .map(|d| std::time::Duration::new(d.seconds as u64, d.nanos as u32))
        .unwrap_or(std::time::Duration::ZERO);

    // Extract labels from metadata.
    let labels = metadata.map(|m| m.labels.clone()).unwrap_or_default();

    info!(
        session_id = %payload.session_id,
        comm = %comm,
        tenant_id = %payload.tenant_id,
        service_id = %payload.service_id,
        traces = traces.len(),
        total_samples = payload.total_samples,
        "session resolved"
    );

    ResolvedSession {
        tenant_id: payload.tenant_id,
        service_id: payload.service_id,
        session_id: payload.session_id,
        capture_source,
        labels,
        capture_start_time,
        capture_duration,
        kernel_release: kernel_release.into(),
        traces,
        total_samples: payload.total_samples,
        sample_period_nanos: payload.sample_period_nanos,
    }
}

/// Kernel frame resolution on the blocking path.
fn resolve_kernel_frame_blocking(
    raw_ip: u64,
    runtime_text_addr: u64,
    kernel_bid: Option<&BuildId>,
    cache: &ObjectCache,
    symbols: &SymbolCache,
) -> Arc<ResolvedFrame> {
    let start_time = Instant::now();

    let Some(bid) = kernel_bid else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };

    let Some(obj) = cache.get_object(bid) else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };
    counter!(METRIC_CACHE_HITS, "kind" => "object", "space" => "kernel").increment(1);

    let static_text = obj
        .static_text_addr
        .unwrap_or(kernel::DEFAULT_STATIC_TEXT_ADDR);
    let vmlinux_vaddr = raw_ip
        .wrapping_sub(runtime_text_addr)
        .wrapping_add(static_text);

    // L2 symbol cache hit — zero-copy Arc return.
    let key = (*bid, vmlinux_vaddr);
    if let Some(cached) = symbols.get(&key) {
        counter!(METRIC_CACHE_HITS, "kind" => "symbol", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return cached;
    }
    counter!(METRIC_CACHE_MISSES, "kind" => "symbol", "space" => "kernel").increment(1);

    let frame = Arc::new(kernel::resolve_kernel_addr(&obj, vmlinux_vaddr));
    symbols.insert(key, frame.clone());
    histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
        .record(start_time.elapsed().as_secs_f64());
    frame
}

/// Resolves a single user-space frame from its proto representation.
fn resolve_user_frame(
    frame: &proto::UserFrame,
    mappings: &[proto::Mapping],
    cache: &ObjectCache,
    symbols: &SymbolCache,
) -> Arc<ResolvedFrame> {
    match frame.frame.as_ref() {
        Some(proto::user_frame::Frame::Resolved(resolved)) => {
            let mapping = mappings.get(resolved.mapping_index as usize);
            match mapping {
                Some(m) => {
                    if let Ok(build_id) = <&[u8; BUILD_ID_SIZE]>::try_from(m.build_id.as_slice()) {
                        user::resolve_frame(build_id, resolved.file_offset, cache, symbols)
                    } else {
                        Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()))
                    }
                }
                None => Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown())),
            }
        }
        Some(proto::user_frame::Frame::Placeholder(ph)) => Arc::new(ResolvedFrame::Symbolized(
            SymbolInfo::placeholder(&ph.label),
        )),
        None => Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown())),
    }
}
