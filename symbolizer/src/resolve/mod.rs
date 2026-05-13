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
use self::cache::{NegativeCache, ObjectCache, SymbolCache};
use self::kernel::KernelResolver;
use crate::debuginfod::DebuginfodClient;
use crate::model::{ResolvedFrame, ResolvedSession, ResolvedTrace, SymbolInfo};
use bistouri_api::v1 as proto;

/// Maximum number of concurrent debuginfod fetches during prefetch.
/// Prevents overwhelming the debuginfod server on sessions with many
/// unique build IDs.
const MAX_CONCURRENT_FETCHES: usize = 16;

/// Orchestrates the full symbolization pipeline for a `SessionPayload`.
///
/// Generic over the debuginfod client type to enable static dispatch
/// (monomorphized at compile time, no vtable overhead).
///
/// Caches are split into kernel and user-space pools so vmlinux objects
/// (200+ MB) are never evicted by user-space churn.
pub struct SessionResolver<C: DebuginfodClient> {
    user_objects: ObjectCache,
    kernel_objects: ObjectCache,
    user_symbols: SymbolCache,
    kernel_symbols: SymbolCache,
    negative: NegativeCache,
    client: Arc<C>,
    kernel: KernelResolver<C>,
}

impl<C: DebuginfodClient + 'static> SessionResolver<C> {
    pub fn new(
        user_objects: ObjectCache,
        kernel_objects: ObjectCache,
        user_symbols: SymbolCache,
        kernel_symbols: SymbolCache,
        negative: NegativeCache,
        client: Arc<C>,
    ) -> Self {
        let kernel = KernelResolver::new(kernel_objects.clone(), negative.clone(), client.clone());
        Self {
            user_objects,
            kernel_objects,
            user_symbols,
            kernel_symbols,
            negative,
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
        let pid = payload.metadata.as_ref().map(|m| m.pid).unwrap_or(0);
        let total_samples = payload.total_samples;
        let comm = payload
            .metadata
            .as_ref()
            .map(|m| m.comm.clone())
            .unwrap_or_else(|| "<unknown>".into());

        // Phase 2: Symbolize in blocking context. Payload is moved, not cloned.
        // moka caches are Clone (internally Arc-wrapped) — cheap to move.
        let user_objects = self.user_objects.clone();
        let kernel_objects = self.kernel_objects.clone();
        let user_symbols = self.user_symbols.clone();
        let kernel_symbols = self.kernel_symbols.clone();
        match tokio::task::spawn_blocking(move || {
            resolve_session_blocking(
                payload,
                &user_objects,
                &kernel_objects,
                &user_symbols,
                &kernel_symbols,
            )
        })
        .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                error!(
                    session_id = %session_id,
                    error = %e,
                    "resolve task panicked or was cancelled"
                );
                ResolvedSession {
                    session_id,
                    pid,
                    comm,
                    kernel_release: String::new(),
                    traces: Vec::new(),
                    total_samples,
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
                let cache = self.user_objects.clone();
                let negative = self.negative.clone();
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
/// Takes ownership of the payload — no cloning required. Metadata
/// fields are moved (not cloned) into the `ResolvedSession`.
fn resolve_session_blocking(
    payload: proto::SessionPayload,
    user_objects: &ObjectCache,
    kernel_objects: &ObjectCache,
    user_symbols: &SymbolCache,
    kernel_symbols: &SymbolCache,
) -> ResolvedSession {
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

            let kernel_frames: Vec<ResolvedFrame> = trace
                .map(|t| {
                    t.kernel_frames
                        .iter()
                        .map(|&raw_ip| {
                            resolve_kernel_frame_blocking(
                                raw_ip,
                                runtime_text_addr,
                                kernel_bid,
                                kernel_objects,
                                kernel_symbols,
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            let user_frames: Vec<ResolvedFrame> = trace
                .map(|t| {
                    t.user_frames
                        .iter()
                        .map(|uf| {
                            resolve_user_frame(uf, &payload.mappings, user_objects, user_symbols)
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
    let pid = metadata.map(|m| m.pid).unwrap_or(0);
    let comm = metadata.map(|m| m.comm.as_str()).unwrap_or("<unknown>");
    let kernel_release = kernel_meta
        .map(|km| km.release.as_str())
        .unwrap_or_default();

    info!(
        session_id = %payload.session_id,
        pid = pid,
        comm = %comm,
        traces = traces.len(),
        total_samples = payload.total_samples,
        "session resolved"
    );

    ResolvedSession {
        session_id: payload.session_id,
        pid,
        comm: comm.into(),
        kernel_release: kernel_release.into(),
        traces,
        total_samples: payload.total_samples,
    }
}

/// Kernel frame resolution on the blocking path.
///
/// Metadata (static_text_addr) is read lock-free from `Arc<CachedObject>`.
/// L2 symbol cache is checked before any per-object lock. Only the DWARF
/// walk (`symbolize_vaddr`) acquires the per-object context Mutex.
fn resolve_kernel_frame_blocking(
    raw_ip: u64,
    runtime_text_addr: u64,
    kernel_bid: Option<&BuildId>,
    cache: &ObjectCache,
    symbols: &SymbolCache,
) -> ResolvedFrame {
    let start_time = Instant::now();

    let Some(bid) = kernel_bid else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return ResolvedFrame::Symbolized(SymbolInfo::unknown());
    };

    let Some(obj) = cache.get_object(bid) else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return ResolvedFrame::Symbolized(SymbolInfo::unknown());
    };
    counter!(METRIC_CACHE_HITS, "kind" => "object", "space" => "kernel").increment(1);

    // Lock-free metadata access — segments and static_text_addr are Sync.
    let static_text = obj
        .static_text_addr
        .unwrap_or(kernel::DEFAULT_STATIC_TEXT_ADDR);
    let vmlinux_vaddr = raw_ip
        .wrapping_sub(runtime_text_addr)
        .wrapping_add(static_text);

    // L2 symbol cache check — entirely lock-free.
    let key = (*bid, vmlinux_vaddr);
    if let Some(cached) = symbols.get(&key) {
        counter!(METRIC_CACHE_HITS, "kind" => "symbol", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return (*cached).clone();
    }
    counter!(METRIC_CACHE_MISSES, "kind" => "symbol", "space" => "kernel").increment(1);

    // Only the DWARF walk acquires the per-object context Mutex.
    let frame = kernel::resolve_kernel_addr(&obj, vmlinux_vaddr);
    symbols.insert(key, Arc::new(frame.clone()));
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
) -> ResolvedFrame {
    match frame.frame.as_ref() {
        Some(proto::user_frame::Frame::Resolved(resolved)) => {
            let mapping = mappings.get(resolved.mapping_index as usize);
            match mapping {
                Some(m) => {
                    if let Ok(build_id) = <&[u8; BUILD_ID_SIZE]>::try_from(m.build_id.as_slice()) {
                        user::resolve_frame(build_id, resolved.file_offset, cache, symbols)
                    } else {
                        ResolvedFrame::Symbolized(SymbolInfo::unknown())
                    }
                }
                None => ResolvedFrame::Symbolized(SymbolInfo::unknown()),
            }
        }
        Some(proto::user_frame::Frame::Placeholder(ph)) => {
            ResolvedFrame::Symbolized(SymbolInfo::placeholder(&ph.label))
        }
        None => ResolvedFrame::Symbolized(SymbolInfo::unknown()),
    }
}
