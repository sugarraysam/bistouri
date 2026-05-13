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

use tracing::{debug, error, info};

use self::build_id::{BuildId, BUILD_ID_SIZE};
use self::cache::{ObjectCache, SymbolCache};
use self::kernel::KernelResolver;
use self::user::UserResolver;
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
pub struct SessionResolver<C: DebuginfodClient> {
    cache: Arc<ObjectCache>,
    kernel: KernelResolver<C>,
    user: UserResolver<C>,
    symbols: Arc<SymbolCache>,
}

impl<C: DebuginfodClient + 'static> SessionResolver<C> {
    pub fn new(cache: Arc<ObjectCache>, client: Arc<C>, symbols: Arc<SymbolCache>) -> Self {
        let kernel = KernelResolver::new(cache.clone(), client.clone());
        let user = UserResolver::new(cache.clone(), client);
        Self {
            cache,
            kernel,
            user,
            symbols,
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

        // Phase 2: Symbolize in blocking context. Payload is moved, not cloned.
        let cache = self.cache.clone();
        let kernel_cache = self.kernel.cache_ref();
        let symbols = self.symbols.clone();
        match tokio::task::spawn_blocking(move || {
            resolve_session_blocking(payload, &cache, &kernel_cache, &symbols)
        })
        .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                // Task panicked or was cancelled. Use static placeholders
                // instead of pre-cloning metadata on the happy path.
                error!(error = %e, "resolve task panicked or was cancelled");
                ResolvedSession {
                    session_id: String::new(),
                    pid: 0,
                    comm: "<panic>".into(),
                    kernel_release: String::new(),
                    traces: Vec::new(),
                    total_samples: 0,
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
                let user = self.user.cache_ref();
                let client = Arc::clone(&self.user.client_ref());
                let user_resolver = UserResolver::new(user, client);
                set.spawn(async move {
                    user_resolver.ensure_cached(&bid).await;
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
    cache: &ObjectCache,
    kernel_cache: &ObjectCache,
    symbols: &SymbolCache,
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
                                kernel_cache,
                                symbols,
                            )
                        })
                        .collect()
                })
                .unwrap_or_default();

            let user_frames: Vec<ResolvedFrame> = trace
                .map(|t| {
                    t.user_frames
                        .iter()
                        .map(|uf| resolve_user_frame(uf, &payload.mappings, cache, symbols))
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
/// Uses the pre-extracted build ID reference and cached `static_text_addr` —
/// no per-frame slice conversion or vmlinux re-parsing.
fn resolve_kernel_frame_blocking(
    raw_ip: u64,
    runtime_text_addr: u64,
    kernel_bid: Option<&BuildId>,
    cache: &ObjectCache,
    symbols: &SymbolCache,
) -> ResolvedFrame {
    let Some(bid) = kernel_bid else {
        return ResolvedFrame::Symbolized(SymbolInfo::unknown());
    };

    cache
        .with_object(bid, |obj| {
            let static_text = obj
                .static_text_addr
                .unwrap_or(kernel::DEFAULT_STATIC_TEXT_ADDR);
            let vmlinux_vaddr = raw_ip
                .wrapping_sub(runtime_text_addr)
                .wrapping_add(static_text);

            // L2 symbol cache check for kernel frames.
            let key = (*bid, vmlinux_vaddr);
            if let Some(cached) = symbols.get(&key) {
                return ResolvedFrame::clone(&cached);
            }

            let frame = kernel::resolve_kernel_addr(obj, vmlinux_vaddr);
            symbols.insert(key, frame.clone());
            frame
        })
        .unwrap_or(ResolvedFrame::Symbolized(SymbolInfo::unknown()))
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
