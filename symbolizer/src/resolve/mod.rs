//! Session-level resolution orchestrator.
//!
//! Two-phase design protecting the tokio event loop:
//! 1. **Fetch phase (async)**: ensure all required ELF objects are cached.
//! 2. **Resolve phase (blocking)**: symbolize frames in `spawn_blocking`.

pub mod build_id;
pub mod cache;
pub mod elf;
pub(crate) mod kernel;
pub(crate) mod user;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use std::time::Instant;

use metrics::{counter, histogram};
use tracing::{debug, error, info};

use crate::telemetry::{
    METRIC_CACHE_HITS, METRIC_CACHE_MISSES, METRIC_DWARF_WALK_SECONDS, METRIC_FRAMES_PER_SESSION,
    METRIC_LATENCY_SECONDS, METRIC_PREFETCH_SECONDS, METRIC_SPAWN_BLOCKING_WAIT_SECONDS,
};

use self::build_id::{BuildId, BUILD_ID_SIZE};
use self::cache::{CachePool, CachedObject, SymbolCache};
use self::kernel::KernelResolver;
use crate::debuginfod::coordinator::FetchCoordinator;
use crate::model::{
    CaptureSourceInfo, ResolvedFrame, ResolvedSession, ResolvedTrace, SymbolInfo, RESOURCE_CPU,
    RESOURCE_IO, RESOURCE_MEMORY, RESOURCE_UNKNOWN,
};
use bistouri_api::v1 as proto;

/// Orchestrates the full symbolization pipeline for a `SessionPayload`.
///
/// Generic over the debuginfod client type for static dispatch.
/// Caches are split into kernel and user-space pools so vmlinux objects
/// (200+ MB) are never evicted by user-space churn.
pub struct SessionResolver {
    caches: CachePool,
    coordinator: Arc<FetchCoordinator>,
    kernel: KernelResolver,
}

impl SessionResolver {
    pub fn new(caches: CachePool, coordinator: Arc<FetchCoordinator>) -> Self {
        let kernel = KernelResolver::new(
            caches.kernel_objects.clone(),
            caches.negative.clone(),
            coordinator.clone(),
        );
        Self {
            caches,
            coordinator,
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
        let prefetch_start = Instant::now();
        let user_prefetch = self.prefetch_user_build_ids(&payload);
        let kernel_prefetch = async {
            if let Some(km) = kernel_meta {
                self.kernel.ensure_cached(&km.build_id).await
            } else {
                None
            }
        };
        let (pinned_user_objects, pinned_kernel_object) =
            tokio::join!(user_prefetch, kernel_prefetch);
        histogram!(METRIC_PREFETCH_SECONDS).record(prefetch_start.elapsed().as_secs_f64());

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
        // Measure time waiting for a spawn_blocking slot.
        let blocking_enqueue_time = Instant::now();
        match tokio::task::spawn_blocking(move || {
            let wait_duration = blocking_enqueue_time.elapsed();
            histogram!(METRIC_SPAWN_BLOCKING_WAIT_SECONDS).record(wait_duration.as_secs_f64());
            resolve_session_blocking(payload, pinned_user_objects, pinned_kernel_object, &caches)
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
    /// Fetches are deduplicated and concurrency-bounded globally by the FetchCoordinator.
    async fn prefetch_user_build_ids(
        &self,
        payload: &proto::SessionPayload,
    ) -> HashMap<BuildId, Arc<CachedObject>> {
        let mut seen = HashSet::new();
        let unique_ids: Vec<BuildId> = payload
            .mappings
            .iter()
            .filter_map(|m| <&[u8; BUILD_ID_SIZE]>::try_from(m.build_id.as_slice()).ok())
            .copied()
            .filter(|bid| seen.insert(*bid))
            .collect();

        let mut set = tokio::task::JoinSet::new();
        for &bid in &unique_ids {
            let cache = self.caches.user_objects.clone();
            let negative = self.caches.negative.clone();
            let coordinator = self.coordinator.clone();
            set.spawn(async move {
                let obj = user::ensure_cached(&bid, &cache, &negative, coordinator.as_ref()).await;
                (bid, obj)
            });
        }

        let mut pinned = HashMap::with_capacity(unique_ids.len());
        while let Some(res) = set.join_next().await {
            if let Ok((bid, Some(obj))) = res {
                pinned.insert(bid, obj);
            }
        }

        debug!(
            unique_build_ids = unique_ids.len(),
            pinned_objects = pinned.len(),
            session_id = %payload.session_id,
            "user build IDs prefetched"
        );
        pinned
    }
}

/// CPU-bound symbolization of all frames in a session.
///
/// Takes ownership of the payload — no cloning required.
fn resolve_session_blocking(
    payload: proto::SessionPayload,
    pinned_user_objects: HashMap<BuildId, Arc<CachedObject>>,
    pinned_kernel_object: Option<Arc<CachedObject>>,
    caches: &CachePool,
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

            let kernel_frames: Vec<Arc<ResolvedFrame>> = trace
                .map(|t| {
                    t.kernel_frames
                        .iter()
                        .map(|&raw_ip| {
                            resolve_kernel_frame_blocking(
                                raw_ip,
                                runtime_text_addr,
                                kernel_bid,
                                &pinned_kernel_object,
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
                                &pinned_user_objects,
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

    // Emit frames-per-session histogram for workload characterization.
    let total_frames: usize = traces
        .iter()
        .map(|t| t.kernel_frames.len() + t.user_frames.len())
        .sum();
    histogram!(METRIC_FRAMES_PER_SESSION).record(total_frames as f64);

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
    // conversion, not recomputation. Negative fields from malformed
    // payloads are clamped to zero to prevent Duration::new() panics.
    let capture_start_time = payload
        .capture_start_time
        .as_ref()
        .map(proto_timestamp_to_system_time)
        .unwrap_or(std::time::UNIX_EPOCH);

    // Extract capture_duration from proto Duration.
    // Same clamping as above for negative fields.
    let capture_duration = payload
        .capture_duration
        .as_ref()
        .map(proto_duration_to_std)
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
    pinned_kernel_object: &Option<Arc<CachedObject>>,
    symbols: &SymbolCache,
) -> Arc<ResolvedFrame> {
    let start_time = Instant::now();

    let Some(bid) = kernel_bid else {
        counter!(METRIC_CACHE_MISSES, "kind" => "object", "space" => "kernel").increment(1);
        histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
            .record(start_time.elapsed().as_secs_f64());
        return Arc::new(ResolvedFrame::Symbolized(SymbolInfo::unknown()));
    };

    let Some(obj) = pinned_kernel_object else {
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

    let dwarf_start = Instant::now();
    let frame = Arc::new(kernel::resolve_kernel_addr(obj, vmlinux_vaddr));
    histogram!(METRIC_DWARF_WALK_SECONDS, "space" => "kernel")
        .record(dwarf_start.elapsed().as_secs_f64());
    symbols.insert(key, frame.clone());
    histogram!(METRIC_LATENCY_SECONDS, "phase" => "kernel")
        .record(start_time.elapsed().as_secs_f64());
    frame
}

/// Resolves a single user-space frame from its proto representation.
fn resolve_user_frame(
    frame: &proto::UserFrame,
    mappings: &[proto::Mapping],
    pinned_user_objects: &HashMap<BuildId, Arc<CachedObject>>,
    symbols: &SymbolCache,
) -> Arc<ResolvedFrame> {
    match frame.frame.as_ref() {
        Some(proto::user_frame::Frame::Resolved(resolved)) => {
            let mapping = mappings.get(resolved.mapping_index as usize);
            match mapping {
                Some(m) => {
                    if let Ok(build_id) = <&[u8; BUILD_ID_SIZE]>::try_from(m.build_id.as_slice()) {
                        user::resolve_frame(
                            build_id,
                            resolved.file_offset,
                            pinned_user_objects,
                            symbols,
                        )
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

/// Converts a proto `Timestamp` to `SystemTime`, clamping negative fields.
///
/// Protobuf `Timestamp` uses `i64` seconds and `i32` nanos. Malformed
/// payloads with negative values would wrap when cast to unsigned,
/// causing `Duration::new()` to panic (nanos ≥ 1_000_000_000).
#[inline]
fn proto_timestamp_to_system_time(ts: &prost_types::Timestamp) -> std::time::SystemTime {
    let secs = ts.seconds.max(0) as u64;
    let nanos = ts.nanos.clamp(0, 999_999_999) as u32;
    std::time::UNIX_EPOCH + std::time::Duration::new(secs, nanos)
}

/// Converts a proto `Duration` to `std::time::Duration`, clamping negative fields.
#[inline]
fn proto_duration_to_std(d: &prost_types::Duration) -> std::time::Duration {
    let secs = d.seconds.max(0) as u64;
    let nanos = d.nanos.clamp(0, 999_999_999) as u32;
    std::time::Duration::new(secs, nanos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Repro: negative `nanos` cast as `u32` wraps to > 999_999_999,
    /// causing `Duration::new()` to panic. After the fix, negatives
    /// are clamped to zero.
    #[rstest]
    #[case::negative_nanos_panicked(0, -1, 0, 0)]
    #[case::negative_seconds(-100, 0, 0, 0)]
    #[case::both_negative(-1, -1, 0, 0)]
    #[case::normal_values(1000, 500_000_000, 1000, 500_000_000)]
    #[case::nanos_at_max(0, 999_999_999, 0, 999_999_999)]
    #[case::nanos_over_max(0, 1_000_000_000, 0, 999_999_999)]
    fn proto_timestamp_clamps_negative(
        #[case] seconds: i64,
        #[case] nanos: i32,
        #[case] expected_secs: u64,
        #[case] expected_nanos: u32,
    ) {
        let ts = prost_types::Timestamp { seconds, nanos };
        let result = proto_timestamp_to_system_time(&ts);
        let expected =
            std::time::UNIX_EPOCH + std::time::Duration::new(expected_secs, expected_nanos);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case::negative_nanos_panicked(0, -1, 0, 0)]
    #[case::negative_seconds(-100, 0, 0, 0)]
    #[case::both_negative(-1, -1, 0, 0)]
    #[case::normal_values(60, 500_000, 60, 500_000)]
    #[case::nanos_over_max(0, 1_000_000_000, 0, 999_999_999)]
    fn proto_duration_clamps_negative(
        #[case] seconds: i64,
        #[case] nanos: i32,
        #[case] expected_secs: u64,
        #[case] expected_nanos: u32,
    ) {
        let d = prost_types::Duration { seconds, nanos };
        let result = proto_duration_to_std(&d);
        assert_eq!(
            result,
            std::time::Duration::new(expected_secs, expected_nanos)
        );
    }
}
