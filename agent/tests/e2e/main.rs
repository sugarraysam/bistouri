//! Bistouri E2E integration tests.
//!
//! Deploys Bistouri as a DaemonSet in a k3s cluster alongside three stress
//! workloads (cpu-burner, io-burner, mem-hog). Validates:
//!
//!   Phase 1: PSI triggers fire for the correct (workload, resource) pairs.
//!   Phase 2: Config hot-reload is detected by the agent.
//!
//! Prerequisites (handled by `run-e2e-wrapper.sh`):
//!   - k3s running on the host with KUBECONFIG exported.
//!   - Bistouri and stress images loaded into k3s containerd.

mod cluster;
mod error;
mod metrics;

use cluster::E2eCluster;
use metrics::MetricsClient;
use std::time::Duration;
use tracing::info;

const METRICS_PORT: u16 = 9464;
const METRICS_REACHABLE_TIMEOUT: Duration = Duration::from_secs(180);
const PHASE1_TIMEOUT: Duration = Duration::from_secs(120);
const PHASE2_TIMEOUT: Duration = Duration::from_secs(120);

fn k8s_dir() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{manifest_dir}/tests/e2e/k8s")
}

#[tokio::test]
async fn bistouri_e2e() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .with_test_writer()
        .init();

    let k8s_dir = k8s_dir();
    let metrics = MetricsClient::new(METRICS_PORT);

    // ── Deploy Phase 1 ───────────────────────────────────────────────
    let cluster = E2eCluster::deploy_phase1(&k8s_dir).expect("failed to deploy Phase 1 resources");

    // ── Readiness: poll metrics endpoint ─────────────────────────────
    metrics
        .wait_until_reachable(METRICS_REACHABLE_TIMEOUT)
        .await
        .expect("bistouri metrics endpoint never became reachable");

    // ── Phase 1: Assert triggers fire ────────────────────────────────
    info!("Phase 1: waiting for PSI triggers");

    let cpu_val = metrics
        .wait_for_counter_gt(
            "bistouri_capture_sessions_started",
            Some(("comm", "cpu-burner")),
            0.0,
            PHASE1_TIMEOUT,
        )
        .await
        .expect("cpu-burner did not trigger a CPU capture session");
    info!(cpu_val, "✅ cpu-burner triggered CPU capture session");

    // IO is now deterministic — io.max throttle guarantees io.pressure.
    let io_val = metrics
        .wait_for_counter_gt(
            "bistouri_capture_sessions_started",
            Some(("comm", "io-burner")),
            0.0,
            PHASE1_TIMEOUT,
        )
        .await
        .expect("io-burner did not trigger an IO capture session");
    info!(io_val, "✅ io-burner triggered IO capture session");

    let mem_val = metrics
        .wait_for_counter_gt(
            "bistouri_capture_sessions_started",
            Some(("comm", "mem-hog")),
            0.0,
            PHASE1_TIMEOUT,
        )
        .await
        .expect("mem-hog did not trigger a Memory capture session");
    info!(mem_val, "✅ mem-hog triggered Memory capture session");

    // ── Phase 1 Summary ──────────────────────────────────────────────
    // Wait for at least 3 completed sessions (one per workload) to
    // confirm the full capture pipeline finishes, not just triggers.
    let completed_total = metrics
        .wait_for_counter_gt(
            "bistouri_capture_sessions_completed",
            None,
            2.0,
            PHASE1_TIMEOUT,
        )
        .await
        .expect("capture sessions never completed (expected >= 3)");
    info!("📊 Phase 1 summary:");
    info!("   capture sessions started:  cpu={cpu_val} io={io_val} mem={mem_val}");
    info!("   capture sessions completed (total): {completed_total}");

    // ── Phase 1: Frame quality assertions ────────────────────────────
    // Validate the BPF stack unwinder produces usable frames. With
    // -fno-omit-frame-pointer on the stress binaries, resolved frames
    // must dominate. A regression here means the frame pointer flag was
    // dropped or the unwinder is broken.
    let resolved = metrics
        .get_counter("bistouri_profiler_user_frames", Some(("kind", "resolved")))
        .await
        .unwrap_or(0.0);
    let corrupted = metrics
        .get_counter("bistouri_profiler_user_frames", Some(("kind", "corrupted")))
        .await
        .unwrap_or(0.0);
    let unresolved = metrics
        .get_counter(
            "bistouri_profiler_user_frames",
            Some(("kind", "unresolved")),
        )
        .await
        .unwrap_or(0.0);
    let vdso = metrics
        .get_counter("bistouri_profiler_user_frames", Some(("kind", "vdso")))
        .await
        .unwrap_or(0.0);

    info!("📊 Frame quality: resolved={resolved} corrupted={corrupted} unresolved={unresolved} vdso={vdso}");

    assert!(
        resolved > corrupted,
        "resolved frames ({resolved}) must exceed corrupted ({corrupted}) — \
         check -fno-omit-frame-pointer in Dockerfile.stress"
    );

    // CPU samples must be ingested — validates the full BPF pipeline
    // (pid_filter_map → perf_event → ringbuf → user-space ingestion).
    let cpu_samples = metrics
        .get_counter(
            "bistouri_capture_samples_ingested",
            Some(("resource", "cpu")),
        )
        .await
        .unwrap_or(0.0);
    assert!(
        cpu_samples > 0.0,
        "expected CPU samples to be ingested, got {cpu_samples}"
    );
    info!("📊 CPU samples ingested: {cpu_samples}");

    // IO samples may be zero — perf_event only fires on-CPU, and
    // io-burner is mostly off-CPU in kernel I/O wait. Log but don't
    // assert until off-CPU profiling is implemented.
    let io_samples = metrics
        .get_counter(
            "bistouri_capture_samples_ingested",
            Some(("resource", "io")),
        )
        .await
        .unwrap_or(0.0);
    if io_samples == 0.0 {
        tracing::warn!("⚠️  IO samples ingested = 0 (expected — perf_event is on-CPU only)");
    } else {
        info!("📊 IO samples ingested: {io_samples}");
    }

    // ── Phase 2: Hot-reload config ───────────────────────────────────
    info!("Phase 2: testing config hot-reload");

    let initial_reloads = metrics
        .get_counter("bistouri_trigger_config_reloads", None)
        .await
        .unwrap_or(0.0);

    cluster
        .apply_phase2_config()
        .expect("failed to apply Phase 2 config");

    metrics
        .wait_for_counter_gt(
            "bistouri_trigger_config_reloads",
            None,
            initial_reloads,
            PHASE2_TIMEOUT,
        )
        .await
        .expect("config hot-reload was not detected");
    info!("✅ config hot-reload detected");

    info!("🎉 All E2E assertions passed");
}
