//! Bistouri E2E integration tests.
//!
//! Deploys Bistouri as a Pod in a k3s cluster alongside three stress
//! workloads (cpu-burner, io-burner, mem-burner). Validates:
//!
//!   Phase 1: Completed sessions arrive at the gRPC sink for each workload,
//!             then Prometheus counters and frame quality are checked in one
//!             scrape.
//!   Phase 2: Config hot-reload is detected by the agent.
//!
//! Prerequisites (handled by `run-e2e-wrapper.sh`):
//!   - k3s running on the host with KUBECONFIG exported.
//!   - Bistouri and stress images loaded into k3s containerd.

mod cluster;
mod error;
mod grpc_sink;
mod metrics;

use cluster::E2eCluster;
use grpc_sink::SessionSink;
use metrics::MetricsClient;
use std::time::Duration;
use tracing::info;

const METRICS_PORT: u16 = 9464;
const METRICS_REACHABLE_TIMEOUT: Duration = Duration::from_secs(180);
const PHASE1_TIMEOUT: Duration = Duration::from_secs(120);
const PHASE2_TIMEOUT: Duration = Duration::from_secs(120);

// The three workloads whose sessions we expect to receive.
const EXPECTED_COMMS: &[&str] = &["cpu-burner", "io-burner", "mem-burner"];

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

    // ── Start gRPC sink (before deploying the agent) ──────────────────
    // The sink must be up before the agent connects, so we start it first.
    // Port is fixed (SINK_PORT = 9500) and shared with the pod YAML.
    let sink = SessionSink::start()
        .await
        .expect("failed to start gRPC session sink");
    info!(port = grpc_sink::SINK_PORT, "gRPC session sink listening");

    // ── Deploy Phase 1 ───────────────────────────────────────────────
    let cluster = E2eCluster::deploy_phase1(&k8s_dir).expect("failed to deploy Phase 1 resources");

    // ── Readiness: poll metrics endpoint ─────────────────────────────
    metrics
        .wait_until_reachable(METRICS_REACHABLE_TIMEOUT)
        .await
        .expect("bistouri metrics endpoint never became reachable");

    // ── Phase 1: Wait for completed sessions ─────────────────────────
    // The sink receives a SessionPayload for each workload once its capture
    // window finishes. This is a stronger signal than any Prometheus counter:
    // it confirms the full pipeline (PSI → BPF capture → serialization →
    // gRPC delivery) completed end-to-end.
    info!("Phase 1: waiting for completed sessions from all workloads");

    let sessions = sink
        .wait_for_comms(EXPECTED_COMMS, PHASE1_TIMEOUT)
        .await
        .expect("did not receive a completed session for every workload");

    for comm in EXPECTED_COMMS {
        let session = sessions
            .iter()
            .find(|s| {
                s.metadata
                    .as_ref()
                    .and_then(|m| m.labels.get("comm"))
                    .is_some_and(|c| c == comm)
            })
            .unwrap_or_else(|| panic!("no session received for workload {comm}"));

        assert!(
            session.total_samples > 0,
            "{comm}: completed session has zero stack samples — \
            check BPF pid_filter_map insertion and process liveness during capture window"
        );

        info!(
            comm = %comm,
            session_id = %session.session_id,
            total_samples = session.total_samples,
            "✅ received completed session",
        );
    }

    // ── Phase 1: Prometheus counter + frame quality assertions ────────
    // The gRPC sink confirmed the pipeline ran — counters are stable.
    // One scrape, all assertions. No polling needed.
    info!("Phase 1: scraping Prometheus counters");
    let snapshot = metrics.scrape().await.expect("failed to scrape metrics");

    // Sessions completed per workload — stronger signal than "started" since it
    // confirms the full capture window ran and the payload was shipped.
    for comm in EXPECTED_COMMS {
        let val = snapshot.counter("bistouri_capture_sessions_completed", Some(("comm", comm)));
        assert!(
            val > 0.0,
            "no completed capture sessions for {comm} (counter = {val})"
        );
        info!(comm, val, "✅ capture sessions completed");
    }

    // Frame quality: resolved must dominate corrupted.
    let resolved = snapshot.counter("bistouri_profiler_user_frames", Some(("kind", "resolved")));
    let corrupted = snapshot.counter("bistouri_profiler_user_frames", Some(("kind", "corrupted")));
    let unresolved = snapshot.counter(
        "bistouri_profiler_user_frames",
        Some(("kind", "unresolved")),
    );
    let vdso = snapshot.counter("bistouri_profiler_user_frames", Some(("kind", "vdso")));

    info!("📊 Frame quality: resolved={resolved} corrupted={corrupted} unresolved={unresolved} vdso={vdso}");
    assert!(
        resolved > corrupted,
        "resolved frames ({resolved}) must exceed corrupted ({corrupted}) — \
         check -fno-omit-frame-pointer in Dockerfile.stress"
    );

    for comm in EXPECTED_COMMS {
        let empty = snapshot.counter("bistouri_capture_sessions_empty", Some(("comm", comm)));
        assert!(
            empty == 0.0,
            "bistouri_capture_sessions_empty[{comm}] = {empty} — capture session \
            produced no samples; check for PID staleness or a short pressure window"
        );
    }
    info!("✅ bistouri_capture_sessions_empty = 0 for all workloads");

    let completed_total = snapshot.counter("bistouri_capture_sessions_completed", None);
    info!(completed_total, "📊 Phase 1: completed sessions");

    // ── Phase 2: Hot-reload config ───────────────────────────────────
    info!("Phase 2: testing config hot-reload");

    // Snapshot the current reload count before triggering the change.
    let initial_reloads = snapshot.counter("bistouri_trigger_config_reloads", None);

    cluster
        .apply_phase2_config()
        .expect("failed to apply Phase 2 config");

    // Poll until the agent detects the reload — this is the only place we
    // genuinely need to wait for a future event.
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

    sink.shutdown();
    info!("🎉 All E2E assertions passed");
}
