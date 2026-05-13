//! Symbolizer E2E integration tests.
//!
//! Deploys the symbolizer + debuginfod sidecar in k3s, sends
//! SessionPayloads via gRPC, and asserts resolved function names
//! appear in `kubectl logs` output from the LogSink.
//!
//! Single-deploy architecture: the cluster is deployed once, all
//! test phases run sequentially, then teardown happens on Drop.
//! This mirrors the agent's E2E pattern.
//!
//! Prerequisites (handled by `run-e2e-wrapper.sh`):
//!   - k3s running on the host with KUBECONFIG exported.
//!   - Symbolizer and debuginfod-fixtures images loaded into k3s containerd.

mod cluster;
mod error;
mod fixture;
mod kernel_meta;

use std::time::Duration;

use bistouri_api::v1::capture_service_client::CaptureServiceClient;
use reqwest::StatusCode;
use tonic::transport::Channel;
use tracing::{info, warn};

use crate::cluster::E2eCluster;
use crate::error::E2eError;

/// Timeout for the symbolizer pod to become ready.
const POD_READY_TIMEOUT: Duration = Duration::from_secs(120);

/// Time to wait after sending payloads for the LogSink to flush.
const LOG_FLUSH_DELAY: Duration = Duration::from_secs(5);

/// Timeout for the gRPC client to connect to the symbolizer.
const GRPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(60);

/// Timeout for debuginfod to finish indexing fixture ELFs.
const DEBUGINFOD_INDEX_TIMEOUT: Duration = Duration::from_secs(60);

/// K8s manifests directory (relative to CARGO_MANIFEST_DIR).
fn k8s_dir() -> String {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    format!("{manifest_dir}/tests/e2e/k8s")
}

/// Connect a gRPC client to the symbolizer on localhost:50051.
async fn connect_grpc() -> Result<CaptureServiceClient<Channel>, E2eError> {
    let endpoint = "http://localhost:50051";
    info!(endpoint, "connecting gRPC client");

    let deadline = tokio::time::Instant::now() + GRPC_CONNECT_TIMEOUT;
    loop {
        match CaptureServiceClient::connect(endpoint.to_string()).await {
            Ok(client) => {
                info!("gRPC client connected");
                return Ok(client);
            }
            Err(e) => {
                if tokio::time::Instant::now() > deadline {
                    return Err(E2eError::Timeout {
                        what: "gRPC connection".into(),
                        timeout: GRPC_CONNECT_TIMEOUT,
                    });
                }
                tracing::debug!(error = %e, "gRPC not ready, retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

/// Wait for the debuginfod sidecar to finish indexing by probing
/// its HTTP endpoint for a known build_id.
///
/// Without this, the symbolizer may query debuginfod before indexing
/// completes, get a 404, and permanently negative-cache the build_id.
async fn wait_debuginfod_indexed(build_id_hex: &str) {
    let url = format!("http://localhost:8002/buildid/{build_id_hex}/executable");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build HTTP client for debuginfod probe");

    let deadline = tokio::time::Instant::now() + DEBUGINFOD_INDEX_TIMEOUT;
    loop {
        // debuginfod only supports GET (HEAD returns 400).
        // Body is discarded — one-time probe during test setup.
        match client.get(&url).send().await {
            Ok(resp) if resp.status() == StatusCode::OK => {
                info!(build_id = build_id_hex, "debuginfod indexing confirmed");
                return;
            }
            Ok(resp) => {
                tracing::debug!(
                    build_id = build_id_hex,
                    status = %resp.status(),
                    "debuginfod not ready yet, retrying..."
                );
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "debuginfod probe failed, retrying..."
                );
            }
        }

        if tokio::time::Instant::now() > deadline {
            panic!(
                "debuginfod did not index build_id {build_id_hex} within {:?}",
                DEBUGINFOD_INDEX_TIMEOUT
            );
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Assert that `logs` contains all expected strings.
fn assert_all_in_logs(logs: &str, expected: &[impl AsRef<str>], context: &str) {
    let missing: Vec<&str> = expected
        .iter()
        .map(AsRef::as_ref)
        .filter(|s| !logs.contains(s))
        .collect();

    assert!(
        missing.is_empty(),
        "{context}: expected string(s) not found in logs: {missing:?}\n\
         --- logs excerpt (last 2000 chars) ---\n{tail}",
        tail = &logs[logs.len().saturating_sub(2000)..],
    );
}

// ─── Single orchestrator test ──────────────────────────────────────────

/// Full E2E test suite — single deploy, all phases sequential.
///
/// Phase 1: User-space frame resolution from fixture ELFs
/// Phase 2: Kernel frame resolution via debuginfod federation (skipped if kptr_restrict)
/// Phase 3: Unknown build_id graceful degradation
#[tokio::test]
async fn symbolizer_e2e() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".parse().unwrap()),
        )
        .with_test_writer()
        .init();

    let k8s_dir = k8s_dir();

    // ── Setup: deploy cluster + connect gRPC ─────────────────────────

    let cluster = E2eCluster::deploy(&k8s_dir).expect("failed to deploy cluster");
    cluster
        .wait_ready(POD_READY_TIMEOUT)
        .expect("symbolizer pod not ready");

    let mut client = connect_grpc()
        .await
        .expect("failed to connect gRPC to symbolizer");

    // ── Phase 1: User-space frame resolution ─────────────────────────

    info!("Phase 1: user-space frame resolution");

    let manifest = fixture::load_manifest().expect("failed to load fixture manifest");
    let hello = manifest.get("hello").expect("hello fixture not found");
    let expected = hello.expected_symbols();

    // Wait for the debuginfod sidecar to index fixture ELFs.
    // Without this, the symbolizer queries debuginfod before indexing
    // completes, gets 404, and negative-caches the build_id.
    wait_debuginfod_indexed(&hello.build_id_hex).await;

    let payload = fixture::build_user_payload("hello", hello);
    info!(session_id = %payload.session_id, "sending user-frame payload");
    client
        .report_session(payload)
        .await
        .expect("ReportSession RPC failed");

    tokio::time::sleep(LOG_FLUSH_DELAY).await;

    let logs = cluster
        .symbolizer_logs()
        .expect("failed to read symbolizer logs");

    // Assert function names appear in logs.
    assert_all_in_logs(
        &logs,
        &expected.function_names,
        "Phase 1: function name resolution",
    );

    // Assert source file:line locations appear (e.g. "target_function at hello.c:12").
    assert_all_in_logs(
        &logs,
        &expected.source_locations,
        "Phase 1: source location resolution",
    );

    info!("✅ Phase 1 passed: user frames resolved with source locations");

    // ── Phase 2: Kernel frame resolution ─────────────────────────────

    info!("Phase 2: kernel frame resolution");

    match kernel_meta::HostKernelMeta::read() {
        Ok(kernel) => {
            info!(
                build_id_len = kernel.build_id.len(),
                text_addr = format!("0x{:x}", kernel.text_addr),
                release = %kernel.release,
                known_symbols = kernel.known_symbols.len(),
                "host kernel metadata"
            );

            if kernel.known_symbols.is_empty() {
                warn!("⚠️  Phase 2 skipped: no known kernel symbols in /proc/kallsyms");
            } else {
                let payload = fixture::build_kernel_payload(&kernel);
                info!(session_id = %payload.session_id, "sending kernel-frame payload");
                client
                    .report_session(payload)
                    .await
                    .expect("ReportSession RPC failed for kernel frames");

                // vmlinux fetch from upstream may be slow.
                info!("waiting for debuginfod federation + symbolization...");
                tokio::time::sleep(Duration::from_secs(30)).await;

                let logs = cluster
                    .symbolizer_logs()
                    .expect("failed to read symbolizer logs");

                let expected_names: Vec<&str> = kernel
                    .known_symbols
                    .iter()
                    .map(|s| s.name.as_str())
                    .collect();

                let any_resolved = expected_names.iter().any(|name| logs.contains(name));

                assert!(
                    any_resolved,
                    "Phase 2: none of the expected kernel functions ({expected_names:?}) \
                     found in logs.\n\
                     --- logs excerpt (last 2000 chars) ---\n{tail}",
                    tail = &logs[logs.len().saturating_sub(2000)..],
                );

                info!("✅ Phase 2 passed: kernel frames resolved");
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                "⚠️  Phase 2 skipped: cannot read kernel metadata \
                 (kptr_restrict active or missing permissions)"
            );
        }
    }

    // ── Phase 3: Unknown build_id graceful degradation ───────────────

    info!("Phase 3: unknown build_id handling");

    let unknown_payload = bistouri_api::v1::SessionPayload {
        session_id: "e2e-unknown-buildid".into(),
        source: Some(bistouri_api::v1::CaptureSource {
            source: Some(bistouri_api::v1::capture_source::Source::Psi(
                bistouri_api::v1::PsiTrigger {
                    resource: bistouri_api::v1::PsiResourceType::Cpu as i32,
                },
            )),
        }),
        metadata: Some(bistouri_api::v1::Metadata {
            pid: 99999,
            comm: "e2e-unknown".into(),
            kernel_meta: Some(bistouri_api::v1::KernelMeta {
                release: "e2e-test".into(),
                build_id: vec![0; 20],
                text_addr: 0,
            }),
        }),
        traces: vec![bistouri_api::v1::CountedTrace {
            trace: Some(bistouri_api::v1::StackTrace {
                kernel_frames: vec![],
                user_frames: vec![bistouri_api::v1::UserFrame {
                    frame: Some(bistouri_api::v1::user_frame::Frame::Resolved(
                        bistouri_api::v1::ResolvedFrame {
                            mapping_index: 0,
                            file_offset: 0x1234,
                        },
                    )),
                }],
            }),
            on_cpu_count: 1,
            off_cpu_count: 0,
        }],
        total_samples: 1,
        capture_duration: Some(prost_types::Duration {
            seconds: 1,
            nanos: 0,
        }),
        sample_period_nanos: 1_000_000_000 / 19,
        mappings: vec![bistouri_api::v1::Mapping {
            build_id: vec![
                0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
        }],
    };

    info!("sending payload with unknown build_id");
    client
        .report_session(unknown_payload)
        .await
        .expect("ReportSession should not fail on unknown build_id");

    tokio::time::sleep(LOG_FLUSH_DELAY).await;

    let logs = cluster
        .symbolizer_logs()
        .expect("failed to read symbolizer logs");

    assert!(
        logs.contains("[unknown]"),
        "Phase 3: expected [unknown] frames for garbage build_id in logs.\n\
         --- logs excerpt (last 2000 chars) ---\n{tail}",
        tail = &logs[logs.len().saturating_sub(2000)..],
    );

    info!("✅ Phase 3 passed: unknown build_id handled gracefully");

    // ── Teardown happens automatically via E2eCluster::drop ──────────
    info!("🎉 All symbolizer E2E phases passed");
}
