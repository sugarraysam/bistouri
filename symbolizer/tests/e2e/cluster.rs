use crate::error::E2eError;
use std::process::Command;
use tracing::info;

/// Manages the symbolizer pod lifecycle for E2E tests.
///
/// Applies the symbolizer pod manifest (symbolizer + debuginfod sidecar)
/// and cleans up on drop. Simpler than the agent's `E2eCluster` since
/// there are no CRDs, RBAC, or workloads — just one pod.
pub(crate) struct E2eCluster {
    k8s_dir: String,
}

impl E2eCluster {
    /// Deploy the symbolizer pod + debuginfod sidecar.
    pub(crate) fn deploy(k8s_dir: &str) -> Result<Self, E2eError> {
        info!("deploying symbolizer pod");
        kubectl(&["apply", "-f", &format!("{k8s_dir}/symbolizer-pod.yaml")])?;
        info!("symbolizer pod deployed");
        Ok(Self {
            k8s_dir: k8s_dir.to_string(),
        })
    }

    /// Wait for the symbolizer container to be ready.
    pub(crate) fn wait_ready(&self, timeout: std::time::Duration) -> Result<(), E2eError> {
        info!("waiting for symbolizer pod to be ready");
        let timeout_str = format!("{}s", timeout.as_secs());
        kubectl(&[
            "wait",
            "--for=condition=Ready",
            "pod/bistouri-symbolizer",
            &format!("--timeout={timeout_str}"),
        ])?;
        info!("symbolizer pod ready");
        Ok(())
    }

    /// Fetch symbolizer container logs for assertion.
    ///
    /// The LogSink outputs resolved function names at INFO level.
    /// E2E tests parse these logs to assert correct symbolization.
    pub(crate) fn symbolizer_logs(&self) -> Result<String, E2eError> {
        kubectl(&["logs", "bistouri-symbolizer", "-c", "symbolizer"])
    }
}

impl Drop for E2eCluster {
    fn drop(&mut self) {
        info!("cleaning up symbolizer pod");
        let _ = kubectl(&[
            "delete",
            "-f",
            &format!("{}/symbolizer-pod.yaml", self.k8s_dir),
            "--ignore-not-found",
        ]);
    }
}

/// Run a kubectl command, returning stdout on success.
fn kubectl(args: &[&str]) -> Result<String, E2eError> {
    let output = Command::new("kubectl")
        .args(args)
        .output()
        .map_err(|e| E2eError::Kubectl {
            args: args.join(" "),
            message: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(E2eError::Kubectl {
            args: args.join(" "),
            message: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
