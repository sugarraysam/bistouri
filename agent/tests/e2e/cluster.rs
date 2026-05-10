use crate::error::E2eError;
use std::process::Command;
use tracing::info;

/// Manages Kubernetes resources for a single E2E test run.
///
/// Uses `kubectl apply/delete` directly — no kube-rs, no YAML
/// deserialization, no trait bounds. The manifests on disk are the
/// source of truth.
///
/// On drop, deletes all applied resources. The shell wrapper provides
/// the ultimate safety net if this process is killed.
pub(crate) struct E2eCluster {
    k8s_dir: String,
}

impl E2eCluster {
    /// Apply Phase 1 resources: ConfigMap (9 rules) + DaemonSet + stress
    /// workloads. Returns the cluster handle for Phase 2 and cleanup.
    pub(crate) fn deploy_phase1(k8s_dir: &str) -> Result<Self, E2eError> {
        info!("deploying Phase 1 resources");

        kubectl(&["apply", "-f", &format!("{k8s_dir}/configmap-phase1.yaml")])?;
        kubectl(&["apply", "-f", &format!("{k8s_dir}/bistouri-agent-pod.yaml")])?;
        kubectl(&["apply", "-f", &format!("{k8s_dir}/workloads.yaml")])?;

        info!("Phase 1 resources deployed");
        Ok(Self {
            k8s_dir: k8s_dir.to_string(),
        })
    }

    /// Hot-reload: replace the ConfigMap with Phase 2 config (drops the
    /// "hot" resource per workload). `kubectl apply` handles the update.
    pub(crate) fn apply_phase2_config(&self) -> Result<(), E2eError> {
        info!("applying Phase 2 config (hot-reload)");
        kubectl(&[
            "apply",
            "-f",
            &format!("{}/configmap-phase2.yaml", self.k8s_dir),
        ])?;

        info!("Phase 2 config applied");
        Ok(())
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
