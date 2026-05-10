use crate::error::E2eError;
use std::process::Command;
use tracing::info;

/// Manages Kubernetes resources for a single E2E test run.
///
/// Uses `kubectl apply/delete` directly — no kube-rs client, no YAML
/// deserialization, no trait bounds. The manifests on disk are the
/// source of truth.
///
/// Deployment order in Phase 1:
///   1. CRD             — installs the BistouriConfig schema
///   2. RBAC            — ClusterRole + ClusterRoleBinding for CR watching
///   3. ServiceAccount  — identity the agent pod runs as
///   4. BistouriConfig  — Phase 1 CR (validated by the CRD schema)
///   5. Agent pod       — reads the CR via kube::runtime::watcher (no ConfigMap)
///   6. Workloads       — stress processes that trigger PSI events
///
/// Phase 2 hot-reload applies only a new BistouriConfig CR; the agent's kube
/// watch fires automatically with no ConfigMap required.
///
/// On drop, deletes all applied resources. The shell wrapper provides
/// the ultimate safety net if this process is killed.
pub(crate) struct E2eCluster {
    k8s_dir: String,
}

impl E2eCluster {
    /// Apply Phase 1 resources and return the cluster handle for Phase 2 and cleanup.
    pub(crate) fn deploy_phase1(k8s_dir: &str) -> Result<Self, E2eError> {
        info!("deploying Phase 1 resources");

        let crd_dir = {
            let manifest_dir =
                std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
            format!("{manifest_dir}/../deployment/crd")
        };

        // 1. Install the BistouriConfig CRD schema. Must happen before any CR is applied.
        info!("applying BistouriConfig CRD");
        kubectl(&["apply", "-f", &crd_dir])?;

        // 2. RBAC — ClusterRole + ClusterRoleBinding so the agent SA can watch CRs.
        info!("applying RBAC");
        kubectl(&["apply", "-f", &format!("{k8s_dir}/clusterrole.yaml")])?;
        kubectl(&["apply", "-f", &format!("{k8s_dir}/clusterrolebinding.yaml")])?;

        // 3. ServiceAccount the agent pod runs as.
        info!("applying ServiceAccount");
        kubectl(&["apply", "-f", &format!("{k8s_dir}/serviceaccount.yaml")])?;

        // 4. Phase 1 BistouriConfig CR — validated against the CRD schema at apply time.
        info!("applying Phase 1 BistouriConfig CR");
        kubectl(&[
            "apply",
            "-f",
            &format!("{k8s_dir}/bistouriconfig-phase1.yaml"),
        ])?;

        // 5. Agent pod — uses kube::runtime::watcher to read the CR above.
        // No ConfigMap volume needed.
        info!("applying agent pod");
        kubectl(&["apply", "-f", &format!("{k8s_dir}/bistouri-agent-pod.yaml")])?;

        // 6. Stress workloads.
        kubectl(&["apply", "-f", &format!("{k8s_dir}/workloads.yaml")])?;

        info!("Phase 1 resources deployed");
        Ok(Self {
            k8s_dir: k8s_dir.to_string(),
        })
    }

    /// Hot-reload: apply the Phase 2 BistouriConfig CR.
    ///
    /// The agent's `kube::runtime::watcher` detects the CR update and sends a
    /// `TriggerControl::Reload` — no ConfigMap apply required.
    pub(crate) fn apply_phase2_config(&self) -> Result<(), E2eError> {
        info!("applying Phase 2 BistouriConfig CR (hot-reload)");
        kubectl(&[
            "apply",
            "-f",
            &format!("{}/bistouriconfig-phase2.yaml", self.k8s_dir),
        ])?;
        info!("Phase 2 CR applied — agent kube watch will trigger reload");
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
