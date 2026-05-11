use std::sync::Arc;

use tracing::info;

use super::kernel::KernelMeta;
use crate::telemetry::hex_encode;

/// Runs startup validation checks and collects host metadata.
pub(crate) async fn run_preflight_checks() -> anyhow::Result<Arc<KernelMeta>> {
    let kernel_meta = tokio::task::spawn_blocking(KernelMeta::collect)
        .await
        .map_err(|e| anyhow::anyhow!("preflight task panicked: {e}"))??;

    info!(
        kernel_release = %kernel_meta.release,
        kaslr_offset = format_args!("{:#x}", kernel_meta.kaslr_offset),
        build_id = format_args!("{}", hex_encode(&kernel_meta.build_id)),
        "kernel metadata collected",
    );

    Ok(Arc::new(kernel_meta))
}
