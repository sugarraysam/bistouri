use std::sync::Arc;

use tracing::info;

use super::kernel::KernelMeta;

/// Runs startup validation checks and collects host metadata.
///
/// Designed to grow as we add more startup assertions (kernel version
/// compatibility, capability checks, cgroup2 mount validation, etc.).
///
/// Performs synchronous file I/O internally — wrapped in
/// `spawn_blocking` to keep the event loop clean.
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

/// Formats a byte slice as a lowercase hex string (e.g. "ab01cd...").
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
