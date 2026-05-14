//! Filesystem-backed debuginfod client.
//!
//! Reads ELF artifacts directly from a local debuginfod cache directory
//! (typically a shared volume mounted from the debuginfod sidecar).
//!
//! Layout: `<cache_path>/<hex_build_id>/debuginfo|executable`

use std::path::PathBuf;

use tracing::debug;

use super::{ArtifactKind, DebuginfodClient};
use crate::error::Result;

/// Debuginfod client that reads artifacts from a local filesystem cache.
///
/// Designed to be composed with `HttpDebuginfodClient` via `TieredDebuginfodClient`
/// for a filesystem-first, HTTP-fallback strategy.
pub struct FilesystemDebuginfodClient {
    cache_path: PathBuf,
}

impl FilesystemDebuginfodClient {
    pub fn new(cache_path: PathBuf) -> Self {
        Self { cache_path }
    }

    /// Constructs the expected filesystem path for an artifact.
    fn artifact_path(&self, build_id_hex: &str, kind: ArtifactKind) -> PathBuf {
        self.cache_path.join(build_id_hex).join(kind.path_segment())
    }
}

#[async_trait::async_trait]
impl DebuginfodClient for FilesystemDebuginfodClient {
    async fn fetch(&self, build_id_hex: &str, kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
        let path = self.artifact_path(build_id_hex, kind);

        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                debug!(
                    build_id = build_id_hex,
                    path = %path.display(),
                    size_bytes = bytes.len(),
                    "filesystem: artifact read from cache"
                );
                Ok(Some(bytes))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(
                    build_id = build_id_hex,
                    path = %path.display(),
                    "filesystem: artifact not found"
                );
                Ok(None)
            }
            Err(e) => {
                // Genuine I/O error — log and return None for HTTP fallback.
                tracing::warn!(
                    build_id = build_id_hex,
                    path = %path.display(),
                    error = %e,
                    "filesystem: I/O error reading artifact, falling back"
                );
                Ok(None)
            }
        }
    }
}
