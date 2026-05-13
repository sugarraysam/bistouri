//! Filesystem-backed debuginfod client.
//!
//! Reads ELF artifacts directly from a local debuginfod cache directory
//! (typically a shared volume mounted from the debuginfod sidecar).
//!
//! Layout: `<cache_path>/<hex_build_id>/debuginfo|executable`
//!
//! ## Race condition safety
//!
//! This client is read-only. The debuginfod server (RW process) uses
//! atomic writes (`write` to temp → `rename(2)`), so we never see
//! partially written files. If a file is deleted while we hold an open
//! fd, the inode stays alive until we close it (POSIX guarantee).

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
    /// Creates a new filesystem client reading from the given cache directory.
    ///
    /// `cache_path` should be the root of the debuginfod cache,
    /// e.g. `/var/cache/debuginfod_client` or a shared volume mount.
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
                // Genuine I/O error (permissions, disk failure, etc.)
                // Log and return None to allow HTTP fallback rather than
                // failing the entire request.
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
