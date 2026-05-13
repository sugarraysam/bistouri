//! Tiered debuginfod client — composes two `DebuginfodClient` implementations.
//!
//! Tries the primary source first (typically filesystem), falls back to the
//! secondary (typically HTTP) on miss. This is the "russian doll" pattern:
//! each layer is a standalone `DebuginfodClient`, and the tiered wrapper
//! combines them into a single unified client.

use tracing::debug;

use super::{ArtifactKind, DebuginfodClient};
use crate::error::Result;

/// Composes two `DebuginfodClient` implementations into a tiered lookup.
///
/// Tries `primary` first. If it returns `Ok(None)` (miss) or `Err` (transient),
/// falls back to `fallback`. Both are generic — any two `DebuginfodClient`
/// impls can be composed.
///
/// # Example
///
/// ```ignore
/// let fs = FilesystemDebuginfodClient::new(cache_path);
/// let http = HttpDebuginfodClient::new(url)?;
/// let client = TieredDebuginfodClient::new(fs, http);
/// ```
pub struct TieredDebuginfodClient<P, F> {
    primary: P,
    fallback: F,
}

impl<P: DebuginfodClient, F: DebuginfodClient> TieredDebuginfodClient<P, F> {
    /// Creates a new tiered client.
    ///
    /// `primary` is tried first (e.g. filesystem cache).
    /// `fallback` is tried on miss (e.g. HTTP debuginfod server).
    pub fn new(primary: P, fallback: F) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait::async_trait]
impl<P: DebuginfodClient, F: DebuginfodClient> DebuginfodClient for TieredDebuginfodClient<P, F> {
    async fn fetch(&self, build_id_hex: &str, kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
        // Try primary first.
        match self.primary.fetch(build_id_hex, kind).await {
            Ok(Some(bytes)) => return Ok(Some(bytes)),
            Ok(None) => {
                debug!(
                    build_id = build_id_hex,
                    "tiered: primary miss, trying fallback"
                );
            }
            Err(e) => {
                debug!(
                    build_id = build_id_hex,
                    error = %e,
                    "tiered: primary error, trying fallback"
                );
            }
        }

        // Fall back to secondary.
        self.fallback.fetch(build_id_hex, kind).await
    }
}
