//! Debuginfod client trait and types.
//!
//! The debuginfod protocol is HTTP-based:
//! - `GET /buildid/<hex_build_id>/executable` → stripped ELF
//! - `GET /buildid/<hex_build_id>/debuginfo`  → DWARF debuginfo

pub mod http;

/// Artifact type to request from debuginfod.
#[derive(Debug, Clone, Copy)]
pub enum ArtifactKind {
    /// Stripped executable (has PT_LOAD segments, may have .symtab).
    Executable,
    /// Debug info companion (has DWARF sections, .symtab).
    Debuginfo,
}

impl ArtifactKind {
    /// URL path component for this artifact type.
    pub fn path_segment(&self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Debuginfo => "debuginfo",
        }
    }
}

/// Trait abstracting debuginfod access for testability.
///
/// Implementations may fetch from HTTP, local filesystem, or return
/// canned data in tests.
#[async_trait::async_trait]
pub trait DebuginfodClient: Send + Sync {
    /// Fetches an artifact by build ID. Returns the raw ELF bytes.
    ///
    /// Returns `Ok(None)` if the artifact is not available (HTTP 404).
    /// Returns `Err` for transient failures (network, timeout).
    async fn fetch(
        &self,
        build_id_hex: &str,
        kind: ArtifactKind,
    ) -> crate::error::Result<Option<Vec<u8>>>;
}
