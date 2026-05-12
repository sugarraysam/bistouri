use thiserror::Error;

/// Errors originating from the symbolizer service.
#[derive(Error, Debug)]
pub(crate) enum SymbolizerError {
    #[error("debuginfod fetch failed for build_id {build_id}: {source}")]
    DebuginfodFetch {
        build_id: String,
        #[source]
        source: reqwest::Error,
    },

    #[error("ELF parse failed for build_id {build_id}: {reason}")]
    ElfParse { build_id: String, reason: String },

    #[error("no PT_LOAD segment contains file_offset {file_offset:#x} in build_id {build_id}")]
    SegmentNotFound { build_id: String, file_offset: u64 },

    #[allow(dead_code)]
    #[error("DWARF symbolization failed: {0}")]
    Dwarf(String),

    #[error("debuginfod returned HTTP {status} for build_id {build_id}")]
    DebuginfodNotFound { build_id: String, status: u16 },

    #[error("gRPC transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
}

/// Result alias for the symbolizer crate.
pub(crate) type Result<T> = std::result::Result<T, SymbolizerError>;
