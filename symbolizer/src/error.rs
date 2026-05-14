use thiserror::Error;

/// Errors originating from the symbolizer service.
#[derive(Error, Debug)]
pub enum SymbolizerError {
    #[error("HTTP client initialization failed: {source}")]
    HttpClientInit {
        #[source]
        source: reqwest::Error,
    },

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

    #[error("debuginfod returned HTTP {status} for build_id {build_id}")]
    DebuginfodNotFound { build_id: String, status: u16 },
}

/// Result alias for the symbolizer crate.
pub type Result<T> = std::result::Result<T, SymbolizerError>;
