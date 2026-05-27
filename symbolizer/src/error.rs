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

    #[error("debuginfod server error for build_id {build_id}: {reason}")]
    DebuginfodServerError { build_id: String, reason: String },
}

/// Result alias for the symbolizer crate.
pub type Result<T> = std::result::Result<T, SymbolizerError>;

impl Clone for SymbolizerError {
    fn clone(&self) -> Self {
        match self {
            Self::HttpClientInit { source } => Self::DebuginfodServerError {
                build_id: String::new(),
                reason: format!("HTTP client initialization failed: {source}"),
            },
            Self::DebuginfodFetch { build_id, source } => Self::DebuginfodServerError {
                build_id: build_id.clone(),
                reason: source.to_string(),
            },
            Self::ElfParse { build_id, reason } => Self::ElfParse {
                build_id: build_id.clone(),
                reason: reason.clone(),
            },
            Self::SegmentNotFound {
                build_id,
                file_offset,
            } => Self::SegmentNotFound {
                build_id: build_id.clone(),
                file_offset: *file_offset,
            },
            Self::DebuginfodNotFound { build_id, status } => Self::DebuginfodNotFound {
                build_id: build_id.clone(),
                status: *status,
            },
            Self::DebuginfodServerError { build_id, reason } => Self::DebuginfodServerError {
                build_id: build_id.clone(),
                reason: reason.clone(),
            },
        }
    }
}
