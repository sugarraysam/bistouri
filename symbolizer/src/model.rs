/// Resolved symbol information for a single stack frame.
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    /// Demangled function name, or a placeholder like `[unknown]`.
    pub function: String,
    /// Source file path (if DWARF info available).
    pub file: Option<String>,
    /// Source line number (if DWARF info available).
    pub line: Option<u32>,
}

impl SymbolInfo {
    pub(crate) fn unknown() -> Self {
        Self {
            function: "[unknown]".into(),
            file: None,
            line: None,
        }
    }

    pub(crate) fn unresolved_module() -> Self {
        Self {
            function: "[kernel module — unresolved]".into(),
            file: None,
            line: None,
        }
    }

    pub(crate) fn placeholder(label: &str) -> Self {
        Self {
            function: label.into(),
            file: None,
            line: None,
        }
    }
}

/// A fully resolved stack frame.
#[derive(Debug, Clone)]
pub enum ResolvedFrame {
    Symbolized(SymbolInfo),
    /// Inlined frames expanded from a single address.
    Inlined(Vec<SymbolInfo>),
}

/// A fully resolved stack trace (kernel + user frames symbolized).
#[derive(Debug)]
pub struct ResolvedTrace {
    pub kernel_frames: Vec<std::sync::Arc<ResolvedFrame>>,
    pub user_frames: Vec<std::sync::Arc<ResolvedFrame>>,
    pub on_cpu_count: u64,
    pub off_cpu_count: u64,
}

/// A fully resolved session, ready for downstream storage.
#[derive(Debug)]
pub struct ResolvedSession {
    pub session_id: String,
    pub pid: u32,
    pub comm: String,
    pub kernel_release: String,
    pub traces: Vec<ResolvedTrace>,
    pub total_samples: u64,
}
