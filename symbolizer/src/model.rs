/// Resolved symbol information for a single stack frame.
#[derive(Debug, Clone)]
pub(crate) struct SymbolInfo {
    /// Demangled function name, or a placeholder like `[unknown]`.
    pub(crate) function: String,
    /// Source file path (if DWARF info available).
    pub(crate) file: Option<String>,
    /// Source line number (if DWARF info available).
    pub(crate) line: Option<u32>,
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
pub(crate) enum ResolvedFrame {
    Symbolized(SymbolInfo),
    /// Inlined frames expanded from a single address.
    Inlined(Vec<SymbolInfo>),
}

/// A fully resolved stack trace (kernel + user frames symbolized).
#[derive(Debug)]
pub(crate) struct ResolvedTrace {
    pub(crate) kernel_frames: Vec<ResolvedFrame>,
    pub(crate) user_frames: Vec<ResolvedFrame>,
    pub(crate) on_cpu_count: u64,
    pub(crate) off_cpu_count: u64,
}

/// A fully resolved session, ready for downstream storage.
#[derive(Debug)]
pub(crate) struct ResolvedSession {
    pub(crate) session_id: String,
    pub(crate) pid: u32,
    pub(crate) comm: String,
    pub(crate) kernel_release: String,
    pub(crate) traces: Vec<ResolvedTrace>,
    pub(crate) total_samples: u64,
}
