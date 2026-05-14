use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// ── Resource type constants ──────────────────────────────────────────────
// Used in CaptureSourceInfo and ClickHouse trigger_detail column.
// Defined as &'static str to avoid allocations on every session.

pub const RESOURCE_MEMORY: &str = "memory";
pub const RESOURCE_CPU: &str = "cpu";
pub const RESOURCE_IO: &str = "io";
pub const RESOURCE_UNKNOWN: &str = "unknown";

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

/// What triggered the capture.
#[derive(Debug, Clone)]
pub enum CaptureSourceInfo {
    Psi { resource: &'static str },
}

/// A fully resolved session, ready for downstream storage.
#[derive(Debug)]
pub struct ResolvedSession {
    pub tenant_id: String,
    pub service_id: String,
    pub session_id: String,
    pub capture_source: CaptureSourceInfo,
    pub labels: HashMap<String, String>,
    pub capture_start_time: SystemTime,
    pub capture_duration: Duration,
    pub kernel_release: String,
    pub traces: Vec<ResolvedTrace>,
    pub total_samples: u64,
    pub sample_period_nanos: u64,
}
