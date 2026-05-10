use thiserror::Error;

#[derive(Error, Debug)]
pub enum AgentError {
    #[error("eBPF operation failed: {0}")]
    Bpf(String, #[source] libbpf_rs::Error),

    #[error("Perf event operation failed: {0}")]
    PerfEvent(String, #[source] std::io::Error),

    #[error("System I/O error: {0}")]
    Io(String, #[source] std::io::Error),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, AgentError>;
