use thiserror::Error;

use crate::trigger::config::PsiResource;

#[derive(Error, Debug)]
pub(crate) enum CaptureError {
    #[error("Failed to add pid {pid} to BPF filter: {source}")]
    PidFilterAdd {
        pid: u32,
        #[source]
        source: libbpf_rs::Error,
    },

    #[error("Failed to remove pid {pid} from BPF filter: {source}")]
    PidFilterRemove {
        pid: u32,
        #[source]
        source: libbpf_rs::Error,
    },

    #[error("Duplicate inflight session for pid {pid}, resource {resource:?}")]
    DuplicateSession { pid: u32, resource: PsiResource },

    #[error("Failed to send completed session downstream")]
    SinkSend,
}

pub(crate) type Result<T> = std::result::Result<T, CaptureError>;
