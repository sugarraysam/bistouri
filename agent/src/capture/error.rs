use thiserror::Error;

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
}

pub(crate) type Result<T> = std::result::Result<T, CaptureError>;

#[derive(Debug, Error)]
pub(crate) enum ExportError {
    #[error("serialization failed: {0}")]
    Serialize(#[from] bincode::Error),

    #[error("gRPC call failed: {0}")]
    Grpc(#[from] tonic::Status),
}
