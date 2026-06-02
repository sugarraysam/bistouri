use bistouri_api::validate::ConfigValidationError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum TriggerError {
    #[error(transparent)]
    ConfigValidation(#[from] ConfigValidationError),

    #[error("Failed to build PSI file descriptor for cgroup {path:?}: {source}")]
    PsiFdBuild {
        path: PathBuf,
        #[source]
        source: presutaoru::PsiFdBuilderError,
    },

    #[error("Failed to register PSI fd with async reactor: {0}")]
    AsyncFd(#[source] std::io::Error),

    #[error("Failed to parse config: {0}")]
    ConfigParse(#[source] serde_yml::Error),

    #[error("Failed to read config file: {0}")]
    ConfigIo(#[source] std::io::Error),

    #[error("BPF comm_lpm_trie update failed: {0}")]
    BpfTrieUpdate(#[source] libbpf_rs::Error),

    #[error("Config watcher setup failed: {0}")]
    ConfigWatcher(#[source] std::io::Error),

    #[error("cgroup2 is not mounted: {0}")]
    Cgroup2NotMounted(#[source] std::io::Error),

    #[error("failed to register signal handler: {0}")]
    SignalRegistration(#[source] std::io::Error),

    #[error("failed to build kube client: {0}")]
    KubeClient(#[source] kube::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TriggerError>;
