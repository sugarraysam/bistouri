use crate::sys::cgroup::error::CgroupError;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub(crate) enum TriggerError {
    #[error("Failed to resolve cgroup for pid {pid}: {source}")]
    CgroupResolve {
        pid: u32,
        #[source]
        source: CgroupError,
    },

    #[error("Failed to build PSI file descriptor for cgroup {path:?}: {source}")]
    PsiFdBuild {
        path: PathBuf,
        #[source]
        source: presutaoru::PsiFdBuilderError,
    },

    #[error("Failed to register PSI fd with async reactor: {0}")]
    AsyncFd(#[source] std::io::Error),

    #[error("Proc walk task panicked: {0}")]
    ProcWalk(String),

    #[error("At least one target rule is required")]
    EmptyTargets,

    #[error("Comm string '{comm}' exceeds 15 characters kernel limit")]
    CommTooLong { comm: String },

    #[error("Threshold {threshold} for comm '{comm}' must be between 1 and 99 (inclusive)")]
    InvalidThreshold { threshold: u8, comm: String },

    #[error("Failed to parse config: {0}")]
    ConfigParse(#[source] serde_yml::Error),

    #[error("Failed to read config file: {0}")]
    ConfigIo(#[source] std::io::Error),

    #[error("BPF comm_lpm_trie update failed: {0}")]
    BpfTrieUpdate(#[source] libbpf_rs::Error),

    #[error("Config watcher setup failed: {0}")]
    ConfigWatcher(#[source] std::io::Error),
}

pub(crate) type Result<T> = std::result::Result<T, TriggerError>;
