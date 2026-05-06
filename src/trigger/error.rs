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
}

pub(crate) type Result<T> = std::result::Result<T, TriggerError>;
