use thiserror::Error;

#[derive(Error, Debug)]
pub(crate) enum CgroupError {
    #[error("System I/O error: {0}")]
    Io(String, #[source] std::io::Error),

    #[error("cgroup2 is not mounted on this system")]
    NotMounted,
}

pub(crate) type Result<T> = std::result::Result<T, CgroupError>;
