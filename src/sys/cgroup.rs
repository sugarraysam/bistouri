use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Discovers the cgroup2 mount point by parsing `<host_proc>/mounts`.
/// Called once at startup — the mount point is stable for the lifetime
/// of the process.
///
/// `host_proc` should point to the host's procfs mount (e.g. `/host/proc`
/// in container deployments, or `/proc` on baremetal).
pub(crate) fn find_cgroup2_mount(host_proc: &Path) -> io::Result<PathBuf> {
    let mounts_path = host_proc.join("mounts");
    let mounts = fs::read_to_string(&mounts_path)?;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[2] == "cgroup2" {
            return Ok(PathBuf::from(parts[1]));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "cgroup2 is not mounted on this system",
    ))
}

/// Resolves the cgroup filesystem path for a given PID by reading
/// `<host_proc>/<pid>/cgroup`.
///
/// Reading from the host's procfs mount (rather than the container's
/// `/proc`) eliminates cgroup namespace escapes — the kernel returns
/// absolute paths from the host's perspective. This makes resolution
/// a simple O(1) string join.
///
/// Returns the full path under the cgroup2 mount (e.g.
/// `/sys/fs/cgroup/kubepods.slice/…/cri-containerd-abc123.scope`).
pub(crate) fn resolve_cgroup_path(
    cgroup_mount: &Path,
    host_proc: &Path,
    pid: u32,
) -> io::Result<PathBuf> {
    let cgroup_file = host_proc.join(format!("{}/cgroup", pid));
    let contents = fs::read_to_string(&cgroup_file)?;

    for line in contents.lines() {
        if let Some(rel_path) = line.strip_prefix("0::") {
            let candidate = cgroup_mount.join(rel_path.trim_start_matches('/'));
            if candidate.is_dir() {
                return Ok(candidate);
            }
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("no cgroup2 entry found in {}", cgroup_file.display()),
    ))
}

/// Derives the cgroup ID from `stat()` on the cgroup directory path.
/// This matches `bpf_get_current_cgroup_id()` which returns the inode number
/// of the cgroup v2 directory. Returns 0 on stat failure — callers use this
/// as a dedup key, so a zero ID simply means no dedup (the PSI fd open will
/// fail independently if the path is gone).
pub(crate) fn cgroup_path_to_id(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
}
