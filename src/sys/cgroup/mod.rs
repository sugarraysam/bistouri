pub(crate) mod error;

use error::{CgroupError, Result};
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug)]
pub(crate) struct CgroupCache {
    mount_point: PathBuf,
    // We maintain a bidirectional cache because when a cgroup is deleted or moved,
    // the inotify event only provides the relative directory name, and the underlying
    // file system node is already gone. Therefore, we cannot call `fs::metadata()` to
    // find its inode. The `path_to_id` map allows us to resolve the deleted path back
    // to the inode ID so we can clean up the primary `id_to_path` map efficiently.
    id_to_path: HashMap<u64, PathBuf>,
    path_to_id: HashMap<PathBuf, u64>,
}

impl CgroupCache {
    pub(crate) fn new() -> Result<Self> {
        let mount_point = Self::find_cgroup2_mount()?;
        Ok(Self {
            mount_point,
            id_to_path: HashMap::new(),
            path_to_id: HashMap::new(),
        })
    }

    fn find_cgroup2_mount() -> Result<PathBuf> {
        let mounts = fs::read_to_string("/proc/mounts")
            .map_err(|e| CgroupError::Io("Failed to read /proc/mounts".into(), e))?;
        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 && parts[2] == "cgroup2" {
                return Ok(PathBuf::from(parts[1]));
            }
        }
        Err(CgroupError::NotMounted)
    }

    pub(crate) fn mount_point(&self) -> &Path {
        &self.mount_point
    }

    pub(crate) fn insert(&mut self, id: u64, path: PathBuf) {
        self.id_to_path.insert(id, path.clone());
        self.path_to_id.insert(path, id);
    }

    pub(crate) fn remove_by_path(&mut self, path: &Path) {
        if let Some(id) = self.path_to_id.remove(path) {
            self.id_to_path.remove(&id);
        }
    }

    fn initial_walk(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.mount_point) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    if let Ok(meta) = fs::metadata(&path) {
                        self.insert(meta.ino(), path);
                    }
                }
            }
        }
    }

    fn handle_inotify_event(&mut self, event: inotify::Event<std::ffi::OsString>) {
        if let Some(name) = event.name {
            let mut full_path = self.mount_point.clone();
            full_path.push(name);

            if event.mask.contains(inotify::EventMask::CREATE)
                || event.mask.contains(inotify::EventMask::MOVED_TO)
            {
                if let Ok(meta) = fs::metadata(&full_path) {
                    self.insert(meta.ino(), full_path);
                }
            } else if event.mask.contains(inotify::EventMask::DELETE)
                || event.mask.contains(inotify::EventMask::MOVED_FROM)
            {
                self.remove_by_path(&full_path);
            }
        }
    }
}

pub(crate) type SharedCgroupCache = Arc<RwLock<CgroupCache>>;

pub(crate) async fn cgroup_watcher_task(cache: SharedCgroupCache) -> Result<()> {
    let inotify =
        Inotify::init().map_err(|e| CgroupError::Io("Failed to initialize inotify".into(), e))?;

    inotify
        .watches()
        .add(
            cache.read().unwrap().mount_point(),
            WatchMask::CREATE | WatchMask::DELETE | WatchMask::MOVED_TO | WatchMask::MOVED_FROM,
        )
        .map_err(|e| CgroupError::Io("Failed to add inotify watch".into(), e))?;

    // Initial walk after watch is added
    cache.write().unwrap().initial_walk();

    let mut buffer = [0; 1024];
    let mut stream = inotify
        .into_event_stream(&mut buffer)
        .map_err(|e| CgroupError::Io("Failed to create inotify stream".into(), e))?;

    while let Some(event_or_error) = stream.next().await {
        let event =
            event_or_error.map_err(|e| CgroupError::Io("Inotify stream error".into(), e))?;
        cache.write().unwrap().handle_inotify_event(event);
    }

    Ok(())
}
