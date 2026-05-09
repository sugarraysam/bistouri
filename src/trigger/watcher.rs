use crate::trigger::config::TriggerConfig;
use crate::trigger::error::{Result, TriggerError};
use crate::trigger::TriggerControl;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const DEBOUNCE_MS: u64 = 200;

/// Watches the config file's parent directory using epoll-backed inotify.
///
/// Runs entirely on the Tokio event loop without spawning background OS threads.
/// Natively catches direct file edits and Kubernetes ConfigMap symlink swaps.
pub(crate) async fn config_watcher_task(
    config_path: PathBuf,
    control_tx: mpsc::Sender<TriggerControl>,
) -> Result<()> {
    let parent_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    // 1. Setup inotify and create directory
    std::fs::create_dir_all(&parent_dir).map_err(TriggerError::ConfigWatcher)?;
    let inotify = Inotify::init().map_err(TriggerError::ConfigWatcher)?;

    inotify
        .watches()
        .add(
            &parent_dir,
            WatchMask::CREATE
                | WatchMask::MOVED_TO
                | WatchMask::CLOSE_WRITE
                | WatchMask::DELETE
                | WatchMask::MODIFY,
        )
        .map_err(TriggerError::ConfigWatcher)?;

    let mut buffer = [0; 1024];
    let mut stream = inotify
        .into_event_stream(&mut buffer)
        .map_err(TriggerError::ConfigWatcher)?;

    let mut last_hash = content_hash(&config_path);

    // 2. Zero-allocation debounce timer. We start it sleeping "forever".
    let sleep = tokio::time::sleep(Duration::MAX);
    tokio::pin!(sleep);
    let mut debounce_active = false;

    loop {
        tokio::select! {
            // Wait for native inotify events via the async stream
            event = stream.next() => {
                match event {
                    Some(Ok(_ev)) => {
                        // Any file change in the parent directory triggers the debounce.
                        // We don't parse filenames because the hash check handles false positives.
                        debug!("inotify event detected, starting/resetting debounce");
                        sleep.as_mut().reset(tokio::time::Instant::now() + Duration::from_millis(DEBOUNCE_MS));
                        debounce_active = true;
                    }
                    Some(Err(e)) => {
                        error!(error = %e, "inotify stream error on config watcher");
                        break;
                    }
                    None => break,
                }
            }

            // The debounce timer fires
            _ = &mut sleep, if debounce_active => {
                debounce_active = false;

                // When the directory activity settles, check our target file
                let current_hash = content_hash(&config_path);

                // Ignore hash of 0 (file missing during hard swap) or unchanged hash (metadata noise)
                if current_hash != last_hash && current_hash != 0 {
                    debug!("config watcher: file content change verified");
                    last_hash = current_hash;
                    trigger_reload(&config_path, &control_tx).await;
                }
            }
        }
    }

    Ok(())
}

/// Returns a simple hash of the file contents for change detection.
/// Falls back to 0 on read error (file not yet present).
fn content_hash(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let Ok(contents) = std::fs::read(path) else {
        return 0;
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    contents.hash(&mut hasher);
    hasher.finish()
}

/// Parses the config file in `spawn_blocking` and sends a reload message.
async fn trigger_reload(config_path: &Path, control_tx: &mpsc::Sender<TriggerControl>) {
    let path = config_path.to_path_buf();
    match tokio::task::spawn_blocking(move || {
        TriggerConfig::load_from_file(path.to_str().unwrap_or_default())
    })
    .await
    {
        Ok(Ok(config)) => {
            info!("config file changed, reloading");
            let _ = control_tx
                .send(TriggerControl::Reload(Arc::new(config)))
                .await;
        }
        Ok(Err(e)) => {
            // Non-fatal: keep current config. The file may be mid-write
            // or contain invalid YAML — eventual consistency applies.
            warn!(error = %e, "config reload failed, keeping current config");
        }
        Err(e) => {
            error!(error = %e, "config parse task panicked");
        }
    }
}
