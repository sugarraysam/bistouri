use crate::trigger::config::TriggerConfig;
use crate::trigger::TriggerControl;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Sleep;

const DEBOUNCE_MS: u64 = 200;

/// Watches the config file's parent directory for changes and sends
/// `TriggerControl::Reload` messages on the control channel.
///
/// Watches the parent directory (not the file itself) to handle editor
/// rename dances (vim, sed -i, kubectl) and the "file doesn't exist yet" case.
/// Debounces rapid events (e.g., vim DELETE + MOVED_TO) with a 200ms window.
///
/// Events for unrelated files in the same directory are discarded via an
/// O(1) filename check. This assumes the config directory (e.g., `/etc/bistouri/`)
/// is a quiet, dedicated path — not a high-churn location like `/tmp/`.
pub(crate) async fn config_watcher_task(
    config_path: PathBuf,
    control_tx: mpsc::Sender<TriggerControl>,
) {
    let parent_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let filename = match config_path.file_name() {
        Some(name) => name.to_os_string(),
        None => {
            eprintln!("Config path has no filename: {:?}", config_path);
            return;
        }
    };

    let inotify = match Inotify::init() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("Failed to initialize inotify for config watcher: {}", e);
            return;
        }
    };

    if let Err(e) = std::fs::create_dir_all(&parent_dir) {
        eprintln!("Failed to create config directory {:?}: {}", parent_dir, e);
        return;
    }

    if let Err(e) = inotify.watches().add(
        &parent_dir,
        WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE,
    ) {
        eprintln!("Failed to add inotify watch on {:?}: {}", parent_dir, e);
        return;
    }

    let mut buffer = [0; 1024];
    let mut stream = match inotify.into_event_stream(&mut buffer) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to create inotify event stream: {}", e);
            return;
        }
    };

    let mut debounce: Option<Pin<Box<Sleep>>> = None;

    loop {
        tokio::select! {
            event = stream.next() => {
                match event {
                    Some(Ok(ev)) => {
                        if ev.name.as_deref() == Some(&filename) {
                            debounce = Some(Box::pin(tokio::time::sleep(
                                Duration::from_millis(DEBOUNCE_MS),
                            )));
                        }
                    }
                    Some(Err(e)) => {
                        eprintln!("inotify error on config watcher: {}", e);
                        break;
                    }
                    None => break,
                }
            }
            _ = async { debounce.as_mut().unwrap().await }, if debounce.is_some() => {
                debounce = None;
                trigger_reload(&config_path, &control_tx).await;
            }
        }
    }
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
            println!("Config file changed, reloading...");
            let _ = control_tx
                .send(TriggerControl::Reload(Arc::new(config)))
                .await;
        }
        Ok(Err(e)) => {
            // Non-fatal: keep current config. The file may be mid-write
            // or contain invalid YAML — eventual consistency applies.
            eprintln!("Config reload failed: {} — keeping current config", e);
        }
        Err(e) => {
            eprintln!("Config parse task panicked: {}", e);
        }
    }
}
