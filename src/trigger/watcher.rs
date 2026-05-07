use crate::trigger::config::TriggerConfig;
use crate::trigger::error::{Result, TriggerError};
use crate::trigger::TriggerControl;
use futures_util::StreamExt;
use inotify::{Inotify, WatchMask};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Sleep;
use tracing::{error, info, warn};

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
///
/// Returns `Result` — inotify setup failures are fatal because config
/// hot-reload is an inherent part of the system.
pub(crate) async fn config_watcher_task(
    config_path: PathBuf,
    control_tx: mpsc::Sender<TriggerControl>,
) -> Result<()> {
    let parent_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let filename = config_path
        .file_name()
        .ok_or_else(|| {
            TriggerError::ConfigWatcher(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("config path has no filename: {:?}", config_path),
            ))
        })?
        .to_os_string();

    let inotify = Inotify::init().map_err(TriggerError::ConfigWatcher)?;

    std::fs::create_dir_all(&parent_dir).map_err(TriggerError::ConfigWatcher)?;

    inotify
        .watches()
        .add(
            &parent_dir,
            WatchMask::CREATE | WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE,
        )
        .map_err(TriggerError::ConfigWatcher)?;

    let mut buffer = [0; 1024];
    let mut stream = inotify
        .into_event_stream(&mut buffer)
        .map_err(TriggerError::ConfigWatcher)?;

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
                        error!(error = %e, "inotify stream error on config watcher");
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

    Ok(())
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
