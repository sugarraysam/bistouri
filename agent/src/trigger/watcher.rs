use crate::args::{Args, ConfigSource, KUBE_SA_NAMESPACE_PATH};
use crate::telemetry::METRIC_CONFIG_LOAD_FAILURES;
use crate::trigger::config::TriggerConfig;
use crate::trigger::error::{Result, TriggerError};
use crate::trigger::TriggerControl;
use async_trait::async_trait;
use bistouri_api::cr::{BistouriConfig, BistouriConfigSpec};
use futures::StreamExt;
use inotify::{Inotify, WatchMask};
use kube::runtime::{watcher, WatchStreamExt};
use kube::{Api, Client, ResourceExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// ---------------------------------------------------------------------------
// ConfigWatcher trait
// ---------------------------------------------------------------------------

/// Common interface for config delivery strategies.
///
/// Exactly one implementation is chosen at startup via `--config-source`.
#[async_trait]
pub(crate) trait ConfigWatcher: Send + 'static {
    /// Load and return the initial configuration.
    async fn load_initial(&mut self) -> Arc<TriggerConfig>;

    /// Run the watch loop until `cancel` fires.
    async fn watch(
        self: Box<Self>,
        control_tx: mpsc::Sender<TriggerControl>,
        cancel: CancellationToken,
    );
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Resolve args into the concrete [`ConfigWatcher`].
pub(crate) async fn build_watcher(args: &Args) -> Box<dyn ConfigWatcher> {
    let resolved = match args.config_source {
        ConfigSource::File => ConfigSource::File,
        ConfigSource::Kube => ConfigSource::Kube,
        ConfigSource::Auto => {
            if std::path::Path::new(KUBE_SA_NAMESPACE_PATH).exists() {
                info!("in-cluster namespace file found — using kube CR watch mode");
                ConfigSource::Kube
            } else {
                info!("no in-cluster namespace file — using file watch mode");
                ConfigSource::File
            }
        }
    };

    match resolved {
        ConfigSource::Kube => {
            let client = Client::try_default()
                .await
                .expect("failed to build kube client — is the pod running with a ServiceAccount?");

            let namespace = std::fs::read_to_string(KUBE_SA_NAMESPACE_PATH)
                .map(|s| s.trim().to_owned())
                .unwrap_or_else(|_| "default".to_owned());

            info!(
                namespace = %namespace,
                cr_name   = %args.cr_name,
                "kube CR watch mode selected",
            );

            Box::new(KubeConfigWatcher {
                client,
                namespace,
                cr_name: args.cr_name.clone(),
                last_spec_hash: 0,
            })
        }
        ConfigSource::File | ConfigSource::Auto => {
            info!(path = %args.config.display(), "file watch mode selected");
            Box::new(FileConfigWatcher {
                path: args.config.clone(),
            })
        }
    }
}

// ---------------------------------------------------------------------------
// FileConfigWatcher
// ---------------------------------------------------------------------------

/// Watches a YAML file via inotify for hot-reload.
pub(crate) struct FileConfigWatcher {
    path: PathBuf,
}

#[async_trait]
impl ConfigWatcher for FileConfigWatcher {
    async fn load_initial(&mut self) -> Arc<TriggerConfig> {
        let path = self.path.clone();
        match tokio::task::spawn_blocking(move || {
            TriggerConfig::load_from_file(path.to_str().unwrap_or_default())
        })
        .await
        {
            Ok(Ok(config)) => {
                let comms: Vec<&str> = config.targets.iter().map(|t| t.rule.comm()).collect();
                info!(
                    target_count = config.targets.len(),
                    ?comms,
                    "loaded trigger config",
                );
                Arc::new(config)
            }
            Ok(Err(e)) => {
                warn!(error = %e, "failed to load config, using default");
                metrics::counter!(METRIC_CONFIG_LOAD_FAILURES).increment(1);
                Arc::new(TriggerConfig::default_config())
            }
            Err(e) => {
                error!(error = %e, "config load task panicked, using default");
                metrics::counter!(METRIC_CONFIG_LOAD_FAILURES).increment(1);
                Arc::new(TriggerConfig::default_config())
            }
        }
    }

    async fn watch(
        self: Box<Self>,
        control_tx: mpsc::Sender<TriggerControl>,
        cancel: CancellationToken,
    ) {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {},
            result = file_watch_loop(&self.path, &control_tx) => {
                if let Err(e) = result {
                    error!(error = %e, "file config watcher failed");
                }
            }
        }
    }
}

const DEBOUNCE_MS: u64 = 200;

/// Inner inotify loop — extracted so the select! above stays clean.
async fn file_watch_loop(
    config_path: &Path,
    control_tx: &mpsc::Sender<TriggerControl>,
) -> Result<()> {
    let parent_dir = config_path.parent().unwrap_or(Path::new(".")).to_path_buf();

    std::fs::create_dir_all(&parent_dir).map_err(TriggerError::ConfigWatcher)?;
    let inotify = Inotify::init().map_err(TriggerError::ConfigWatcher)?;
    inotify
        .watches()
        .add(
            &parent_dir,
            // MOVED_TO catches k8s ConfigMap symlink rewrite.
            // CLOSE_WRITE and MODIFY catch standard file edits.
            WatchMask::MOVED_TO | WatchMask::CLOSE_WRITE | WatchMask::MODIFY,
        )
        .map_err(TriggerError::ConfigWatcher)?;

    let mut buffer = [0; 1024];
    let mut stream = inotify
        .into_event_stream(&mut buffer)
        .map_err(TriggerError::ConfigWatcher)?;

    let mut last_hash = content_hash(config_path);

    // Zero-allocation debounce timer, starts sleeping forever.
    let sleep = tokio::time::sleep(Duration::MAX);
    tokio::pin!(sleep);
    let mut debounce_active = false;

    loop {
        tokio::select! {
            event = stream.next() => match event {
                Some(Ok(_)) => {
                    debug!("inotify event — starting debounce");
                    sleep.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(DEBOUNCE_MS)
                    );
                    debounce_active = true;
                }
                Some(Err(e)) => {
                    error!(error = %e, "inotify stream error");
                    break;
                }
                None => break,
            },

            _ = &mut sleep, if debounce_active => {
                debounce_active = false;
                let current_hash = content_hash(config_path);

                if current_hash == 0 {
                    // File mid-swap — re-arm debounce.
                    debug!("config file unreadable mid-swap, re-arming debounce");
                    sleep.as_mut().reset(
                        tokio::time::Instant::now() + Duration::from_millis(DEBOUNCE_MS)
                    );
                    debounce_active = true;
                    continue;
                }

                if current_hash != last_hash {
                    last_hash = current_hash;
                    trigger_reload_from_file(config_path, control_tx).await;
                }
            }
        }
    }

    Ok(())
}

fn content_hash(path: &Path) -> u64 {
    use std::hash::{Hash, Hasher};
    let Ok(contents) = std::fs::read(path) else {
        return 0;
    };
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    contents.hash(&mut hasher);
    hasher.finish()
}

async fn trigger_reload_from_file(config_path: &Path, control_tx: &mpsc::Sender<TriggerControl>) {
    let path = config_path.to_path_buf();
    match tokio::task::spawn_blocking(move || {
        TriggerConfig::load_from_file(path.to_str().unwrap_or_default())
    })
    .await
    {
        Ok(Ok(config)) => {
            info!("config file changed — reloading");
            let _ = control_tx
                .send(TriggerControl::Reload(Arc::new(config)))
                .await;
        }
        Ok(Err(e)) => {
            // Non-fatal: keep current config. The file may be mid-write.
            warn!(error = %e, "config reload failed — keeping current config");
        }
        Err(e) => {
            error!(error = %e, "config parse task panicked");
        }
    }
}

// ---------------------------------------------------------------------------
// KubeConfigWatcher
// ---------------------------------------------------------------------------

/// Watches a `BistouriConfig` CR via the Kubernetes API for hot-reload.
///
/// Spec content hash deduplicates reloads: metadata-only updates are skipped.
pub(crate) struct KubeConfigWatcher {
    client: Client,
    namespace: String,
    cr_name: String,
    last_spec_hash: u64,
}

#[async_trait]
impl ConfigWatcher for KubeConfigWatcher {
    async fn load_initial(&mut self) -> Arc<TriggerConfig> {
        let api: Api<BistouriConfig> = Api::namespaced(self.client.clone(), &self.namespace);

        match api.get(&self.cr_name).await {
            Ok(cr) => {
                self.last_spec_hash = spec_content_hash(&cr.spec);
                match parse_cr(cr) {
                    Ok(config) => {
                        let comms: Vec<&str> =
                            config.targets.iter().map(|t| t.rule.comm()).collect();
                        info!(
                            target_count = config.targets.len(),
                            ?comms,
                            "loaded initial config from BistouriConfig CR",
                        );
                        Arc::new(config)
                    }
                    Err(e) => {
                        warn!(
                            error = %e,
                            cr_name = %self.cr_name,
                            "BistouriConfig CR failed validation — using default config",
                        );
                        Arc::new(TriggerConfig::default_config())
                    }
                }
            }
            Err(kube::Error::Api(err)) if err.code == 404 => {
                warn!(
                    cr_name = %self.cr_name,
                    namespace = %self.namespace,
                    "BistouriConfig CR not found — using default config until CR is applied",
                );
                Arc::new(TriggerConfig::default_config())
            }
            Err(e) => {
                warn!(error = %e, "failed to fetch BistouriConfig CR — using default config");
                Arc::new(TriggerConfig::default_config())
            }
        }
    }

    async fn watch(
        mut self: Box<Self>,
        control_tx: mpsc::Sender<TriggerControl>,
        cancel: CancellationToken,
    ) {
        let api: Api<BistouriConfig> = Api::namespaced(self.client.clone(), &self.namespace);
        let mut stream = watcher(api, watcher::Config::default())
            .default_backoff()
            .boxed();

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                event = stream.next() => match event {
                    // InitApply intentionally not handled: load_initial() already
                    // fetched the CR. Handling it would race with proc_walk.
                    Some(Ok(watcher::Event::Apply(cr))) if cr.name_any() == self.cr_name => {
                        let new_hash = spec_content_hash(&cr.spec);
                        if new_hash == self.last_spec_hash {
                            debug!(
                                cr_name = %self.cr_name,
                                "BistouriConfig CR applied with unchanged spec — skipping reload",
                            );
                            continue;
                        }
                        match parse_cr(cr) {
                            Ok(config) => {
                                self.last_spec_hash = new_hash;
                                info!(
                                    cr_name = %self.cr_name,
                                    "BistouriConfig CR spec changed — reloading",
                                );
                                let _ = control_tx
                                    .send(TriggerControl::Reload(Arc::new(config)))
                                    .await;
                            }
                            Err(e) => {
                                warn!(error = %e, cr_name = %self.cr_name, "CR validation failed, keeping current config");
                            }
                        }
                    }
                    Some(Ok(watcher::Event::Delete(cr))) if cr.name_any() == self.cr_name => {
                        warn!(cr_name = %self.cr_name, "BistouriConfig CR deleted, keeping current config");
                    }
                    Some(Ok(_)) => {} // Other CR names, Init, InitApply events — ignore.
                    Some(Err(e)) => {
                        warn!(error = %e, "kube watch error — will reconnect");
                    }
                    None => break,
                }
            }
        }
    }
}

/// Parse a `BistouriConfig` CR into a validated `TriggerConfig`.
fn parse_cr(cr: BistouriConfig) -> crate::trigger::error::Result<TriggerConfig> {
    let targets = cr
        .spec
        .targets
        .into_iter()
        .map(bistouri_api::config::TargetConfig::from)
        .collect();
    TriggerConfig::try_new(targets)
}

/// Compute a content hash of the BistouriConfig spec.
/// Uses `Debug` repr → `DefaultHasher` for deterministic, metadata-independent hashing.
fn spec_content_hash(spec: &BistouriConfigSpec) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    format!("{spec:?}").hash(&mut hasher);
    hasher.finish()
}
