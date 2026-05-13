use crate::error::E2eError;
use std::time::Duration;
use tracing::{debug, info};

/// A single parsed scrape of Bistouri's `/metrics` endpoint.
///
/// Holds the full parse result so callers can query many counters without
/// making repeated HTTP requests.
pub(crate) struct MetricsSnapshot {
    scrape: prometheus_parse::Scrape,
}

impl MetricsSnapshot {
    /// Look up a counter by name, optionally filtering by a single label pair.
    /// Returns `0.0` when the metric is absent.
    pub(crate) fn counter(&self, name: &str, label: Option<(&str, &str)>) -> f64 {
        self.scrape
            .samples
            .iter()
            .find(|s| {
                s.metric == name
                    && label.is_none_or(|(k, v)| s.labels.get(k).is_some_and(|lv| lv == v))
            })
            .map_or(0.0, |s| match s.value {
                prometheus_parse::Value::Counter(v)
                | prometheus_parse::Value::Gauge(v)
                | prometheus_parse::Value::Untyped(v) => v,
                _ => 0.0,
            })
    }
}

/// Prometheus metrics client that polls Bistouri's `/metrics` endpoint.
pub(crate) struct MetricsClient {
    url: String,
    port: u16,
    client: reqwest::Client,
}

impl MetricsClient {
    pub(crate) fn new(port: u16) -> Self {
        Self {
            url: format!("http://localhost:{port}/metrics"),
            port,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .expect("reqwest client"),
        }
    }

    /// Block until the metrics endpoint returns 200.
    pub(crate) async fn wait_until_reachable(&self, timeout: Duration) -> Result<(), E2eError> {
        info!(port = self.port, "waiting for metrics endpoint");
        tokio::time::timeout(timeout, async {
            loop {
                match self.client.get(&self.url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        info!(port = self.port, "metrics endpoint reachable");
                        return;
                    }
                    Ok(resp) => debug!(status = %resp.status(), "metrics not ready yet"),
                    Err(e) => debug!(error = %e, "metrics connection failed"),
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        })
        .await
        .map_err(|_| E2eError::Timeout {
            what: format!("metrics endpoint on port {}", self.port),
            timeout,
        })
    }

    /// Fetch and parse the `/metrics` endpoint once, returning a snapshot for
    /// multi-counter assertions without repeated HTTP round-trips.
    pub(crate) async fn scrape(&self) -> Result<MetricsSnapshot, E2eError> {
        let body = self.client.get(&self.url).send().await?.text().await?;
        let lines = body.lines().map(|l| Ok(l.to_owned()));
        let scrape = prometheus_parse::Scrape::parse(lines)
            .map_err(|e| E2eError::MetricsParse(e.to_string()))?;
        Ok(MetricsSnapshot { scrape })
    }

    /// Poll until a counter exceeds `threshold`, or time out.
    ///
    /// Kept for Phase 2 (hot-reload) where we must wait for an event
    /// that hasn't happened yet. All Phase 1 assertions use `scrape()`
    /// instead — the gRPC sink guarantees the pipeline has already run.
    #[allow(dead_code)]
    pub(crate) async fn wait_for_counter_gt(
        &self,
        name: &str,
        label: Option<(&str, &str)>,
        threshold: f64,
        timeout: Duration,
    ) -> Result<f64, E2eError> {
        tokio::time::timeout(timeout, async {
            loop {
                let val = self
                    .scrape()
                    .await
                    .map(|s| s.counter(name, label))
                    .unwrap_or(0.0);
                if val > threshold {
                    return val;
                }
                debug!(metric = name, val, threshold, "polling");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        })
        .await
        .map_err(|_| E2eError::Timeout {
            what: format!("{name} > {threshold}"),
            timeout,
        })
    }
}
