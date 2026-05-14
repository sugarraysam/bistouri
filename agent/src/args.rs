use clap::builder::styling::{AnsiColor, Color, Style, Styles};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Which config delivery strategy to use.
///
/// `Auto` probes for the Kubernetes in-cluster service account token
/// (`/var/run/secrets/kubernetes.io/serviceaccount/token`). If present the
/// agent watches a `BistouriConfig` CR; if absent it falls back to a YAML file
/// watched via inotify. This makes both DaemonSet and baremetal (systemd)
/// deployments work with no explicit flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ConfigSource {
    /// Auto-detect: kube if in-cluster SA token exists, file otherwise.
    Auto,
    /// Watch a `BistouriConfig` CR via the Kubernetes API.
    Kube,
    /// Watch a YAML file on disk via inotify.
    File,
}

/// Default config file path when neither --config flag nor BISTOURI_CONFIG env is set.
const DEFAULT_CONFIG_PATH: &str = "/etc/bistouri/trigger.yaml";

/// Default BistouriConfig CR name watched in kube source mode.
const DEFAULT_CR_NAME: &str = "bistouri-config";

/// Path to the Kubernetes in-cluster namespace file.
///
/// This file is present in every pod that has a ServiceAccount mounted
/// (the default for all pods unless `automountServiceAccountToken: false`).
/// Its presence is used by `--config-source=auto` to detect an in-cluster
/// environment, and its content is read to determine the agent's namespace.
pub(crate) const KUBE_SA_NAMESPACE_PATH: &str =
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace";

/// Bistouri — lightweight eBPF profiling agent triggered by Linux PSI events.
///
/// Captures stack traces from processes experiencing memory, CPU, or IO pressure.
/// Runs on a minimal thread budget by default (1 async IO thread + 1 blocking thread)
/// and scales via --io-threads / --blocking-threads for high-event environments.
#[derive(Parser)]
#[command(version, about, color = clap::ColorChoice::Always, styles = clap_styles())]
pub(crate) struct Args {
    /// Config delivery strategy.
    ///
    /// `auto` (default) probes for a Kubernetes in-cluster service account
    /// token. Found → kube CR watch mode. Not found → file inotify mode.
    /// Use `file` or `kube` to override auto-detection explicitly.
    #[arg(
        long,
        env = "BISTOURI_CONFIG_SOURCE",
        default_value = "auto",
        value_name = "SOURCE"
    )]
    pub config_source: ConfigSource,

    /// Path to the trigger config file (YAML).
    ///
    /// Used when `--config-source=file` (or `auto` resolves to file).
    /// Resolution order: --config flag > BISTOURI_CONFIG env > /etc/bistouri/trigger.yaml
    #[arg(
        short,
        long,
        env = "BISTOURI_CONFIG",
        default_value = DEFAULT_CONFIG_PATH,
        conflicts_with = "cr_name"
    )]
    pub config: PathBuf,

    /// Name of the BistouriConfig CR to watch.
    ///
    /// Used when `--config-source=kube` (or `auto` resolves to kube).
    /// The CR must exist in the same namespace as the agent pod (derived
    /// from the in-cluster service account token).
    #[arg(
        long,
        env = "BISTOURI_CR_NAME",
        default_value = DEFAULT_CR_NAME,
        conflicts_with = "config",
        value_name = "NAME"
    )]
    pub cr_name: String,

    /// Path to procfs.
    ///
    /// Container deployments should mount the host's /proc to a path like
    /// /host/proc and set this flag. Ensures we see all host PIDs and
    /// resolve cgroups from the host's perspective.
    ///
    /// Defaults to /proc (correct for baremetal).
    #[arg(long, env = "BISTOURI_PROC_PATH", default_value = "/proc")]
    pub proc_path: PathBuf,

    /// Path to the cgroup2 filesystem.
    ///
    /// When set, skips auto-detection from <proc_path>/mounts and uses
    /// this path directly. Useful when the cgroup mount is at a
    /// non-standard location.
    ///
    /// When omitted, auto-detected from <proc_path>/mounts.
    #[arg(long, env = "BISTOURI_CGROUP_PATH")]
    pub cgroup_path: Option<PathBuf>,

    /// Number of async IO worker threads for the tokio runtime.
    ///
    /// Controls how many threads service the async event loop (PSI watchers,
    /// inotify, channels). Default of 1 is sufficient for most deployments;
    /// increase for high-event environments with many concurrent PSI triggers.
    #[arg(long, default_value_t = 1)]
    pub io_threads: usize,

    /// Max threads in the spawn_blocking pool.
    ///
    /// Used for transient synchronous work like /proc walking and config
    /// file parsing. These tasks are serialized in practice, so 1 is sufficient.
    #[arg(long, default_value_t = 1)]
    pub blocking_threads: usize,

    /// Log level filter (e.g. "bistouri_agent=debug", "bistouri_agent=info,tokio=warn").
    ///
    /// Resolution order: --log-level flag > RUST_LOG env > "bistouri_agent=info"
    #[arg(long, env = "RUST_LOG")]
    pub log_level: Option<String>,

    /// Duration in seconds to capture stack traces after a PSI trigger fires.
    ///
    /// At the default sampling frequency of 19 Hz, a 3-second capture window
    /// yields ~57 stack samples per PID — enough for a statistically meaningful
    /// flamegraph. Shorter windows risk missing patterns; longer windows increase
    /// memory usage and may outlast the stall event.
    #[arg(long, env = "BISTOURI_CAPTURE_DURATION", default_value_t = 3)]
    pub capture_duration_secs: u64,

    /// Port for the Prometheus /metrics HTTP endpoint.
    ///
    /// Default 9464 follows the OpenTelemetry exporter convention.
    /// Prometheus will scrape this endpoint for operational metrics.
    #[arg(long, env = "BISTOURI_METRICS_PORT", default_value_t = 9464)]
    pub metrics_port: u16,

    /// Sampling frequency in Hz for the perf event profiler.
    ///
    /// Uses a prime number (default 19) to avoid aliasing with periodic
    /// workloads that run at power-of-two frequencies. Higher values
    /// increase CPU overhead linearly — each sample invokes bpf_get_stack()
    /// with VMA walks for build_id resolution.
    ///
    /// Must be a prime number between 2 and 1009 (inclusive).
    #[arg(long, env = "BISTOURI_FREQ", default_value_t = 19, value_parser = parse_prime_freq)]
    pub freq: u64,

    /// gRPC endpoint for the downstream CaptureService (e.g. `http://localhost:9500`).
    ///
    /// When set, completed capture sessions are forwarded to this endpoint via
    /// the `CaptureService.ReportSession` RPC. When omitted, sessions are
    /// logged locally (NullExporter).
    ///
    /// In production this points at the symbolizer service. In E2E tests it
    /// points at the in-process `SessionSink`.
    #[arg(long, env = "BISTOURI_SYMBOLIZER_ENDPOINT")]
    pub symbolizer_endpoint: Option<String>,

    /// Tenant identity for multi-tenant routing. Required.
    ///
    /// Identifies the billing/organizational unit. Every SessionPayload
    /// from this agent carries this value.
    #[arg(long, env = "BISTOURI_TENANT_ID")]
    pub tenant_id: String,

    /// Additional key=value labels attached to every session.
    ///
    /// Can be specified multiple times: --label hostname=node-1 --label env=prod
    /// Or via env: BISTOURI_LABELS="hostname=node-1,env=prod"
    /// Target-level labels from TriggerConfig take precedence on conflict.
    #[arg(long, value_parser = parse_label, env = "BISTOURI_LABELS", value_delimiter = ',')]
    pub label: Vec<(String, String)>,
}

fn parse_label(s: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = s
        .split_once('=')
        .ok_or_else(|| format!("invalid label '{s}': expected key=value"))?;
    if key.is_empty() {
        return Err(format!("invalid label '{s}': key must not be empty"));
    }
    Ok((key.to_string(), value.to_string()))
}

fn clap_styles() -> Styles {
    Styles::styled()
        .header(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
        .usage(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan))))
        .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))))
        .error(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
        )
        .valid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
        )
        .invalid(
            Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
        )
}

fn parse_prime_freq(s: &str) -> std::result::Result<u64, String> {
    let n: u64 = s.parse().map_err(|e| format!("{e}"))?;
    if !(2..=1009).contains(&n) {
        return Err("frequency must be between 2 and 1009 Hz".into());
    }
    if !is_prime(n) {
        return Err(format!(
            "{n} is not prime — use a prime frequency to avoid aliasing \
             with periodic workloads (e.g. 19, 47, 97, 199, 499, 997)"
        ));
    }
    Ok(n)
}

fn is_prime(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n.is_multiple_of(2) || n.is_multiple_of(3) {
        return false;
    }
    let mut i = 5;
    while i * i <= n {
        if n.is_multiple_of(i) || n.is_multiple_of(i + 2) {
            return false;
        }
        i += 6;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::zero(0, false)]
    #[case::one(1, false)]
    #[case::two(2, true)]
    #[case::three(3, true)]
    #[case::four(4, false)]
    #[case::five(5, true)]
    #[case::six(6, false)]
    #[case::nineteen(19, true)]
    #[case::twenty(20, false)]
    #[case::ninety_seven(97, true)]
    #[case::hundred(100, false)]
    #[case::nine_ninety_seven(997, true)]
    #[case::thousand_nine(1009, true)]
    fn is_prime_cases(#[case] n: u64, #[case] expected: bool) {
        assert_eq!(is_prime(n), expected, "is_prime({n})");
    }

    #[rstest]
    #[case::valid_default("19", true)]
    #[case::valid_large_prime("997", true)]
    #[case::zero("0", false)]
    #[case::one("1", false)]
    #[case::composite("20", false)]
    #[case::too_large("1013", false)]
    #[case::not_a_number("abc", false)]
    fn parse_prime_freq_cases(#[case] input: &str, #[case] should_succeed: bool) {
        let result = parse_prime_freq(input);
        assert_eq!(
            result.is_ok(),
            should_succeed,
            "parse_prime_freq({input:?})"
        );
    }
}
