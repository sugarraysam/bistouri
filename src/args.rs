use clap::builder::styling::{AnsiColor, Color, Style, Styles};
use clap::Parser;
use std::path::PathBuf;

/// Default config file path when neither --config flag nor BISTOURI_CONFIG env is set.
const DEFAULT_CONFIG_PATH: &str = "/etc/bistouri/trigger.yaml";

/// Bistouri — lightweight eBPF profiling agent triggered by Linux PSI events.
///
/// Captures stack traces from processes experiencing memory, CPU, or IO pressure.
/// Runs on a minimal thread budget by default (1 async IO thread + 1 blocking thread)
/// and scales via --io-threads / --blocking-threads for high-event environments.
#[derive(Parser)]
#[command(version, about, color = clap::ColorChoice::Always, styles = my_styles())]
pub(crate) struct Args {
    /// Path to the trigger config file (YAML).
    ///
    /// Resolution order: --config flag > BISTOURI_CONFIG env > /etc/bistouri/trigger.yaml
    #[arg(short, long, env = "BISTOURI_CONFIG", default_value = DEFAULT_CONFIG_PATH)]
    pub config: PathBuf,

    /// Path to the host's procfs mount.
    ///
    /// Container deployments should mount the host's /proc to a path like
    /// /host/proc and set this flag. Eliminates cgroup namespace escapes
    /// (../ components) that occur when reading /proc/<pid>/cgroup from
    /// inside a container's cgroup namespace.
    ///
    /// When running directly on the host, the default /proc works as-is.
    #[arg(long, env = "BISTOURI_HOST_PROC", default_value = "/proc")]
    pub host_proc: PathBuf,

    /// Path to the host's cgroup2 filesystem mount.
    ///
    /// Container deployments should mount the host's /sys/fs/cgroup to a
    /// path like /host/sys/fs/cgroup and set this flag. When set, skips
    /// mount-table auto-detection and uses this path directly.
    ///
    /// When omitted, auto-detected from <host_proc>/mounts.
    #[arg(long, env = "BISTOURI_HOST_CGROUP")]
    pub host_cgroup: Option<PathBuf>,

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

    /// Log level filter (e.g. "bistouri=debug", "bistouri=info,tokio=warn").
    ///
    /// Resolution order: --log-level flag > RUST_LOG env > "bistouri=info"
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
}

// Define your custom color palette
fn my_styles() -> Styles {
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
