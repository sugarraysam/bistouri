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
