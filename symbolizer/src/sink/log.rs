//! Log-based sink for development and debugging.
//!
//! Logs each resolved session's traces at INFO level with function names,
//! sample counts, and source locations.

use std::sync::Arc;

use tracing::info;

use super::{SessionSink, SinkError};
use crate::model::{ResolvedFrame, ResolvedSession, SymbolInfo};

/// Sink that logs resolved sessions to the tracing subscriber.
#[derive(Debug)]
pub struct LogSink;

#[async_trait::async_trait]
impl SessionSink for LogSink {
    async fn store(&self, session: ResolvedSession) -> std::result::Result<(), SinkError> {
        info!(
            session_id = %session.session_id,
            tenant_id = %session.tenant_id,
            service_id = %session.service_id,
            kernel_release = %session.kernel_release,
            total_samples = session.total_samples,
            unique_traces = session.traces.len(),
            "resolved session"
        );

        for (i, trace) in session.traces.iter().enumerate() {
            let samples = trace.on_cpu_count + trace.off_cpu_count;
            info!(
                trace = i,
                on_cpu = trace.on_cpu_count,
                off_cpu = trace.off_cpu_count,
                samples = samples,
                "trace #{i}"
            );

            if !trace.kernel_frames.is_empty() {
                info!("  kernel stack:");
                for frame in &trace.kernel_frames {
                    log_frame(frame, "    ");
                }
            }

            if !trace.user_frames.is_empty() {
                info!("  user stack:");
                for frame in &trace.user_frames {
                    log_frame(frame, "    ");
                }
            }
        }

        Ok(())
    }
}

fn log_frame(frame: &Arc<ResolvedFrame>, indent: &str) {
    match frame.as_ref() {
        ResolvedFrame::Symbolized(sym) => log_symbol(sym, indent),
        ResolvedFrame::Inlined(syms) => {
            for (i, sym) in syms.iter().enumerate() {
                let prefix = if i == 0 {
                    indent
                } else {
                    &format!("{indent}[inlined] ")
                };
                log_symbol(sym, prefix);
            }
        }
    }
}

fn log_symbol(sym: &SymbolInfo, prefix: &str) {
    match (&sym.file, sym.line) {
        (Some(file), Some(line)) => {
            info!("{prefix}{} at {file}:{line}", sym.function);
        }
        (Some(file), None) => {
            info!("{prefix}{} at {file}", sym.function);
        }
        _ => {
            info!("{prefix}{}", sym.function);
        }
    }
}
