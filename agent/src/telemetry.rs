//! Centralized metric definitions for the Bistouri agent.
//!
//! All Prometheus metric names, descriptions, and the `describe_all()` entry
//! point live here — one source of truth for the entire metric catalog.
//! Call `describe_all()` once during daemon startup, before any counters
//! are incremented, to ensure help text is registered.

use crate::sys::kernel::KernelMeta;

// ---------------------------------------------------------------------------
// Profiler subsystem (agent/profiler.rs, agent/ringbuf.rs, capture/trace.rs)
// ---------------------------------------------------------------------------

/// BPF stack ring buffer reservation failures (64 MB buffer full).
pub(crate) const METRIC_STACK_RINGBUF_FULL: &str = "bistouri_profiler_stack_ringbuf_full";

/// BPF `bpf_get_stack()` failures (transient, process likely exited).
/// Labels: `space` = kernel | user.
pub(crate) const METRIC_STACK_FETCH_ERRORS: &str = "bistouri_profiler_stack_fetch_errors";

/// BPF trigger ring buffer reservation failures (256 KB buffer full).
pub(crate) const METRIC_TRIGGER_RINGBUF_FULL: &str = "bistouri_profiler_trigger_ringbuf_full";

/// Trigger events dropped due to full channel (proc_walk provides completeness).
pub(crate) const METRIC_TRIGGER_CHANNEL_FULL: &str = "bistouri_profiler_trigger_channel_full";

/// Stack samples dropped due to full channel (statistical loss at 19 Hz).
pub(crate) const METRIC_STACK_CHANNEL_FULL: &str = "bistouri_profiler_stack_channel_full";

/// User stack frames by classification.
/// Labels: `kind` = "resolved" | "vdso" | "corrupted" | "unresolved".
pub(crate) const METRIC_USER_FRAMES: &str = "bistouri_profiler_user_frames";

// ---------------------------------------------------------------------------
// Trigger subsystem (trigger/mod.rs, trigger/psi.rs)
// ---------------------------------------------------------------------------

/// Cgroup resolution failures during event processing.
pub(crate) const METRIC_CGROUP_RESOLVE_FAILURES: &str = "bistouri_trigger_cgroup_resolve_failures";

/// Stale events filtered after config reload.
pub(crate) const METRIC_STALE_EVENTS: &str = "bistouri_trigger_stale_events";

/// PSI file descriptor build failures.
pub(crate) const METRIC_PSI_FD_BUILD_FAILURES: &str = "bistouri_trigger_psi_fd_build_failures";

/// Successful configuration hot-reloads.
pub(crate) const METRIC_CONFIG_RELOADS: &str = "bistouri_trigger_config_reloads";

/// Failed configuration hot-reload attempts.
pub(crate) const METRIC_CONFIG_RELOAD_FAILURES: &str = "bistouri_trigger_config_reload_failures";

/// Capture request channel full, PSI event dropped.
pub(crate) const METRIC_CAPTURE_CHANNEL_FULL: &str = "bistouri_trigger_capture_channel_full";

/// Currently active PSI watchers (gauge).
pub(crate) const METRIC_ACTIVE_PSI_WATCHERS: &str = "bistouri_trigger_active_psi_watchers";

/// Processes matched during proc_walk.
pub(crate) const METRIC_PROC_WALK_MATCHES: &str = "bistouri_trigger_proc_walk_matches";

/// Duration of each proc_walk scan in seconds (histogram).
pub(crate) const METRIC_PROC_WALK_DURATION: &str = "bistouri_trigger_proc_walk_duration_seconds";

// ---------------------------------------------------------------------------
// Capture subsystem (capture/orchestrator.rs)
// ---------------------------------------------------------------------------

/// Capture sessions started after PSI trigger.
/// Labels: `resource`, `comm`.
pub(crate) const METRIC_SESSIONS_STARTED: &str = "bistouri_capture_sessions_started";

/// Capture sessions finalized and sent downstream.
/// Labels: `resource`, `comm`.
pub(crate) const METRIC_SESSIONS_COMPLETED: &str = "bistouri_capture_sessions_completed";

/// Capture requests rejected due to duplicate (pid, resource) inflight.
pub(crate) const METRIC_SESSIONS_REJECTED_DUPLICATE: &str =
    "bistouri_capture_sessions_rejected_duplicate";

/// Stack samples ingested into active sessions.
/// Labels: `resource`.
pub(crate) const METRIC_SAMPLES_INGESTED: &str = "bistouri_capture_samples_ingested";

/// Stack samples received for PIDs with no active session.
pub(crate) const METRIC_SAMPLES_UNMATCHED: &str = "bistouri_capture_samples_unmatched";

/// Failures sending completed sessions downstream.
pub(crate) const METRIC_SINK_FAILURES: &str = "bistouri_capture_sink_failures";

/// Currently active capture sessions (gauge).
pub(crate) const METRIC_ACTIVE_SESSIONS: &str = "bistouri_capture_active_sessions";

/// Total samples collected per completed session (histogram).
pub(crate) const METRIC_SESSION_SAMPLES: &str = "bistouri_capture_session_samples";

// ---------------------------------------------------------------------------
// Agent info
// ---------------------------------------------------------------------------

/// Info metric exposing agent build and host metadata.
/// Labels: `kernel_release`, `build_id`, `freq_hz`, `capture_duration_secs`.
pub(crate) const METRIC_AGENT_INFO: &str = "bistouri_agent_info";

// ---------------------------------------------------------------------------
// describe_all — called once at startup
// ---------------------------------------------------------------------------

/// Registers metric descriptions for the entire agent. Call exactly once
/// in `BistouriDaemon::start()` before any metric is incremented.
pub(crate) fn describe_all() {
    // -- Profiler --
    metrics::describe_counter!(
        METRIC_STACK_RINGBUF_FULL,
        "BPF stack ring buffer reservation failures (64MB buffer full)"
    );
    metrics::describe_counter!(
        METRIC_STACK_FETCH_ERRORS,
        "BPF bpf_get_stack() failures (transient, process likely exited)"
    );
    metrics::describe_counter!(
        METRIC_TRIGGER_RINGBUF_FULL,
        "BPF trigger ring buffer reservation failures (256KB buffer full)"
    );
    metrics::describe_counter!(
        METRIC_TRIGGER_CHANNEL_FULL,
        "Trigger events dropped due to full channel (proc_walk provides completeness)"
    );
    metrics::describe_counter!(
        METRIC_STACK_CHANNEL_FULL,
        "Stack samples dropped due to full channel (statistical loss at 19Hz)"
    );
    metrics::describe_counter!(
        METRIC_USER_FRAMES,
        "User stack frames by classification (resolved, vdso, corrupted, unresolved)"
    );

    // -- Trigger --
    metrics::describe_counter!(
        METRIC_CGROUP_RESOLVE_FAILURES,
        "Number of cgroup resolution failures during event processing"
    );
    metrics::describe_counter!(
        METRIC_STALE_EVENTS,
        "Number of stale events filtered after config reload"
    );
    metrics::describe_counter!(
        METRIC_PSI_FD_BUILD_FAILURES,
        "Number of PSI file descriptor build failures"
    );
    metrics::describe_counter!(
        METRIC_CONFIG_RELOADS,
        "Number of successful configuration hot-reloads"
    );
    metrics::describe_counter!(
        METRIC_CONFIG_RELOAD_FAILURES,
        "Number of failed configuration hot-reload attempts"
    );
    metrics::describe_counter!(
        METRIC_CAPTURE_CHANNEL_FULL,
        "Capture request channel full, PSI event dropped"
    );
    metrics::describe_gauge!(
        METRIC_ACTIVE_PSI_WATCHERS,
        "Number of currently active PSI watchers"
    );
    metrics::describe_counter!(
        METRIC_PROC_WALK_MATCHES,
        "Processes matched during proc_walk scans"
    );
    metrics::describe_histogram!(
        METRIC_PROC_WALK_DURATION,
        "Duration of each proc_walk scan in seconds"
    );

    // -- Capture --
    metrics::describe_counter!(
        METRIC_SESSIONS_STARTED,
        "Capture sessions started after PSI trigger"
    );
    metrics::describe_counter!(
        METRIC_SESSIONS_COMPLETED,
        "Capture sessions finalized and sent downstream"
    );
    metrics::describe_counter!(
        METRIC_SESSIONS_REJECTED_DUPLICATE,
        "Capture requests rejected due to duplicate (pid, resource) inflight"
    );
    metrics::describe_counter!(
        METRIC_SAMPLES_INGESTED,
        "Stack samples ingested into active sessions"
    );
    metrics::describe_counter!(
        METRIC_SAMPLES_UNMATCHED,
        "Stack samples received for PIDs with no active session"
    );
    metrics::describe_counter!(
        METRIC_SINK_FAILURES,
        "Failures sending completed sessions downstream"
    );
    metrics::describe_gauge!(
        METRIC_ACTIVE_SESSIONS,
        "Number of currently active capture sessions"
    );
    metrics::describe_histogram!(
        METRIC_SESSION_SAMPLES,
        "Total samples collected per completed session"
    );

    // -- Agent info --
    metrics::describe_gauge!(
        METRIC_AGENT_INFO,
        "Bistouri agent metadata (constant 1, labels carry metadata)"
    );
}

/// Records the `bistouri_agent_info` gauge with host/config metadata labels.
/// Called once at startup after `describe_all()`.
pub(crate) fn record_agent_info(
    kernel_meta: &KernelMeta,
    freq_hz: u64,
    capture_duration_secs: u64,
) {
    let build_id_hex: String = kernel_meta
        .build_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    metrics::gauge!(
        METRIC_AGENT_INFO,
        "kernel_release" => kernel_meta.release.clone(),
        "build_id" => build_id_hex,
        "freq_hz" => freq_hz.to_string(),
        "capture_duration_secs" => capture_duration_secs.to_string(),
    )
    .set(1.0);
}
