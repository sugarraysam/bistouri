use crate::agent::profiler::{LoadedProfilerAgent, ProfilerAgentBuilder};
use crate::args::Args;
use crate::capture::orchestrator::{CaptureOrchestrator, STACK_SAMPLE_CHANNEL_SIZE};
use crate::capture::session::CompletedSession;
use crate::capture::trace::StackSample;
use crate::trigger::PreparedTriggerAgent;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Top-level lifecycle manager for all Bistouri subsystems.
///
/// Owns a single `CancellationToken` that propagates shutdown to every
/// subsystem. Components that need independent cancellation (e.g. proc_walk
/// on config reload) use `child_token()` so the parent cancel still reaches
/// them.
///
/// `loaded_agent` must live as long as the daemon: it owns the BPF skel,
/// perf-event links, and the OpenObject backing memory. The ring buffer
/// polling task and BPF map handles all reference fds owned by the skel —
/// dropping it prematurely causes IO safety violations.
pub(crate) struct BistouriDaemon {
    cancel: CancellationToken,
    #[allow(dead_code)]
    loaded_agent: LoadedProfilerAgent,
    poll_handle: JoinHandle<()>,
    trigger_handle: JoinHandle<()>,
    orch_handle: JoinHandle<()>,
    downstream_handle: JoinHandle<()>,
}

impl BistouriDaemon {
    /// Boots all subsystems in dependency order and returns a running daemon.
    ///
    /// A single `CancellationToken` is threaded through every component:
    /// - Ring buffer polling
    /// - Trigger agent event loop
    /// - Config file watcher
    /// - Capture orchestrator
    /// - Downstream consumer
    pub(crate) async fn start(args: Args) -> anyhow::Result<Self> {
        let cancel = CancellationToken::new();

        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(([0, 0, 0, 0], args.metrics_port))
            .install()
            .map_err(|e| anyhow::anyhow!("metrics server on port {}: {e}", args.metrics_port))?;

        // Stack sample channel created here (not inside orchestrator) because the
        // BPF ringbuffer callback needs the Sender at agent build time — before
        // the orchestrator exists. All other channels are internal to start().
        let (stack_tx, stack_rx) = mpsc::channel::<StackSample>(STACK_SAMPLE_CHANNEL_SIZE);

        // Phase 1: Prepare TriggerAgent (loads config, creates event channel,
        // resolves cgroup2 mount point).
        let prepared =
            PreparedTriggerAgent::prepare(args.config, args.host_proc, args.host_cgroup).await?;

        // Phase 2: Build ProfilerAgent with trigger + stack sample senders.
        let agent_builder = ProfilerAgentBuilder::new()
            .with_trigger_tx(prepared.trigger_tx())
            .with_stack_tx(stack_tx);
        let mut loaded_agent = agent_builder.try_build()?.load_and_attach()?;
        let comm_lpm_trie_handle = loaded_agent.comm_lpm_trie_handle()?;
        let pid_filter_handle = loaded_agent.pid_filter_handle()?;

        let poll_handle = loaded_agent.start_polling(cancel.clone())?;

        // Phase 3: Start CaptureOrchestrator with BPF pid filter and stack channel.
        let orch_handle = CaptureOrchestrator::start(
            pid_filter_handle,
            args.capture_duration_secs,
            stack_rx,
            cancel.clone(),
        );

        let capture_tx = orch_handle.capture_tx.clone();
        let orch_task = orch_handle.task_handle;
        let completed_rx = orch_handle.completed_rx;

        // Phase 4: Start TriggerAgent with BPF trie handle and capture channel.
        let trigger_handle = prepared
            .start(comm_lpm_trie_handle, capture_tx, cancel.clone())
            .await?;

        // Downstream consumer — logs completed sessions until symbolizer is wired.
        let ds_cancel = cancel.clone();
        let downstream_handle = tokio::spawn(async move {
            Self::downstream_consumer(completed_rx, ds_cancel).await;
        });

        info!("BPF profiler agent started");

        Ok(Self {
            cancel,
            loaded_agent,
            poll_handle,
            trigger_handle,
            orch_handle: orch_task,
            downstream_handle,
        })
    }

    /// Graceful shutdown: cancels the token and awaits all tasks.
    pub(crate) async fn shutdown(self) {
        self.cancel.cancel();

        let _ = self.poll_handle.await;
        let _ = self.trigger_handle.await;
        let _ = self.orch_handle.await;
        let _ = self.downstream_handle.await;

        // loaded_agent drops here — BPF skel, links, and object are released last.
    }

    /// Placeholder downstream consumer — logs completed sessions until
    /// the symbolizer service is wired in.
    async fn downstream_consumer(
        mut completed_rx: mpsc::Receiver<CompletedSession>,
        cancel: CancellationToken,
    ) {
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                session = completed_rx.recv() => match session {
                    Some(session) => {
                        info!(
                            session_id = %session.session_id,
                            pid = session.pid,
                            comm = %session.comm,
                            resource = ?session.resource,
                            total_samples = session.total_samples,
                            unique_traces = session.stack_traces.len(),
                            "completed session ready for symbolization",
                        );
                        // TODO: forward to symbolizer service
                    }
                    None => break,
                },
            }
        }
    }
}
