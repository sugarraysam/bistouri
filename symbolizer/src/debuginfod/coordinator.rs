//! Fetch coordinator for debuginfod fetches.
//!
//! Coalesces concurrent fetch requests for the same BuildId and ArtifactKind
//! into a single request, preventing the thundering herd problem.
//! Bounds global fetch concurrency using a Semaphore.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use super::DebuginfodClient;
use crate::error::{Result, SymbolizerError};
use crate::resolve::build_id::{self, BuildId};

/// Result of a single fetch operation (bytes are Arc-wrapped to avoid large clones).
pub type FetchResult = Result<Option<Arc<[u8]>>>;

/// Request sent to the coordinator actor.
struct FetchRequest {
    build_id: BuildId,
    reply: oneshot::Sender<FetchResult>,
}

/// Actor that coordinates and deduplicates debuginfod fetches.
pub struct FetchCoordinator {
    tx: mpsc::Sender<FetchRequest>,
}

impl FetchCoordinator {
    /// Creates a new FetchCoordinator and spawns its actor loop.
    pub fn new(
        client: Arc<dyn DebuginfodClient>,
        max_concurrent_fetches: usize,
        channel_capacity: usize,
        cancel_token: CancellationToken,
    ) -> Self {
        let (tx, rx) = mpsc::channel(channel_capacity);
        let semaphore = Arc::new(Semaphore::new(max_concurrent_fetches));
        tokio::spawn(coordinator_loop(client, rx, semaphore, cancel_token));
        Self { tx }
    }

    /// Fetches an artifact, coalescing duplicate requests for the same BuildId.
    pub async fn fetch(&self, build_id: &BuildId) -> FetchResult {
        let (reply_tx, reply_rx) = oneshot::channel();
        let request = FetchRequest {
            build_id: *build_id,
            reply: reply_tx,
        };

        if self.tx.send(request).await.is_err() {
            return Err(SymbolizerError::DebuginfodServerError {
                build_id: build_id::to_hex(build_id),
                reason: "FetchCoordinator actor shutdown".into(),
            });
        }

        match reply_rx.await {
            Ok(result) => result,
            Err(_) => Err(SymbolizerError::DebuginfodServerError {
                build_id: build_id::to_hex(build_id),
                reason: "FetchCoordinator request cancelled".into(),
            }),
        }
    }
}

async fn coordinator_loop(
    client: Arc<dyn DebuginfodClient>,
    mut rx: mpsc::Receiver<FetchRequest>,
    semaphore: Arc<Semaphore>,
    cancel_token: CancellationToken,
) {
    let mut in_flight: HashMap<BuildId, Vec<oneshot::Sender<FetchResult>>> = HashMap::new();
    let mut fetch_tasks = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                debug!("FetchCoordinator cancelled, shutting down");
                break;
            }
            Some(req) = rx.recv() => {
                let key = req.build_id;
                let waiters = in_flight.entry(key).or_default();
                waiters.push(req.reply);
                if waiters.len() == 1 {
                    let client_clone = client.clone();
                    let sem_clone = semaphore.clone();
                    let build_id_hex = build_id::to_hex(&req.build_id);
                    let build_id = req.build_id;

                    fetch_tasks.spawn(async move {
                        let _permit = match sem_clone.acquire_owned().await {
                            Ok(permit) => permit,
                            Err(_) => {
                                return (build_id, Err(SymbolizerError::DebuginfodServerError {
                                    build_id: build_id_hex,
                                    reason: "semaphore closed".into(),
                                }), std::time::Duration::ZERO);
                            }
                        };

                        metrics::gauge!(crate::telemetry::METRIC_FETCH_INFLIGHT).increment(1.0);
                        let start = Instant::now();
                        let result = client_clone.fetch(&build_id_hex).await;
                        metrics::gauge!(crate::telemetry::METRIC_FETCH_INFLIGHT).decrement(1.0);
                        let duration = start.elapsed();

                        let mapped = match result {
                            Ok(Some(vec)) => Ok(Some(Arc::from(vec.into_boxed_slice()))),
                            Ok(None) => Ok(None),
                            Err(e) => Err(e),
                        };

                        (build_id, mapped, duration)
                    });
                } else {
                    metrics::counter!(crate::telemetry::METRIC_FETCH_COALESCED_TOTAL).increment(1);
                }
            }
            Some(task_result) = fetch_tasks.join_next() => {
                match task_result {
                    Ok((build_id, fetch_result, duration)) => {
                        let key = build_id;
                        if let Some(waiters) = in_flight.remove(&key) {
                            for tx in waiters {
                                let res = fetch_result.clone();
                                if tx.send(res).is_ok() {
                                    metrics::histogram!(crate::telemetry::METRIC_FETCH_WAIT_SECONDS).record(duration.as_secs_f64());
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Fetch coordinator task panicked: {:?}", e);
                    }
                }
            }
            else => {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::build_id::BUILD_ID_SIZE;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::time::sleep;

    struct MockClient {
        calls: Arc<AtomicUsize>,
        delay: Duration,
        result: Result<Option<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl DebuginfodClient for MockClient {
        async fn fetch(&self, _build_id_hex: &str) -> Result<Option<Vec<u8>>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.delay > Duration::ZERO {
                sleep(self.delay).await;
            }
            match &self.result {
                Ok(Some(v)) => Ok(Some(v.clone())),
                Ok(None) => Ok(None),
                Err(e) => Err(e.clone()),
            }
        }
    }

    fn dummy_bid(val: u8) -> BuildId {
        let mut bid = [0u8; BUILD_ID_SIZE];
        bid[0] = val;
        bid
    }

    #[tokio::test]
    async fn test_basic_fetch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(MockClient {
            calls: calls.clone(),
            delay: Duration::ZERO,
            result: Ok(Some(vec![1, 2, 3])),
        });
        let cancel = CancellationToken::new();
        let coordinator = FetchCoordinator::new(client, 4, 16, cancel);

        let res = coordinator.fetch(&dummy_bid(1)).await;
        assert_eq!(res.unwrap().unwrap().as_ref(), &[1, 2, 3]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_deduplication() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(MockClient {
            calls: calls.clone(),
            delay: Duration::from_millis(50),
            result: Ok(Some(vec![1, 2, 3])),
        });
        let cancel = CancellationToken::new();
        let coordinator = Arc::new(FetchCoordinator::new(client, 4, 16, cancel));

        let bid = dummy_bid(1);
        let mut tasks = JoinSet::new();

        for _ in 0..5 {
            let coord = coordinator.clone();
            tasks.spawn(async move { coord.fetch(&bid).await });
        }

        while let Some(res) = tasks.join_next().await {
            let val = res.unwrap().unwrap().unwrap();
            assert_eq!(val.as_ref(), &[1, 2, 3]);
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_concurrency_bound() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(MockClient {
            calls: calls.clone(),
            delay: Duration::from_millis(50),
            result: Ok(Some(vec![1, 2, 3])),
        });
        let cancel = CancellationToken::new();
        // Allow only 2 concurrent fetches
        let coordinator = Arc::new(FetchCoordinator::new(client, 2, 16, cancel));

        let mut tasks = JoinSet::new();
        for i in 0..5 {
            let coord = coordinator.clone();
            tasks.spawn(async move { coord.fetch(&dummy_bid(i as u8)).await });
        }

        while let Some(res) = tasks.join_next().await {
            assert!(res.is_ok());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(MockClient {
            calls: calls.clone(),
            delay: Duration::ZERO,
            result: Err(SymbolizerError::DebuginfodNotFound {
                build_id: "test".into(),
                status: 404,
            }),
        });
        let cancel = CancellationToken::new();
        let coordinator = FetchCoordinator::new(client, 4, 16, cancel);

        let res = coordinator.fetch(&dummy_bid(1)).await;
        assert!(res.is_err());
        assert!(matches!(
            res.unwrap_err(),
            SymbolizerError::DebuginfodNotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_mixed_keys() {
        let calls = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(MockClient {
            calls: calls.clone(),
            delay: Duration::from_millis(20),
            result: Ok(Some(vec![1, 2, 3])),
        });
        let cancel = CancellationToken::new();
        let coordinator = Arc::new(FetchCoordinator::new(client, 4, 16, cancel));

        let mut tasks = JoinSet::new();
        tasks.spawn({
            let coord = coordinator.clone();
            async move { coord.fetch(&dummy_bid(1)).await }
        });
        tasks.spawn({
            let coord = coordinator.clone();
            async move { coord.fetch(&dummy_bid(2)).await }
        });

        while let Some(res) = tasks.join_next().await {
            assert!(res.unwrap().is_ok());
        }

        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
