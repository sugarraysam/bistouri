//! Concurrent debuginfod client — races two sources in parallel.
//!
//! Queries both backends via [`tokio::join!`] and returns the first
//! `Ok(Some(bytes))`. This avoids the latency penalty of sequential
//! tiering when a build ID only exists in one source.
//!
//! Designed for composing the private `debuginfo-indexer` with a
//! public `debuginfod` server (e.g., `debuginfod.elfutils.org`).

use tracing::debug;

use super::{ArtifactKind, DebuginfodClient};
use crate::error::Result;

/// Races two [`DebuginfodClient`] implementations concurrently.
///
/// Dispatched via `tokio::select!` with a fallback: the first source to complete
/// is awaited. If it returns a success (`Ok(Some(bytes))`), the other source is cancelled
/// immediately (dropped), saving memory and bandwidth. If it returns a miss (`Ok(None)`)
/// or error, we fallback to awaiting the second source.
///
/// The first success wins. If both return `Ok(None)`, the result is `Ok(None)`.
/// If one errors and the other succeeds, the success wins. If both error, the first
/// error that occurred is returned.
pub struct ConcurrentDebuginfodClient<A, B> {
    /// Typically the private `IndexerDebuginfodClient`.
    source_a: A,
    /// Typically the public `HttpDebuginfodClient`.
    source_b: B,
}

impl<A: DebuginfodClient, B: DebuginfodClient> ConcurrentDebuginfodClient<A, B> {
    pub fn new(source_a: A, source_b: B) -> Self {
        Self { source_a, source_b }
    }
}

#[async_trait::async_trait]
impl<A: DebuginfodClient, B: DebuginfodClient> DebuginfodClient
    for ConcurrentDebuginfodClient<A, B>
{
    async fn fetch(&self, build_id_hex: &str, kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
        let mut fut_a = std::pin::pin!(self.source_a.fetch(build_id_hex, kind));
        let mut fut_b = std::pin::pin!(self.source_b.fetch(build_id_hex, kind));

        // Race: first to complete wins, biasing toward source A if both are ready.
        let (winner, loser, source) = tokio::select! {
            biased;
            result_a = &mut fut_a => (result_a, fut_b, "a"),
            result_b = &mut fut_b => (result_b, fut_a, "b"),
        };

        // If winner has data, cancel loser (drop) and return.
        if let Ok(Some(_)) = &winner {
            debug!(
                build_id = build_id_hex,
                source = source,
                "concurrent: hit from source {source}"
            );
            return winner;
        }

        // Winner was None or Err — await the loser as fallback.
        let fallback = loser.await;
        let fallback_source = if source == "a" { "b" } else { "a" };

        if let Ok(Some(_)) = &fallback {
            debug!(
                build_id = build_id_hex,
                source = fallback_source,
                "concurrent: hit from source {fallback_source}"
            );
            return fallback;
        }

        // Both missed or errored. Prefer Ok(None) over Err — a definitive
        // miss is more useful than a transient error for negative caching.
        match (&winner, &fallback) {
            (Ok(None), Ok(None)) => {
                debug!(
                    build_id = build_id_hex,
                    "concurrent: both sources returned miss"
                );
                Ok(None)
            }
            (Ok(None), Err(e)) | (Err(e), Ok(None)) => {
                // One source confirmed "not found", the other errored.
                // The miss is authoritative for that source; the error
                // is transient for the other. Return None so the negative
                // cache fires — the errored source will be retried on
                // the next session anyway.
                debug!(
                    build_id = build_id_hex,
                    error = %e,
                    "concurrent: one miss, one error — treating as miss"
                );
                Ok(None)
            }
            _ => {
                // Both errored — return the first error (winner).
                debug!(build_id = build_id_hex, "concurrent: both sources errored");
                if winner.is_err() {
                    winner
                } else {
                    fallback
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SymbolizerError;
    use rstest::rstest;
    use std::time::Duration;

    /// Stub client that returns a configured response.
    struct StubClient {
        response: Result<Option<Vec<u8>>>,
    }

    impl StubClient {
        fn hit(data: &[u8]) -> Self {
            Self {
                response: Ok(Some(data.to_vec())),
            }
        }

        fn miss() -> Self {
            Self { response: Ok(None) }
        }

        fn error() -> Self {
            Self {
                response: Err(SymbolizerError::DebuginfodNotFound {
                    build_id: "test".into(),
                    status: 500,
                }),
            }
        }
    }

    #[async_trait::async_trait]
    impl DebuginfodClient for StubClient {
        async fn fetch(&self, _build_id_hex: &str, _kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
            match &self.response {
                Ok(Some(v)) => Ok(Some(v.clone())),
                Ok(None) => Ok(None),
                Err(_) => Err(SymbolizerError::DebuginfodNotFound {
                    build_id: "test".into(),
                    status: 500,
                }),
            }
        }
    }

    #[rstest]
    #[case::a_hits(
        StubClient::hit(b"from-a"),
        StubClient::miss(),
        Some(b"from-a".to_vec()),
        "source A hit wins"
    )]
    #[case::b_hits(
        StubClient::miss(),
        StubClient::hit(b"from-b"),
        Some(b"from-b".to_vec()),
        "source B hit wins when A misses"
    )]
    #[case::both_hit_a_wins(
        StubClient::hit(b"from-a"),
        StubClient::hit(b"from-b"),
        Some(b"from-a".to_vec()),
        "both hit — source A wins (deterministic)"
    )]
    #[case::both_miss(StubClient::miss(), StubClient::miss(), None, "both miss → None")]
    #[case::a_errors_b_hits(
        StubClient::error(),
        StubClient::hit(b"from-b"),
        Some(b"from-b".to_vec()),
        "A errors, B hits → B wins"
    )]
    #[case::a_hits_b_errors(
        StubClient::hit(b"from-a"),
        StubClient::error(),
        Some(b"from-a".to_vec()),
        "A hits, B errors → A wins"
    )]
    #[case::miss_and_error(
        StubClient::miss(),
        StubClient::error(),
        None,
        "one miss + one error → None (miss is authoritative)"
    )]
    #[tokio::test]
    async fn concurrent_resolution(
        #[case] a: StubClient,
        #[case] b: StubClient,
        #[case] expected: Option<Vec<u8>>,
        #[case] description: &str,
    ) {
        let client = ConcurrentDebuginfodClient::new(a, b);
        let result = client.fetch("deadbeef", ArtifactKind::Debuginfo).await;

        match result {
            Ok(data) => assert_eq!(data, expected, "{description}"),
            Err(_) if expected.is_none() => {} // both errored case
            Err(e) => panic!("{description}: unexpected error: {e}"),
        }
    }

    #[tokio::test]
    async fn both_error_returns_err() {
        let client = ConcurrentDebuginfodClient::new(StubClient::error(), StubClient::error());
        let result = client.fetch("deadbeef", ArtifactKind::Debuginfo).await;
        assert!(result.is_err(), "both errors should propagate");
    }

    #[tokio::test]
    async fn test_fast_miss_fallback() {
        struct SlowClient {
            delay: Duration,
            data: Vec<u8>,
        }
        #[async_trait::async_trait]
        impl DebuginfodClient for SlowClient {
            async fn fetch(
                &self,
                _build_id_hex: &str,
                _kind: ArtifactKind,
            ) -> Result<Option<Vec<u8>>> {
                tokio::time::sleep(self.delay).await;
                Ok(Some(self.data.clone()))
            }
        }

        let a = StubClient::miss();
        let b = SlowClient {
            delay: Duration::from_millis(10),
            data: b"slow-data".to_vec(),
        };

        let client = ConcurrentDebuginfodClient::new(a, b);
        let result = client.fetch("deadbeef", ArtifactKind::Debuginfo).await;
        assert_eq!(result.unwrap().unwrap(), b"slow-data");
    }
}
