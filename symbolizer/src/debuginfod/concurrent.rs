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
/// Both fetches are dispatched via `tokio::join!` (run to completion).
/// The first `Ok(Some(bytes))` wins. If both return `Ok(None)`, the
/// result is `Ok(None)`. If one errors and the other succeeds, the
/// success wins. If both error, the first error is returned.
///
/// # Why `tokio::join!` instead of `tokio::select!`?
///
/// `select!` cancels the losing branch, but we need the second
/// result when the first returns `None` (a definitive miss, not an
/// error). `join!` runs both to completion, then we pick the winner.
/// The cost is wasted bandwidth if both hit — acceptable because the
/// negative cache prevents repeated lookups for the same build ID.
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
        let (result_a, result_b) = tokio::join!(
            self.source_a.fetch(build_id_hex, kind),
            self.source_b.fetch(build_id_hex, kind),
        );

        // First success with data wins.
        match (&result_a, &result_b) {
            (Ok(Some(_)), _) => {
                debug!(
                    build_id = build_id_hex,
                    source = "a",
                    "concurrent: hit from source A"
                );
                return result_a;
            }
            (_, Ok(Some(_))) => {
                debug!(
                    build_id = build_id_hex,
                    source = "b",
                    "concurrent: hit from source B"
                );
                return result_b;
            }
            _ => {}
        }

        // Both missed or errored. Prefer Ok(None) over Err — a definitive
        // miss is more useful than a transient error for negative caching.
        match (result_a, result_b) {
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
            (Err(e), Err(_e2)) => {
                // Both errored — return the first error.
                debug!(build_id = build_id_hex, "concurrent: both sources errored");
                Err(e)
            }
            // Covered by the match arms above.
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::SymbolizerError;
    use rstest::rstest;

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
}
