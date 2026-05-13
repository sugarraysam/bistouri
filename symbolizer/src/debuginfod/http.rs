//! HTTP-based debuginfod client using reqwest.

use reqwest::Client;
use tracing::debug;

use super::{ArtifactKind, DebuginfodClient};
use crate::error::{Result, SymbolizerError};

/// Timeout for individual debuginfod HTTP requests.
const FETCH_TIMEOUT_SECS: u64 = 30;

/// Debuginfod client that fetches artifacts over HTTP.
///
/// Expects a debuginfod-compatible server (e.g. `elfutils-debuginfod` sidecar)
/// at the configured base URL.
#[derive(Debug)]
pub struct HttpDebuginfodClient {
    client: Client,
    base_url: String,
}

impl HttpDebuginfodClient {
    /// Creates a new client pointing at the given debuginfod server.
    ///
    /// `base_url` should be the root URL without trailing slash,
    /// e.g. `http://localhost:8002`.
    pub fn new(base_url: String) -> Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(FETCH_TIMEOUT_SECS))
            .build()
            .map_err(|e| SymbolizerError::HttpClientInit { source: e })?;

        Ok(Self { client, base_url })
    }
}

#[async_trait::async_trait]
impl DebuginfodClient for HttpDebuginfodClient {
    async fn fetch(&self, build_id_hex: &str, kind: ArtifactKind) -> Result<Option<Vec<u8>>> {
        let url = format!(
            "{}/buildid/{}/{}",
            self.base_url,
            build_id_hex,
            kind.path_segment()
        );

        debug!(url = %url, "fetching from debuginfod");

        let response =
            self.client
                .get(&url)
                .send()
                .await
                .map_err(|e| SymbolizerError::DebuginfodFetch {
                    build_id: build_id_hex.into(),
                    source: e,
                })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!(build_id = build_id_hex, "debuginfod: artifact not found");
            return Ok(None);
        }

        if !status.is_success() {
            return Err(SymbolizerError::DebuginfodNotFound {
                build_id: build_id_hex.into(),
                status: status.as_u16(),
            });
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| SymbolizerError::DebuginfodFetch {
                build_id: build_id_hex.into(),
                source: e,
            })?;

        debug!(
            build_id = build_id_hex,
            size_bytes = bytes.len(),
            "debuginfod: artifact fetched"
        );

        Ok(Some(bytes.to_vec()))
    }
}
