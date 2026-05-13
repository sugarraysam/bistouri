//! Fixture loading and SessionPayload construction for E2E tests.

use std::collections::HashMap;
use std::path::PathBuf;

use bistouri_api::v1 as proto;

use crate::error::E2eError;
use crate::kernel_meta::HostKernelMeta;

/// Parsed fixture manifest entry.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct FixtureEntry {
    pub build_id_hex: String,
    pub symbols: HashMap<String, SymbolEntry>,
}

/// A symbol's file offset and expected source location.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct SymbolEntry {
    pub file_offset: u64,
    /// Source file basename (e.g. "hello.c").
    pub file: String,
    /// Source line number where the function starts.
    pub line: u32,
}

/// Load the fixture manifest from the standard location.
pub(crate) fn load_manifest() -> Result<HashMap<String, FixtureEntry>, E2eError> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    let manifest_path = PathBuf::from(manifest_dir).join("tests/e2e/fixtures/manifest.json");

    let content = std::fs::read_to_string(&manifest_path)
        .map_err(|e| E2eError::Fixture(format!("reading {}: {e}", manifest_path.display())))?;

    serde_json::from_str(&content).map_err(E2eError::Json)
}

/// Decode a hex build ID string into raw bytes.
fn decode_build_id(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

/// Expected assertions for a fixture — function names and source locations
/// that the LogSink output should contain after symbolization.
pub(crate) struct ExpectedSymbols<'a> {
    pub function_names: Vec<&'a str>,
    /// `"function at file:line"` patterns from LogSink output.
    pub source_locations: Vec<String>,
}

impl FixtureEntry {
    /// Derive the expected function names and source locations for assertions.
    pub(crate) fn expected_symbols(&self) -> ExpectedSymbols<'_> {
        let function_names: Vec<&str> = self
            .symbols
            .keys()
            .filter(|name| *name != "main")
            .map(String::as_str)
            .collect();

        // DWARF stores full source paths (e.g. "/home/.../hello.c:12"),
        // so we check for "file:line" as a substring rather than
        // "func at file:line" which would fail against full paths.
        let source_locations: Vec<String> = self
            .symbols
            .iter()
            .filter(|(name, _)| *name != "main")
            .map(|(_, sym)| format!("{}:{}", sym.file, sym.line))
            .collect();

        ExpectedSymbols {
            function_names,
            source_locations,
        }
    }
}

/// Build a SessionPayload with user-space frames from a fixture entry.
///
/// Creates one trace per symbol, each with a single user frame pointing
/// at the symbol's file_offset. The mapping table references the
/// fixture's build_id.
pub(crate) fn build_user_payload(
    fixture_name: &str,
    entry: &FixtureEntry,
) -> proto::SessionPayload {
    let build_id_bytes = decode_build_id(&entry.build_id_hex);

    let mappings = vec![proto::Mapping {
        build_id: build_id_bytes,
    }];

    let traces: Vec<proto::CountedTrace> = entry
        .symbols
        .values()
        .map(|sym| proto::CountedTrace {
            trace: Some(proto::StackTrace {
                kernel_frames: vec![],
                user_frames: vec![proto::UserFrame {
                    frame: Some(proto::user_frame::Frame::Resolved(proto::ResolvedFrame {
                        mapping_index: 0,
                        file_offset: sym.file_offset,
                    })),
                }],
            }),
            on_cpu_count: 1,
            off_cpu_count: 0,
        })
        .collect();

    let total_samples = traces.len() as u64;

    proto::SessionPayload {
        session_id: format!("e2e-user-{fixture_name}"),
        source: Some(proto::CaptureSource {
            source: Some(proto::capture_source::Source::Psi(proto::PsiTrigger {
                resource: proto::PsiResourceType::Cpu as i32,
            })),
        }),
        metadata: Some(proto::Metadata {
            pid: 12345,
            comm: format!("e2e-{fixture_name}"),
            kernel_meta: Some(proto::KernelMeta {
                release: "e2e-test".into(),
                build_id: vec![0; 20],
                text_addr: 0,
            }),
        }),
        traces,
        total_samples,
        capture_duration: Some(prost_types::Duration {
            seconds: 1,
            nanos: 0,
        }),
        sample_period_nanos: 1_000_000_000 / 19,
        mappings,
    }
}

/// Build a SessionPayload with kernel frames from real host addresses.
///
/// Uses the host's actual kernel build_id and _text address so the
/// symbolizer can fetch vmlinux via debuginfod federation and resolve
/// the frames.
pub(crate) fn build_kernel_payload(kernel: &HostKernelMeta) -> proto::SessionPayload {
    let kernel_frames: Vec<u64> = kernel.known_symbols.iter().map(|sym| sym.addr).collect();

    let traces = vec![proto::CountedTrace {
        trace: Some(proto::StackTrace {
            kernel_frames,
            user_frames: vec![],
        }),
        on_cpu_count: 1,
        off_cpu_count: 0,
    }];

    proto::SessionPayload {
        session_id: "e2e-kernel-frames".into(),
        source: Some(proto::CaptureSource {
            source: Some(proto::capture_source::Source::Psi(proto::PsiTrigger {
                resource: proto::PsiResourceType::Cpu as i32,
            })),
        }),
        metadata: Some(proto::Metadata {
            pid: 0,
            comm: "kernel".into(),
            kernel_meta: Some(proto::KernelMeta {
                release: kernel.release.clone(),
                build_id: kernel.build_id.clone(),
                text_addr: kernel.text_addr,
            }),
        }),
        traces,
        total_samples: 1,
        capture_duration: Some(prost_types::Duration {
            seconds: 1,
            nanos: 0,
        }),
        sample_period_nanos: 1_000_000_000 / 19,
        mappings: vec![],
    }
}
