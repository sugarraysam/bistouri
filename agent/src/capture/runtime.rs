//! Go runtime detection via ELF section scan.
//!
//! Probes `/proc/<pid>/exe` for Go-specific ELF sections (`.go.buildid`,
//! `.gopclntab`). Must be called from `spawn_blocking` — reads from procfs.
//!
//! Called once per process at trigger time (PSI rule match), not per
//! `CaptureSession`. The result is cached in the `CaptureRequest`.

use bistouri_api::runtime::GO_SECTION_MARKERS;
use bistouri_api::v1::RuntimeHint;
use std::path::Path;
use tracing::debug;

/// Detects the runtime of a running process by scanning its ELF binary
/// for Go-specific section headers.
///
/// # Arguments
/// * `pid` — target process ID
/// * `proc_path` — root of procfs (e.g. `/proc`)
///
/// Returns `RuntimeHint::Go` if any Go marker section is found,
/// `RuntimeHint::Native` otherwise. On any I/O or parse error,
/// conservatively returns `RuntimeHint::Native`.
pub(crate) fn detect_runtime(pid: u32, proc_path: &Path) -> RuntimeHint {
    let exe_path = proc_path.join(format!("{pid}/exe"));
    match detect_runtime_from_path(&exe_path) {
        Ok(hint) => {
            debug!(pid, hint = ?hint, "runtime detected");
            hint
        }
        Err(e) => {
            debug!(pid, error = %e, "runtime detection failed, defaulting to native");
            RuntimeHint::Native
        }
    }
}

/// Detects the runtime from an ELF binary at the given path.
///
/// Separated from `detect_runtime` for testability — tests can pass
/// arbitrary paths without a live `/proc`.
fn detect_runtime_from_path(path: &Path) -> std::io::Result<RuntimeHint> {
    let data = std::fs::read(path)?;
    Ok(detect_runtime_from_bytes(&data))
}

/// Detects Go runtime from raw ELF bytes by scanning section headers.
///
/// Pure function for unit testing without filesystem access.
pub(crate) fn detect_runtime_from_bytes(data: &[u8]) -> RuntimeHint {
    use object::Object;

    let Ok(elf) = object::read::File::parse(data) else {
        return RuntimeHint::Native;
    };

    use object::ObjectSection;
    for section in elf.sections() {
        let Ok(name) = section.name() else {
            continue;
        };
        if GO_SECTION_MARKERS.contains(&name) {
            return RuntimeHint::Go;
        }
    }

    RuntimeHint::Native
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // ── detect_runtime_from_bytes — rstest table ────────────────────

    #[rstest]
    #[case::empty_input(&[], RuntimeHint::Native, "empty bytes → native")]
    #[case::garbage_input(&[0xDE, 0xAD], RuntimeHint::Native, "garbage → native")]
    fn detect_runtime_invalid_input(
        #[case] data: &[u8],
        #[case] expected: RuntimeHint,
        #[case] description: &str,
    ) {
        assert_eq!(
            detect_runtime_from_bytes(data) as i32,
            expected as i32,
            "{description}",
        );
    }

    /// Test with the real C fixture binary — should detect as Native.
    #[test]
    fn c_fixture_detected_as_native() {
        let fixture_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../symbolizer/tests/e2e/fixtures/bin/hello");
        if !fixture_dir.exists() {
            // Skip if fixture not available (e.g. clean build)
            return;
        }
        let data = std::fs::read(&fixture_dir).unwrap();
        assert_eq!(
            detect_runtime_from_bytes(&data) as i32,
            RuntimeHint::Native as i32,
            "C fixture should be detected as Native",
        );
    }

    #[test]
    fn nonexistent_pid_returns_native() {
        let hint = detect_runtime(u32::MAX, Path::new("/proc"));
        assert_eq!(hint as i32, RuntimeHint::Native as i32);
    }

    /// Test with the real Go fixture binary — should detect as Go.
    #[test]
    fn go_fixture_detected_as_go() {
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../symbolizer/tests/e2e/fixtures/bin/hello_go");
        if !fixture_path.exists() {
            return;
        }
        let data = std::fs::read(&fixture_path).unwrap();
        assert_eq!(
            detect_runtime_from_bytes(&data) as i32,
            RuntimeHint::Go as i32,
            "Go fixture should be detected as Go",
        );
    }

    /// Stripped Go binaries must still be detected as Go.
    ///
    /// `strip --strip-all` removes .debug_* and .symtab but preserves:
    ///   - `.note.go.buildid` (PT_NOTE segment — metadata, not debug)
    ///   - `.gopclntab` (PT_LOAD — Go runtime reads this at startup)
    ///
    /// Both are Go marker sections checked by `detect_runtime_from_bytes`.
    #[test]
    fn stripped_go_fixture_detected_as_go() {
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../symbolizer/tests/e2e/fixtures/bin/hello_go_stripped");
        if !fixture_path.exists() {
            // Skip if stripped fixture not built.
            return;
        }
        let data = std::fs::read(&fixture_path).unwrap();
        assert_eq!(
            detect_runtime_from_bytes(&data) as i32,
            RuntimeHint::Go as i32,
            "stripped Go binary should still be detected as Go \
             (.note.go.buildid and .gopclntab survive stripping)",
        );
    }
}
