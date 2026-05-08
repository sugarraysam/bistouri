use libbpf_rs::MapCore;

use super::error::{CaptureError, Result};
use super::orchestrator::PidFilter;

/// Production `PidFilter` implementation wrapping a BPF `pid_filter_map` handle.
///
/// Uses `MapHandle` (duplicated fd) so it can be owned independently of the
/// `LoadedProfilerAgent` that created the original map.
pub(crate) struct BpfPidFilter {
    map_handle: libbpf_rs::MapHandle,
}

impl BpfPidFilter {
    pub(crate) fn new(map_handle: libbpf_rs::MapHandle) -> Self {
        Self { map_handle }
    }
}

impl PidFilter for BpfPidFilter {
    fn add_pid(&mut self, pid: u32) -> Result<()> {
        let active: u8 = 1;
        self.map_handle
            .update(
                &pid.to_ne_bytes(),
                &active.to_ne_bytes(),
                libbpf_rs::MapFlags::ANY,
            )
            .map_err(|e| CaptureError::PidFilterAdd { pid, source: e })
    }

    fn remove_pid(&mut self, pid: u32) -> Result<()> {
        self.map_handle
            .delete(&pid.to_ne_bytes())
            .map_err(|e| CaptureError::PidFilterRemove { pid, source: e })
    }
}
