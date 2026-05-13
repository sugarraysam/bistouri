//! Host kernel metadata extraction for E2E kernel frame testing.
//!
//! Reads the running kernel's build ID, KASLR base address, and known
//! function addresses from procfs/sysfs. These are used to construct
//! SessionPayloads with real kernel instruction pointers that the
//! symbolizer can resolve via federated vmlinux from debuginfod.

use crate::error::E2eError;

/// Known kernel function addresses read from /proc/kallsyms.
#[derive(Debug)]
pub(crate) struct KernelSymbol {
    pub name: String,
    pub addr: u64,
}

/// Host kernel metadata for constructing E2E test payloads.
#[derive(Debug)]
pub(crate) struct HostKernelMeta {
    /// 20-byte GNU build ID from /sys/kernel/notes.
    pub build_id: Vec<u8>,
    /// Runtime _text address (KASLR base) from /proc/kallsyms.
    pub text_addr: u64,
    /// Kernel release string from /proc/sys/kernel/osrelease.
    pub release: String,
    /// Known kernel function addresses for constructing test payloads.
    pub known_symbols: Vec<KernelSymbol>,
}

/// Well-known kernel functions to look up in /proc/kallsyms.
/// These exist on virtually all Linux kernels.
const TARGET_SYMBOLS: &[&str] = &["schedule", "do_syscall_64", "sys_read"];

impl HostKernelMeta {
    /// Read kernel metadata from the host.
    ///
    /// Requires root or appropriate capabilities to read /proc/kallsyms
    /// with real addresses (kptr_restrict=0 or CAP_SYSLOG).
    pub(crate) fn read() -> Result<Self, E2eError> {
        let build_id = Self::read_build_id()?;
        let (text_addr, known_symbols) = Self::read_kallsyms()?;
        let release = Self::read_release()?;

        Ok(Self {
            build_id,
            text_addr,
            release,
            known_symbols,
        })
    }

    /// Parse the kernel's GNU build ID from /sys/kernel/notes.
    fn read_build_id() -> Result<Vec<u8>, E2eError> {
        let data = std::fs::read("/sys/kernel/notes")
            .map_err(|e| E2eError::KernelMeta(format!("reading /sys/kernel/notes: {e}")))?;

        bistouri_sys::kernel::parse_build_id_from_notes(&data)
            .map(|bid| bid.to_vec())
            .ok_or_else(|| {
                E2eError::KernelMeta("GNU build ID not found in /sys/kernel/notes".into())
            })
    }

    /// Read _text address and known function addresses from /proc/kallsyms.
    fn read_kallsyms() -> Result<(u64, Vec<KernelSymbol>), E2eError> {
        let contents = std::fs::read_to_string("/proc/kallsyms")
            .map_err(|e| E2eError::KernelMeta(format!("reading /proc/kallsyms: {e}")))?;

        let text_addr = bistouri_sys::kernel::parse_text_addr(&contents).ok_or_else(|| {
            E2eError::KernelMeta(
                "_text address is 0 or not found — kptr_restrict is active. \
                 Run with sudo or set kernel.kptr_restrict=0"
                    .into(),
            )
        })?;

        let symbols: Vec<KernelSymbol> = TARGET_SYMBOLS
            .iter()
            .filter_map(|name| {
                bistouri_sys::kernel::parse_symbol_addr(&contents, name).map(|addr| KernelSymbol {
                    name: (*name).to_string(),
                    addr,
                })
            })
            .collect();

        Ok((text_addr, symbols))
    }

    /// Read the kernel release string.
    fn read_release() -> Result<String, E2eError> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| E2eError::KernelMeta(format!("reading osrelease: {e}")))?;
        Ok(release.trim().to_string())
    }
}
