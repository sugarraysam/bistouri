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

        // Walk ELF notes: each is { u32 namesz, u32 descsz, u32 type, name[], desc[] }
        let mut offset = 0;
        while offset + 12 <= data.len() {
            let namesz = u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
            let descsz =
                u32::from_ne_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;
            let ntype = u32::from_ne_bytes(data[offset + 8..offset + 12].try_into().unwrap());

            let name_start = offset + 12;
            let name_padded = (namesz + 3) & !3;
            let desc_start = name_start + name_padded;
            let desc_padded = (descsz + 3) & !3;

            if desc_start + descsz > data.len() {
                break;
            }

            let name = &data[name_start..name_start + namesz];

            // NT_GNU_BUILD_ID = 3, name = "GNU\0"
            if ntype == 3 && name == b"GNU\0" {
                return Ok(data[desc_start..desc_start + descsz].to_vec());
            }

            offset = desc_start + desc_padded;
        }

        Err(E2eError::KernelMeta(
            "GNU build ID not found in /sys/kernel/notes".into(),
        ))
    }

    /// Read _text address and known function addresses from /proc/kallsyms.
    fn read_kallsyms() -> Result<(u64, Vec<KernelSymbol>), E2eError> {
        let contents = std::fs::read_to_string("/proc/kallsyms")
            .map_err(|e| E2eError::KernelMeta(format!("reading /proc/kallsyms: {e}")))?;

        let mut text_addr: Option<u64> = None;
        let mut symbols = Vec::new();

        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            let addr_hex = match parts.next() {
                Some(a) => a,
                None => continue,
            };
            let _sym_type = parts.next();
            let sym_name = match parts.next() {
                Some(n) => n,
                None => continue,
            };

            let addr = u64::from_str_radix(addr_hex, 16).unwrap_or(0);

            if sym_name == "_text" {
                if addr == 0 {
                    return Err(E2eError::KernelMeta(
                        "_text address is 0 — kptr_restrict is active. \
                         Run with sudo or set kernel.kptr_restrict=0"
                            .into(),
                    ));
                }
                text_addr = Some(addr);
            }

            if TARGET_SYMBOLS.contains(&sym_name) && addr != 0 {
                symbols.push(KernelSymbol {
                    name: sym_name.to_string(),
                    addr,
                });
            }
        }

        let text_addr = text_addr.ok_or_else(|| {
            E2eError::KernelMeta("_text symbol not found in /proc/kallsyms".into())
        })?;

        Ok((text_addr, symbols))
    }

    /// Read the kernel release string.
    fn read_release() -> Result<String, E2eError> {
        let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|e| E2eError::KernelMeta(format!("reading osrelease: {e}")))?;
        Ok(release.trim().to_string())
    }
}
