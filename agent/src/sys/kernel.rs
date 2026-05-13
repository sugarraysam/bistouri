use std::fs;
use std::io::{self, Read};
use std::path::Path;

use thiserror::Error;

/// Size of a GNU build ID in bytes (SHA-1 hash).
const BUILD_ID_SIZE: usize = bistouri_sys::kernel::BUILD_ID_SIZE;

#[derive(Error, Debug)]
pub(crate) enum KernelMetaError {
    #[error("failed to read {path}: {source}")]
    Read {
        path: &'static str,
        #[source]
        source: io::Error,
    },

    #[error(
        "GNU build ID (NT_GNU_BUILD_ID) not found in /sys/kernel/notes — \
         kernel may not have been built with CONFIG_BUILD_ID"
    )]
    BuildIdNotFound,

    #[error(
        "_text symbol not found in {path} — cannot determine KASLR base. \
         Ensure /proc/kallsyms is readable and the kernel exports _text"
    )]
    KallsymsTextNotFound { path: String },

    #[error(
        "KASLR base address is zero — /proc/kallsyms is restricted by \
         kptr_restrict. Set kernel.kptr_restrict=0 \
         (sysctl -w kernel.kptr_restrict=0) or ensure bistouri runs \
         with CAP_SYSLOG"
    )]
    KptrRestricted,
}

/// Host kernel metadata collected once at startup.
///
/// Carried through to every `FinalizedSession` for remote symbolization.
/// The symbolizer uses these fields to resolve raw kernel instruction
/// pointers into function names:
///
/// 1. `build_id` → match the correct `vmlinux` debuginfo binary
/// 2. `text_addr` → compute vmlinux-relative addresses from raw IPs
/// 3. `release` → human-readable secondary key / fallback for symbol lookup
#[derive(Debug, Clone)]
pub(crate) struct KernelMeta {
    /// 20-byte GNU build ID parsed from `/sys/kernel/notes`.
    pub build_id: [u8; BUILD_ID_SIZE],
    /// Runtime virtual address of the kernel's `_text` symbol, read from
    /// `/proc/kallsyms`. Under KASLR this is randomized at each boot.
    /// The symbolizer computes vmlinux-relative addresses as:
    ///   `vmlinux_vaddr = raw_ip - text_addr + vmlinux_static_text`
    pub text_addr: u64,
    /// Kernel release string (e.g. `6.8.0-40-generic`).
    pub release: String,
}

impl KernelMeta {
    /// Collects all kernel metadata from procfs/sysfs.
    ///
    /// This performs synchronous file I/O — call from `spawn_blocking`
    /// during startup. All paths use the host's filesystem directly
    /// (not proc_path) because `/sys/kernel/notes` and
    /// `/proc/sys/kernel/osrelease` are host-global and not
    /// namespace-affected.
    pub(crate) fn collect() -> Result<Self, KernelMetaError> {
        let build_id = Self::read_build_id()?;
        let text_addr = Self::read_text_addr(Path::new("/proc/kallsyms"))?;
        let release = Self::read_release()?;

        Ok(Self {
            build_id,
            text_addr,
            release,
        })
    }

    /// Parses the kernel's GNU build ID from `/sys/kernel/notes`.
    ///
    /// The file contains raw concatenated ELF note sections (not a full
    /// ELF binary). Each note has the layout:
    ///
    /// ```text
    /// ┌──────────┬──────────┬──────────┐
    /// │ n_namesz │ n_descsz │  n_type  │  (3 × u32 = 12 bytes)
    /// ├──────────┴──────────┴──────────┤
    /// │  name (n_namesz bytes, padded  │
    /// │  to 4-byte alignment)          │
    /// ├────────────────────────────────┤
    /// │  desc (n_descsz bytes, padded  │
    /// │  to 4-byte alignment)          │
    /// └────────────────────────────────┘
    /// ```
    ///
    /// We walk notes until `n_type == NT_GNU_BUILD_ID` and name == "GNU".
    fn read_build_id() -> Result<[u8; BUILD_ID_SIZE], KernelMetaError> {
        let mut file = fs::File::open("/sys/kernel/notes").map_err(|e| KernelMetaError::Read {
            path: "/sys/kernel/notes",
            source: e,
        })?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|e| KernelMetaError::Read {
                path: "/sys/kernel/notes",
                source: e,
            })?;

        bistouri_sys::kernel::parse_build_id_from_notes(&data)
            .ok_or(KernelMetaError::BuildIdNotFound)
    }

    /// Reads the runtime `_text` address from `/proc/kallsyms`.
    /// Format: `<hex_addr> <type> <name>`.
    fn read_text_addr(kallsyms_path: &Path) -> Result<u64, KernelMetaError> {
        let contents = fs::read_to_string(kallsyms_path).map_err(|e| KernelMetaError::Read {
            path: "/proc/kallsyms",
            source: e,
        })?;

        Self::parse_kaslr_from_kallsyms(&contents, kallsyms_path)
    }

    /// Parses the `_text` address from kallsyms content.
    /// Extracted for testability.
    fn parse_kaslr_from_kallsyms(contents: &str, path: &Path) -> Result<u64, KernelMetaError> {
        // parse_text_addr returns None for both "not found" and "zero address"
        // (kptr_restrict). Distinguish by checking for the symbol presence.
        if let Some(addr) = bistouri_sys::kernel::parse_text_addr(contents) {
            return Ok(addr);
        }

        // Determine whether _text is absent or has a zero address.
        for line in contents.lines() {
            let mut parts = line.split_whitespace();
            let _addr_hex = parts.next();
            let _sym_type = parts.next();
            if parts.next() == Some("_text") {
                return Err(KernelMetaError::KptrRestricted);
            }
        }

        Err(KernelMetaError::KallsymsTextNotFound {
            path: path.display().to_string(),
        })
    }

    /// Reads the kernel release string from procfs.
    fn read_release() -> Result<String, KernelMetaError> {
        let release = fs::read_to_string("/proc/sys/kernel/osrelease").map_err(|e| {
            KernelMetaError::Read {
                path: "/proc/sys/kernel/osrelease",
                source: e,
            }
        })?;
        Ok(release.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const NT_GNU_BUILD_ID: u32 = 3;
    const GNU_NOTE_NAME: &[u8] = b"GNU\0";

    /// Builds a synthetic ELF note in native byte order.
    fn make_note(name: &[u8], desc: &[u8], n_type: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&(desc.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&n_type.to_ne_bytes());

        buf.extend_from_slice(name);
        let name_pad = bistouri_sys::kernel::align4(name.len()) - name.len();
        buf.extend(std::iter::repeat_n(0u8, name_pad));

        buf.extend_from_slice(desc);
        let desc_pad = bistouri_sys::kernel::align4(desc.len()) - desc.len();
        buf.extend(std::iter::repeat_n(0u8, desc_pad));

        buf
    }

    // -------------------------------------------------------------------
    // ELF note parsing — success cases (delegates to bistouri_sys)
    // -------------------------------------------------------------------

    #[rstest]
    #[case::single_gnu_note(
        make_note(GNU_NOTE_NAME, &[0xAB; BUILD_ID_SIZE], NT_GNU_BUILD_ID),
        [0xAB; BUILD_ID_SIZE],
        "single GNU build-id note"
    )]
    #[case::skips_non_matching_notes(
        {
            let mut d = make_note(b"Linux\0\0\0", &[1, 2, 3, 4], 42);
            d.extend(make_note(GNU_NOTE_NAME, &[0xCD; BUILD_ID_SIZE], NT_GNU_BUILD_ID));
            d
        },
        [0xCD; BUILD_ID_SIZE],
        "skips non-GNU note, finds build-id second"
    )]
    fn build_id_success(
        #[case] data: Vec<u8>,
        #[case] expected: [u8; BUILD_ID_SIZE],
        #[case] description: &str,
    ) {
        let result = bistouri_sys::kernel::parse_build_id_from_notes(&data).unwrap();
        assert_eq!(result, expected, "{description}");
    }

    // -------------------------------------------------------------------
    // ELF note parsing — failure cases
    // -------------------------------------------------------------------

    #[rstest]
    #[case::empty_input(vec![], "empty data yields not-found")]
    #[case::wrong_note_type(
        make_note(GNU_NOTE_NAME, &[0u8; BUILD_ID_SIZE], 99),
        "GNU name but wrong n_type"
    )]
    #[case::wrong_desc_size(
        make_note(GNU_NOTE_NAME, &[0u8; 16], NT_GNU_BUILD_ID),
        "correct type but 16-byte desc instead of 20"
    )]
    fn build_id_failure(#[case] data: Vec<u8>, #[case] description: &str) {
        assert!(
            bistouri_sys::kernel::parse_build_id_from_notes(&data).is_none(),
            "{description}"
        );
    }

    // -------------------------------------------------------------------
    // kallsyms parsing — success cases
    // -------------------------------------------------------------------

    #[rstest]
    #[case::standard_text(
        "ffffffff81000000 T _text\nffffffff81000010 T startup_64",
        0xffffffff81000000
    )]
    #[case::lowercase_type("ffffffff82000000 t _text\n", 0xffffffff82000000)]
    #[case::text_not_first_line(
        "ffffffff81000000 T other_sym\nffffffff82abcdef T _text\n",
        0xffffffff82abcdef
    )]
    fn kallsyms_success(#[case] contents: &str, #[case] expected: u64) {
        let result =
            KernelMeta::parse_kaslr_from_kallsyms(contents, Path::new("/proc/kallsyms")).unwrap();
        assert_eq!(result, expected);
    }

    // -------------------------------------------------------------------
    // kallsyms parsing — failure cases
    // -------------------------------------------------------------------

    #[rstest]
    #[case::text_not_found(
        "ffffffff81000000 T startup_64\n",
        "KallsymsTextNotFound",
        "_text absent from kallsyms"
    )]
    #[case::kptr_restricted(
        "0000000000000000 T _text\n",
        "KptrRestricted",
        "zero address indicates kptr_restrict"
    )]
    fn kallsyms_failure(
        #[case] contents: &str,
        #[case] expected_variant: &str,
        #[case] description: &str,
    ) {
        let err = KernelMeta::parse_kaslr_from_kallsyms(contents, Path::new("/proc/kallsyms"))
            .unwrap_err();
        let variant_name = format!("{err:?}");
        assert!(
            variant_name.starts_with(expected_variant),
            "{description}: expected {expected_variant}, got {variant_name}",
        );
    }

    // -------------------------------------------------------------------
    // align4 (delegated to bistouri_sys)
    // -------------------------------------------------------------------

    #[rstest]
    #[case::zero(0, 0)]
    #[case::one(1, 4)]
    #[case::three(3, 4)]
    #[case::four(4, 4)]
    #[case::five(5, 8)]
    #[case::eight(8, 8)]
    fn align4_cases(#[case] input: usize, #[case] expected: usize) {
        assert_eq!(bistouri_sys::kernel::align4(input), expected);
    }
}
