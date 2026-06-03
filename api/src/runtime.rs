//! Runtime-aware DWARF section resolution.
//!
//! Each [`RuntimeHint`] maps to a static set of [`DwarfSection`]s that the
//! symbolizer must load for addr2line resolution. Go binaries use legacy
//! zlib-compressed `.zdebug_*` section names; native (C/C++/Rust) binaries
//! use standard `.debug_*` names.
//!
//! Defined in the API crate so both agent and symbolizer share the same
//! section resolution strategy without duplication.

use crate::v1::RuntimeHint;

/// Describes a DWARF section with its canonical name and possible aliases.
///
/// When loading DWARF sections from an ELF binary, the symbolizer tries
/// the canonical name first, then falls back to aliases in order. This
/// handles Go's legacy `.zdebug_*` compressed sections transparently.
#[derive(Debug, Clone, Copy)]
pub struct DwarfSection {
    /// Canonical section name (e.g. `.debug_info`).
    pub canonical: &'static str,
    /// Alternative section names to try, in order (e.g. `.zdebug_info`).
    pub aliases: &'static [&'static str],
}

/// Convenience macro: define a DwarfSection with canonical name and aliases.
macro_rules! dwarf_section {
    ($canonical:expr) => {
        DwarfSection {
            canonical: $canonical,
            aliases: &[],
        }
    };
    ($canonical:expr, $($alias:expr),+ $(,)?) => {
        DwarfSection {
            canonical: $canonical,
            aliases: &[$($alias),+],
        }
    };
}

// ── Native (C/C++/Rust) DWARF sections ──────────────────────────────

static NATIVE_SECTIONS: &[DwarfSection] = &[
    dwarf_section!(".debug_abbrev"),
    dwarf_section!(".debug_addr"),
    dwarf_section!(".debug_aranges"),
    dwarf_section!(".debug_info"),
    dwarf_section!(".debug_line"),
    dwarf_section!(".debug_line_str"),
    dwarf_section!(".debug_ranges"),
    dwarf_section!(".debug_rnglists"),
    dwarf_section!(".debug_str"),
    dwarf_section!(".debug_str_offsets"),
];

// ── Go DWARF sections ───────────────────────────────────────────────
//
// Go compresses DWARF sections using legacy zlib format (.zdebug_*).
// Starting with Go 1.22 some builds use SHF_COMPRESSED on standard
// .debug_* names instead. We try both: canonical first, zdebug alias
// second. The `object` crate's `uncompressed_data()` handles both
// compression formats transparently.

static GO_SECTIONS: &[DwarfSection] = &[
    dwarf_section!(".debug_abbrev", ".zdebug_abbrev"),
    dwarf_section!(".debug_addr", ".zdebug_addr"),
    dwarf_section!(".debug_aranges", ".zdebug_aranges"),
    dwarf_section!(".debug_info", ".zdebug_info"),
    dwarf_section!(".debug_line", ".zdebug_line"),
    dwarf_section!(".debug_line_str", ".zdebug_line_str"),
    dwarf_section!(".debug_ranges", ".zdebug_ranges"),
    dwarf_section!(".debug_rnglists", ".zdebug_rnglists"),
    dwarf_section!(".debug_str", ".zdebug_str"),
    dwarf_section!(".debug_str_offsets", ".zdebug_str_offsets"),
];

impl RuntimeHint {
    /// Returns the DWARF sections required for symbolization of binaries
    /// compiled with this runtime.
    ///
    /// The symbolizer uses this to determine which ELF sections to load
    /// and which aliases to try when the canonical name is absent.
    pub fn required_dwarf_sections(&self) -> &'static [DwarfSection] {
        match self {
            RuntimeHint::Go => GO_SECTIONS,
            // Native and Unspecified both use standard DWARF sections.
            RuntimeHint::Native | RuntimeHint::Unspecified => NATIVE_SECTIONS,
        }
    }

    /// Returns `true` if this section name (as found in an ELF binary)
    /// is required for symbolization under this runtime hint.
    ///
    /// Checks both canonical names and aliases.
    pub fn is_required_section(&self, name: &str) -> bool {
        self.required_dwarf_sections()
            .iter()
            .any(|s| s.canonical == name || s.aliases.contains(&name))
    }
}

impl DwarfSection {
    /// Returns an iterator over the canonical name followed by all aliases.
    /// The symbolizer should try names in this order when looking up
    /// sections in an ELF binary.
    pub fn names(&self) -> impl Iterator<Item = &'static str> {
        std::iter::once(self.canonical).chain(self.aliases.iter().copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::native_has_debug_info(RuntimeHint::Native, ".debug_info", true)]
    #[case::native_no_zdebug(RuntimeHint::Native, ".zdebug_info", false)]
    #[case::go_has_debug_info(RuntimeHint::Go, ".debug_info", true)]
    #[case::go_has_zdebug_info(RuntimeHint::Go, ".zdebug_info", true)]
    #[case::go_no_debug_frame(RuntimeHint::Go, ".debug_frame", false)]
    #[case::unspecified_uses_native(RuntimeHint::Unspecified, ".debug_info", true)]
    #[case::unspecified_no_zdebug(RuntimeHint::Unspecified, ".zdebug_info", false)]
    fn is_required_section(
        #[case] hint: RuntimeHint,
        #[case] section: &str,
        #[case] expected: bool,
    ) {
        assert_eq!(
            hint.is_required_section(section),
            expected,
            "hint={hint:?} section={section}",
        );
    }

    #[rstest]
    #[case::native(RuntimeHint::Native, 10)]
    #[case::go(RuntimeHint::Go, 10)]
    #[case::unspecified(RuntimeHint::Unspecified, 10)]
    fn section_count(#[case] hint: RuntimeHint, #[case] expected: usize) {
        assert_eq!(hint.required_dwarf_sections().len(), expected);
    }

    #[test]
    fn go_sections_have_zdebug_aliases() {
        for section in RuntimeHint::Go.required_dwarf_sections() {
            assert!(
                !section.aliases.is_empty(),
                "Go section {} should have at least one alias",
                section.canonical,
            );
            for alias in section.aliases {
                assert!(
                    alias.starts_with(".zdebug_"),
                    "Go alias {alias} should start with .zdebug_",
                );
            }
        }
    }

    #[test]
    fn native_sections_have_no_aliases() {
        for section in RuntimeHint::Native.required_dwarf_sections() {
            assert!(
                section.aliases.is_empty(),
                "Native section {} should have no aliases",
                section.canonical,
            );
        }
    }

    #[test]
    fn dwarf_section_names_iterator() {
        let section = dwarf_section!(".debug_info", ".zdebug_info");
        let names: Vec<_> = section.names().collect();
        assert_eq!(names, vec![".debug_info", ".zdebug_info"]);
    }

    #[test]
    fn dwarf_section_names_no_aliases() {
        let section = dwarf_section!(".debug_info");
        let names: Vec<_> = section.names().collect();
        assert_eq!(names, vec![".debug_info"]);
    }
}
