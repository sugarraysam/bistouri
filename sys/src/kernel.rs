//! Kernel metadata parsing utilities.
//!
//! Pure functions that operate on raw data — no I/O, no error types.
//! Consumers read files and wrap results in their own error types.
//!
//! # ELF note format
//!
//! `/sys/kernel/notes` contains raw concatenated ELF note sections:
//!
//! ```text
//! ┌──────────┬──────────┬──────────┐
//! │ n_namesz │ n_descsz │  n_type  │  (3 × u32 = 12 bytes)
//! ├──────────┴──────────┴──────────┤
//! │  name (n_namesz bytes, padded  │
//! │  to 4-byte alignment)          │
//! ├────────────────────────────────┤
//! │  desc (n_descsz bytes, padded  │
//! │  to 4-byte alignment)          │
//! └────────────────────────────────┘
//! ```
//!
//! # kallsyms format
//!
//! `/proc/kallsyms` lines: `<hex_addr> <type> <name> [module]`

/// Size of a GNU build ID in bytes (SHA-1 hash).
pub const BUILD_ID_SIZE: usize = 20;

/// Fixed-size build ID type — 20-byte SHA-1 hash, `Copy`, no heap allocation.
pub type BuildId = [u8; BUILD_ID_SIZE];

/// ELF note type for GNU build ID (`NT_GNU_BUILD_ID`).
const NT_GNU_BUILD_ID: u32 = 3;

/// ELF note owner name for GNU notes.
const GNU_NOTE_NAME: &[u8] = b"GNU\0";

/// Rounds up to the nearest 4-byte boundary (ELF note alignment).
#[inline]
pub fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Parses a GNU build ID from raw ELF note data.
///
/// Walks concatenated ELF notes looking for `NT_GNU_BUILD_ID` with
/// owner name `"GNU\0"`. Returns `None` if no matching note is found
/// or if the descriptor length doesn't match `BUILD_ID_SIZE`.
///
/// # Arguments
/// * `data` — raw bytes from `/sys/kernel/notes`
pub fn parse_build_id_from_notes(data: &[u8]) -> Option<BuildId> {
    let mut offset = 0;

    while offset + 12 <= data.len() {
        let n_namesz = u32::from_ne_bytes(data[offset..offset + 4].try_into().ok()?) as usize;
        let n_descsz = u32::from_ne_bytes(data[offset + 4..offset + 8].try_into().ok()?) as usize;
        let n_type = u32::from_ne_bytes(data[offset + 8..offset + 12].try_into().ok()?) as usize;

        let name_start = offset + 12;
        let name_padded = align4(n_namesz);
        let desc_start = name_start + name_padded;
        let desc_padded = align4(n_descsz);

        if desc_start + n_descsz > data.len() {
            break;
        }

        let name = &data[name_start..name_start + n_namesz];

        if n_type == NT_GNU_BUILD_ID as usize && name == GNU_NOTE_NAME && n_descsz == BUILD_ID_SIZE
        {
            let mut build_id = [0u8; BUILD_ID_SIZE];
            build_id.copy_from_slice(&data[desc_start..desc_start + BUILD_ID_SIZE]);
            return Some(build_id);
        }

        offset = desc_start + desc_padded;
    }

    None
}

/// Parses the `_text` symbol address from kallsyms content.
///
/// Returns the KASLR-randomized runtime address of `_text`, or `None`
/// if the symbol isn't found. Returns `None` if the address is zero
/// (indicates `kptr_restrict` is active).
///
/// # Arguments
/// * `content` — full text content of `/proc/kallsyms`
pub fn parse_text_addr(content: &str) -> Option<u64> {
    parse_symbol_addr(content, "_text")
}

/// Parses a named symbol's address from kallsyms content.
///
/// Format: `<hex_addr> <type> <name> [module]`
///
/// Returns `None` if the symbol isn't found or if its address is zero
/// (zero addresses indicate `kptr_restrict` is active).
///
/// # Arguments
/// * `content` — full text content of `/proc/kallsyms`
/// * `name` — symbol name to search for (e.g. `"_text"`, `"schedule"`)
pub fn parse_symbol_addr(content: &str, name: &str) -> Option<u64> {
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let addr_hex = parts.next()?;
        let _sym_type = parts.next();
        let sym_name = parts.next()?;

        if sym_name == name {
            let addr = u64::from_str_radix(addr_hex, 16).ok()?;
            if addr == 0 {
                return None;
            }
            return Some(addr);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Builds a synthetic ELF note in native byte order.
    fn make_note(name: &[u8], desc: &[u8], n_type: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&(desc.len() as u32).to_ne_bytes());
        buf.extend_from_slice(&n_type.to_ne_bytes());

        buf.extend_from_slice(name);
        let name_pad = align4(name.len()) - name.len();
        buf.extend(std::iter::repeat_n(0u8, name_pad));

        buf.extend_from_slice(desc);
        let desc_pad = align4(desc.len()) - desc.len();
        buf.extend(std::iter::repeat_n(0u8, desc_pad));

        buf
    }

    // -------------------------------------------------------------------
    // ELF note parsing — success cases
    // -------------------------------------------------------------------

    #[rstest]
    #[case::single_gnu_note(
        make_note(GNU_NOTE_NAME, &[0xAB; BUILD_ID_SIZE], NT_GNU_BUILD_ID),
        Some([0xAB; BUILD_ID_SIZE]),
        "single GNU build-id note"
    )]
    #[case::skips_non_matching_notes(
        {
            let mut d = make_note(b"Linux\0\0\0", &[1, 2, 3, 4], 42);
            d.extend(make_note(GNU_NOTE_NAME, &[0xCD; BUILD_ID_SIZE], NT_GNU_BUILD_ID));
            d
        },
        Some([0xCD; BUILD_ID_SIZE]),
        "skips non-GNU note, finds build-id second"
    )]
    #[case::empty_input(vec![], None, "empty data yields None")]
    #[case::wrong_note_type(
        make_note(GNU_NOTE_NAME, &[0u8; BUILD_ID_SIZE], 99),
        None,
        "GNU name but wrong n_type"
    )]
    #[case::wrong_desc_size(
        make_note(GNU_NOTE_NAME, &[0u8; 16], NT_GNU_BUILD_ID),
        None,
        "correct type but 16-byte desc instead of 20"
    )]
    fn build_id_parsing(
        #[case] data: Vec<u8>,
        #[case] expected: Option<BuildId>,
        #[case] description: &str,
    ) {
        assert_eq!(parse_build_id_from_notes(&data), expected, "{description}");
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
    fn text_addr_success(#[case] content: &str, #[case] expected: u64) {
        assert_eq!(parse_text_addr(content), Some(expected));
    }

    // -------------------------------------------------------------------
    // kallsyms parsing — failure cases
    // -------------------------------------------------------------------

    #[rstest]
    #[case::text_not_found("ffffffff81000000 T startup_64\n", "_text absent from kallsyms")]
    #[case::kptr_restricted("0000000000000000 T _text\n", "zero address indicates kptr_restrict")]
    fn text_addr_failure(#[case] content: &str, #[case] description: &str) {
        assert!(parse_text_addr(content).is_none(), "{description}");
    }

    // -------------------------------------------------------------------
    // parse_symbol_addr — named symbol lookup
    // -------------------------------------------------------------------

    #[rstest]
    #[case::schedule(
        "ffffffff81000000 T _text\nffffffff81100000 T schedule\n",
        "schedule",
        Some(0xffffffff81100000)
    )]
    #[case::not_found("ffffffff81000000 T _text\n", "nonexistent", None)]
    #[case::zero_is_none("0000000000000000 T schedule\n", "schedule", None)]
    fn symbol_addr_lookup(
        #[case] content: &str,
        #[case] name: &str,
        #[case] expected: Option<u64>,
    ) {
        assert_eq!(parse_symbol_addr(content, name), expected);
    }

    // -------------------------------------------------------------------
    // align4
    // -------------------------------------------------------------------

    #[rstest]
    #[case::zero(0, 0)]
    #[case::one(1, 4)]
    #[case::three(3, 4)]
    #[case::four(4, 4)]
    #[case::five(5, 8)]
    #[case::eight(8, 8)]
    fn align4_cases(#[case] input: usize, #[case] expected: usize) {
        assert_eq!(align4(input), expected);
    }
}
