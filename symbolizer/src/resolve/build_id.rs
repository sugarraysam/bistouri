//! Shared build ID utilities.
//!
//! GNU build IDs are 20-byte SHA-1 hashes that content-address an ELF binary.
//! The same `build_id` always maps to the same binary contents, regardless
//! of which host loaded it — this is what makes centralized symbolization
//! work across fleets.

/// Size of a GNU build ID in bytes (SHA-1).
pub(crate) const BUILD_ID_SIZE: usize = 20;

/// Fixed-size build ID type alias.
pub(crate) type BuildId = [u8; BUILD_ID_SIZE];

/// Tries to convert a byte slice into a fixed-size build ID reference.
///
/// Returns `None` if the slice length doesn't match `BUILD_ID_SIZE`.
#[inline]
pub(crate) fn try_from_slice(bytes: &[u8]) -> Option<&BuildId> {
    bytes.try_into().ok()
}

/// Encodes a build ID as a lowercase hex string (40 chars) for debuginfod URLs.
#[inline]
pub(crate) fn to_hex(build_id: &BuildId) -> String {
    let mut buf = vec![0u8; BUILD_ID_SIZE * 2];
    faster_hex::hex_encode(build_id, &mut buf).expect("buffer is correctly sized");
    // SAFETY: hex_encode produces valid ASCII which is valid UTF-8.
    unsafe { String::from_utf8_unchecked(buf) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::all_zeros([0u8; 20], "0000000000000000000000000000000000000000")]
    #[case::mixed_bytes(
        [0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
         0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01],
        "abcdef0123456789abcdef0123456789abcdef01"
    )]
    #[case::all_ff([0xFF; 20], "ffffffffffffffffffffffffffffffffffffffff")]
    fn hex_encoding(#[case] build_id: BuildId, #[case] expected: &str) {
        assert_eq!(to_hex(&build_id), expected);
    }

    #[rstest]
    #[case::correct_20_bytes(&[0xAAu8; 20] as &[u8], true)]
    #[case::too_short_16(&[0xAAu8; 16] as &[u8], false)]
    #[case::too_long_24(&[0xAAu8; 24] as &[u8], false)]
    #[case::empty(&[] as &[u8], false)]
    fn try_from_slice_validation(#[case] input: &[u8], #[case] expected_some: bool) {
        assert_eq!(try_from_slice(input).is_some(), expected_some);
    }
}
