//! Content ceiling of a canonical principal-root envelope.
//!
//! The bound is the decoded ciphertext. The AES-GCM tag stays inside it.
//! A head the probe cannot parse keeps the old three-quarter ceiling.

use super::{parse_canonical_envelope_head, CanonicalHeadParse, CANONICAL_TAIL};

/// Decoded-byte ceiling of a no-pad base64 length. A length that is not
/// base64 counts itself, so the ceiling never sits under the ciphertext.
pub(super) fn base64_decoded_upper(len: u64) -> u64 {
    match len % 4 {
        0 => len / 4 * 3,
        2 => len / 4 * 3 + 1,
        3 => len / 4 * 3 + 2,
        _ => len,
    }
}

/// Content ceiling of a canonical envelope: the ciphertext only. The tag is
/// not subtracted. A head this probe cannot parse keeps the old three-quarter
/// ceiling, which is still at least the ciphertext.
pub(super) fn envelope_content_bound(file_len: u64, prefix: &[u8]) -> u64 {
    let CanonicalHeadParse::Complete(head) = parse_canonical_envelope_head(prefix) else {
        return file_len / 4 * 3;
    };
    let Some(b64_len) = file_len.checked_sub(head.len as u64 + CANONICAL_TAIL.len() as u64) else {
        return file_len / 4 * 3;
    };
    base64_decoded_upper(b64_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_quartet_decodes_to_three_and_a_bad_length_counts_itself() {
        assert_eq!(base64_decoded_upper(0), 0);
        assert_eq!(base64_decoded_upper(4), 3);
        assert_eq!(base64_decoded_upper(8), 6);
        assert_eq!(base64_decoded_upper(2), 1);
        assert_eq!(base64_decoded_upper(3), 2);
        assert_eq!(base64_decoded_upper(1), 1);
    }

    #[test]
    fn an_unparsed_head_keeps_the_three_quarter_ceiling() {
        assert_eq!(envelope_content_bound(100, b"not-an-envelope"), 75);
        assert_eq!(envelope_content_bound(3, b"x"), 0);
    }
}
