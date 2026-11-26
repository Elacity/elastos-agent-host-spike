//! Content ceiling of a canonical principal-root envelope.
//!
//! When the head parses, the bound is the decoded ciphertext with the
//! 16-byte AES-GCM tag taken off. A head the probe cannot parse keeps the
//! old three-quarter ceiling, and that ceiling does not take the tag off.

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

/// Content ceiling of a canonical envelope: the decoded ciphertext with the
/// 16-byte tag taken off. A head this probe cannot parse keeps the old
/// three-quarter ceiling, which is still at least the ciphertext.
pub(super) fn envelope_content_bound(file_len: u64, prefix: &[u8]) -> u64 {
    const TAG_LEN: u64 = 16;
    let CanonicalHeadParse::Complete(head) = parse_canonical_envelope_head(prefix) else {
        return file_len / 4 * 3;
    };
    let Some(b64_len) = file_len.checked_sub(head.len as u64 + CANONICAL_TAIL.len() as u64) else {
        return file_len / 4 * 3;
    };
    base64_decoded_upper(b64_len).saturating_sub(TAG_LEN)
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

    /// The canonical head, through the opening quote of `ciphertext`.
    fn canonical_prefix() -> Vec<u8> {
        let fields = [
            ("schema", "s"),
            ("principal_id", "p"),
            ("localhost_root", "r"),
            ("data_key_id", "k"),
            ("object_uri", "u"),
            ("cipher", "c"),
            ("nonce", "n"),
        ];
        let mut out = Vec::new();
        for (index, (name, value)) in fields.iter().enumerate() {
            if index == 0 {
                out.extend(format!("{{\n  \"{name}\": \"{value}").bytes());
            } else {
                out.extend(format!("\",\n  \"{name}\": \"{value}").bytes());
            }
        }
        out.extend(b"\",\n  \"ciphertext\": \"");
        out
    }

    #[test]
    fn a_canonical_head_takes_off_the_tag_and_an_older_head_does_not() {
        let prefix = canonical_prefix();
        assert!(matches!(
            parse_canonical_envelope_head(&prefix),
            CanonicalHeadParse::Complete(_)
        ));
        // 24 base64 chars decode to 18. The tag is 16 of those.
        let file_len = prefix.len() as u64 + 24 + CANONICAL_TAIL.len() as u64;
        assert_eq!(envelope_content_bound(file_len, &prefix), 2);
        assert_eq!(
            envelope_content_bound(file_len, b"not-an-envelope"),
            file_len / 4 * 3,
            "an older head keeps the three-quarter ceiling"
        );
    }
}
