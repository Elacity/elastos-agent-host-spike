//! The one text form of a package root that a manifest may pin.
//!
//! A package root is the CID of an ordinary UnixFS directory: CIDv1, dag-pb,
//! SHA-256. Its text is the multibase mark `b` followed by RFC 4648 base32 in
//! lowercase without padding, 59 characters in all. This module only checks
//! that form. It fetches nothing, hashes nothing and starts nothing.

const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The bytes every such CID starts with: version 1, dag-pb, sha2-256, and a
/// digest length of 32.
const ROOT_PREFIX: [u8; 4] = [0x01, 0x70, 0x12, 0x20];

/// The 32 digest bytes of `text`, if `text` is a package root in its one
/// spelling; `None` for anything else.
///
/// Decoded, the text must be [`ROOT_PREFIX`] and 32 bytes; and those bytes,
/// written again, must be the text. The second check is what refuses a second
/// spelling of the same bytes: a character more, or an unused low bit set in
/// the last character. A length and a prefix alone would accept those.
pub fn cid_form(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix('b')?;
    let bytes = decode_base32(digits)?;
    let digest: [u8; 32] = bytes.strip_prefix(&ROOT_PREFIX)?.try_into().ok()?;
    (encode_base32(&bytes) == digits).then_some(digest)
}

/// The bytes of base32 digits; `None` when a character is not in the
/// alphabet. Bits left over after the last whole byte are dropped here;
/// [`cid_form`] refuses a text that sets them, by writing the bytes again.
fn decode_base32(digits: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(digits.len() * 5 / 8);
    let (mut bits, mut held) = (0u32, 0u32);
    for character in digits.bytes() {
        let value = BASE32_ALPHABET.iter().position(|&one| one == character)?;
        bits = (bits << 5) | value as u32;
        held += 5;
        if held >= 8 {
            held -= 8;
            bytes.push((bits >> held) as u8);
        }
        bits &= (1 << held) - 1;
    }
    Some(bytes)
}

/// Base32 digits of `bytes`: lowercase, no padding, unused low bits zero.
fn encode_base32(bytes: &[u8]) -> String {
    let mut digits = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut bits, mut held) = (0u32, 0u32);
    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        held += 8;
        while held >= 5 {
            held -= 5;
            digits.push(BASE32_ALPHABET[((bits >> held) & 31) as usize] as char);
        }
        bits &= (1 << held) - 1;
    }
    if held > 0 {
        digits.push(BASE32_ALPHABET[((bits << (5 - held)) & 31) as usize] as char);
    }
    digits
}

#[cfg(test)]
mod tests {
    use super::cid_form;

    // Every vector is a constant this code did not print. Kubo 0.42.0 printed
    // VALID, CID_V0 and RAW_LEAF (`ipfs add --only-hash`) for a two-file
    // folder; the rest were derived from VALID with Python's base32.
    const VALID: &str = "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy";
    const VALID_DIGEST_HEX: &str =
        "44924ba2246c682beea12f0c7708682bbf1637f85d98e62cb2bd0d90cdb46196";

    #[test]
    fn a_package_root_is_accepted_and_gives_its_digest() {
        let digest = cid_form(VALID).expect("a dag-pb SHA-256 root in lowercase base32");
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, VALID_DIGEST_HEX);
    }

    #[test]
    fn anything_that_is_not_a_package_root_in_its_one_spelling_is_refused() {
        let accepted: Vec<&str> = [
            (
                "uppercase",
                "BAFYBEICESJF2EJDMNAV65IJPBR3QQ2BLX4LDP6C5TDTCZMV5BWIM3NDBSY",
            ),
            (
                "uppercase digits",
                "bAFYBEICESJF2EJDMNAV65IJPBR3QQ2BLX4LDP6C5TDTCZMV5BWIM3NDBSY",
            ),
            (
                "padding",
                "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy======",
            ),
            ("a CIDv0", "QmRWHs4rmfDXUo8SbBRcGZCfJBMYMo66ysSgD2wq88cp8i"),
            (
                "the raw codec",
                "bafkreiexeojjebb246sivqmgnpofipuzhepe3t5c656s34piqcdkr5doxa",
            ),
            (
                "another hash code at the right length",
                "bafybgicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy",
            ),
            (
                "one character short",
                "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbs",
            ),
            (
                "one character long",
                "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsya",
            ),
            (
                "an unused low bit set in the last character",
                "bafybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsz",
            ),
            (
                "a path separator",
                "bafybeicesjf2ejdmnav/5ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy",
            ),
            (
                "two dots",
                "bafybeicesjf2ejdmnav..ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy",
            ),
            (
                "no multibase mark",
                "afybeicesjf2ejdmnav65ijpbr3qq2blx4ldp6c5tdtczmv5bwim3ndbsy",
            ),
            ("the empty text", ""),
            ("the mark alone", "b"),
        ]
        .into_iter()
        .filter(|(_, text)| cid_form(text).is_some())
        .map(|(what, _)| what)
        .collect();
        assert_eq!(accepted, Vec::<&str>::new());
    }
}
