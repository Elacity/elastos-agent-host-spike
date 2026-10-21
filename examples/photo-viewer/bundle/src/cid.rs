//! CIDv1, raw codec (0x55), sha2-256 multihash, multibase base32 lower (`b`).

use sha2::{Digest, Sha256};

pub fn cid_v1_raw_sha256(bytes: &[u8]) -> String {
    let mut cid = vec![0x01, 0x55, 0x12, 0x20];
    cid.extend_from_slice(&Sha256::digest(bytes));
    format!("b{}", base32_lower(&cid))
}

/// RFC 4648 base32, lower case, no padding (multibase `b`).
fn base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "my"),
            ("fo", "mzxq"),
            ("foo", "mzxw6"),
            ("foob", "mzxw6yq"),
            ("fooba", "mzxw6ytb"),
            ("foobar", "mzxw6ytboi"),
        ] {
            assert_eq!(base32_lower(input.as_bytes()), expected);
        }
    }

    #[test]
    fn raw_cid_has_the_cidv1_sha256_prefix() {
        // Every CIDv1 raw sha2-256 in base32 starts "bafkrei".
        let cid = cid_v1_raw_sha256(b"hello");
        assert!(cid.starts_with("bafkrei"), "{cid}");
        // The well-known CID of "hello" as raw bytes.
        assert_eq!(
            cid,
            "bafkreibm6jg3ux5qumhcn2b3flc3tyu6dmlb4xa7u5bf44yegnrjhc4yeq"
        );
    }
}
