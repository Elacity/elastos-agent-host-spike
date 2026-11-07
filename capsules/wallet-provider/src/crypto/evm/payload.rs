use serde_json::Value;
use sha3::{Digest, Keccak256};

pub(crate) fn payload_str<'a>(payload: &'a Value, field: &str) -> Result<&'a str, String> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("transaction intent missing {field}"))
}

pub(crate) fn payload_u64(payload: &Value, field: &str) -> Result<u64, String> {
    payload
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("transaction intent missing numeric {field}"))
}

pub(crate) fn payload_evm_address_bytes(payload: &Value, field: &str) -> Result<Vec<u8>, String> {
    let value = payload_str(payload, field)?;
    elastos_auth::validate_evm_address(value)?;
    hex_prefixed_bytes(value, Some(20), field)
}

pub(crate) fn payload_hex_bytes(payload: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex_prefixed_bytes(payload_str(payload, field)?, None, field)
}

pub(crate) fn payload_quantity_bytes(payload: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex_quantity_bytes(payload_str(payload, field)?, field)
}

pub(crate) fn hex_prefixed_bytes(
    value: &str,
    expected_bytes: Option<usize>,
    field: &str,
) -> Result<Vec<u8>, String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must start with 0x"))?;
    if raw.len() % 2 != 0 || !raw.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{field} must be even-length hex"));
    }
    if let Some(expected_bytes) = expected_bytes {
        if raw.len() != expected_bytes * 2 {
            return Err(format!("{field} must be {expected_bytes} bytes"));
        }
    }
    hex::decode(raw).map_err(|err| err.to_string())
}

pub(crate) fn hex_quantity_bytes(value: &str, field: &str) -> Result<Vec<u8>, String> {
    let raw = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("{field} must start with 0x"))?;
    if raw.is_empty() || !raw.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("{field} must be a hex quantity"));
    }
    if raw == "0" {
        return Ok(Vec::new());
    }
    if raw.len() > 1 && raw.starts_with('0') {
        return Err(format!("{field} must be a canonical hex quantity"));
    }
    let padded = if raw.len() % 2 == 0 {
        raw.to_string()
    } else {
        format!("0{raw}")
    };
    let bytes = hex::decode(padded).map_err(|err| err.to_string())?;
    Ok(trim_integer_bytes(&bytes).to_vec())
}

pub(crate) fn trim_integer_bytes(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte != 0) {
        Some(index) => &bytes[index..],
        None => &[],
    }
}

pub(crate) fn left_pad_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = bytes.len().min(32);
    out[32 - len..].copy_from_slice(&bytes[bytes.len() - len..]);
    out
}

pub(crate) fn keccak256_bytes(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// One test per refusal these readers raise, each asserting the whole `Err`
/// value. They pin answers the readers already give: they add no rule and
/// register no falsifier. They prove what the wallet provider answers a
/// transaction intent, not confinement: the Runtime decides whether the
/// provider runs.
///
/// Where the text carries a format argument, the test names the text this
/// input makes the code produce, not the template.
///
/// `{field} must start with 0x` stands at two sites, in `hex_prefixed_bytes`
/// (`:39`) and in `hex_quantity_bytes` (`:54`), so one test drives both.
/// `payload_evm_address_bytes`, `payload_hex_bytes` and `payload_quantity_bytes`
/// raise nothing of their own: they forward to these readers and to
/// `elastos_auth::validate_evm_address`, so they are exercised here rather than
/// pinned separately.
#[cfg(test)]
mod uf_payload_refusal_tests {
    use super::*;
    use serde_json::json;

    /// Falsifier: read a missing text field as the empty string, so a
    /// transaction intent with no sender reaches the address check as one.
    #[test]
    fn missing_text_field_is_refused() {
        assert_eq!(
            payload_str(&json!({ "to": "0x" }), "from").unwrap_err(),
            "transaction intent missing from"
        );
    }

    /// Falsifier: read a missing number field as zero, so a transaction intent
    /// with no chain id signs as chain 0.
    #[test]
    fn missing_numeric_field_is_refused() {
        assert_eq!(
            payload_u64(&json!({ "chain_id": "20" }), "chain_id").unwrap_err(),
            "transaction intent missing numeric chain_id"
        );
    }

    /// Both readers raise this string, so this one test holds both.
    ///
    /// Falsifier: strip a leading `0x` only when it is present, so a decimal
    /// value is read as hex with its high nibbles lost.
    #[test]
    fn value_without_prefix_is_refused() {
        let reason = "to must start with 0x";
        assert_eq!(hex_prefixed_bytes("1234", None, "to").unwrap_err(), reason);
        assert_eq!(hex_quantity_bytes("1234", "to").unwrap_err(), reason);
    }

    /// The guard has two conditions, an odd body length and a body with a
    /// character that is not a hex digit, and both raise this string.
    ///
    /// Falsifier: read an odd-length hex body by dropping its last nibble, so
    /// a truncated value signs as a different one.
    #[test]
    fn odd_length_hex_is_refused() {
        let reason = "data must be even-length hex";
        assert_eq!(
            hex_prefixed_bytes("0x123", None, "data").unwrap_err(),
            reason
        );
        assert_eq!(
            hex_prefixed_bytes("0x12zz", None, "data").unwrap_err(),
            reason
        );
    }

    /// The guard refuses a body of any length other than the expected one in
    /// bytes, and both directions raise this string: a short `to` and a long
    /// one.
    ///
    /// Falsifier: return the bytes of a short address, so a one-byte `to`
    /// reaches the RLP encoder as a valid recipient.
    #[test]
    fn short_fixed_bytes_value_is_refused() {
        let reason = "to must be 20 bytes";
        assert_eq!(
            hex_prefixed_bytes("0x1122", Some(20), "to").unwrap_err(),
            reason
        );
        assert_eq!(
            hex_prefixed_bytes(&format!("0x{}", "11".repeat(21)), Some(20), "to").unwrap_err(),
            reason
        );
    }

    /// The guard has two conditions, an empty body and a body with a
    /// character that is not a hex digit, and both raise this string.
    ///
    /// Falsifier: read an empty quantity body as zero, so a truncated nonce
    /// signs as the first transaction of the account.
    #[test]
    fn empty_hex_quantity_is_refused() {
        let reason = "nonce must be a hex quantity";
        assert_eq!(hex_quantity_bytes("0x", "nonce").unwrap_err(), reason);
        assert_eq!(hex_quantity_bytes("0xzz", "nonce").unwrap_err(), reason);
    }

    /// Falsifier: keep leading zeros, so the same quantity has several byte
    /// encodings and two different intents sign the same transaction.
    #[test]
    fn non_canonical_hex_quantity_is_refused() {
        assert_eq!(
            hex_quantity_bytes("0x00", "chain_id").unwrap_err(),
            "chain_id must be a canonical hex quantity"
        );
    }
}
