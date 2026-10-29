use super::payload::{hex_prefixed_bytes, keccak256_bytes, left_pad_32};
use elastos_auth::validate_evm_address;
use serde_json::Value;

pub(crate) fn eip712_payload_hash(payload: &Value) -> Result<[u8; 32], String> {
    let typed_data = typed_data_from_payload(payload)?;
    validate_eip712_typed_data_shape(&typed_data)?;
    eip712_hash_typed_data(&typed_data)
}

pub(crate) fn typed_data_from_payload(payload: &Value) -> Result<Value, String> {
    if let Some(canonical) = payload.get("typed_data_canonical").and_then(Value::as_str) {
        return serde_json::from_str(canonical).map_err(|err| format!("invalid typed data: {err}"));
    }
    payload
        .get("typed_data")
        .cloned()
        .ok_or_else(|| "Browser typed-data payload missing typed_data".to_string())
}

pub(crate) fn validate_eip712_typed_data_shape(typed_data: &Value) -> Result<(), String> {
    let types = typed_data
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| "typed data missing types".to_string())?;
    let primary_type = typed_data
        .get("primaryType")
        .and_then(Value::as_str)
        .ok_or_else(|| "typed data missing primaryType".to_string())?;
    if !types.contains_key(primary_type) {
        return Err("typed data primaryType is not declared".to_string());
    }
    typed_data
        .get("domain")
        .and_then(Value::as_object)
        .ok_or_else(|| "typed data missing domain".to_string())?;
    typed_data
        .get("message")
        .and_then(Value::as_object)
        .ok_or_else(|| "typed data missing message".to_string())?;
    Ok(())
}

pub(crate) fn eip712_hash_typed_data(typed_data: &Value) -> Result<[u8; 32], String> {
    let types = typed_data
        .get("types")
        .and_then(Value::as_object)
        .ok_or_else(|| "typed data missing types".to_string())?;
    let primary_type = typed_data
        .get("primaryType")
        .and_then(Value::as_str)
        .ok_or_else(|| "typed data missing primaryType".to_string())?;
    let domain = typed_data.get("domain").unwrap_or(&Value::Null);
    let message = typed_data.get("message").unwrap_or(&Value::Null);
    let domain_hash = eip712_hash_struct("EIP712Domain", domain, types)?;
    let message_hash = eip712_hash_struct(primary_type, message, types)?;
    let mut encoded = Vec::with_capacity(66);
    encoded.extend_from_slice(b"\x19\x01");
    encoded.extend_from_slice(&domain_hash);
    encoded.extend_from_slice(&message_hash);
    Ok(keccak256_bytes(&encoded))
}

pub(crate) fn eip712_hash_struct(
    type_name: &str,
    value: &Value,
    types: &serde_json::Map<String, Value>,
) -> Result<[u8; 32], String> {
    let fields = eip712_fields(type_name, types)?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("typed data {type_name} value must be an object"))?;
    let mut encoded = Vec::with_capacity(32 * (fields.len() + 1));
    encoded.extend_from_slice(&keccak256_bytes(
        eip712_encode_type(type_name, types)?.as_bytes(),
    ));
    for field in fields {
        let field_name = eip712_field_name(field)?;
        let field_type = eip712_field_type(field)?;
        let field_value = object.get(field_name).unwrap_or(&Value::Null);
        encoded.extend_from_slice(&eip712_encode_value(field_type, field_value, types)?);
    }
    Ok(keccak256_bytes(&encoded))
}

pub(crate) fn eip712_encode_type(
    primary_type: &str,
    types: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    let mut deps = Vec::<String>::new();
    collect_eip712_deps(primary_type, types, &mut deps)?;
    deps.retain(|dep| dep != primary_type);
    deps.sort();
    deps.dedup();
    let mut ordered = vec![primary_type.to_string()];
    ordered.extend(deps);
    ordered
        .iter()
        .map(|type_name| eip712_type_declaration(type_name, types))
        .collect::<Result<Vec<_>, _>>()
        .map(|items| items.join(""))
}

pub(crate) fn collect_eip712_deps(
    type_name: &str,
    types: &serde_json::Map<String, Value>,
    deps: &mut Vec<String>,
) -> Result<(), String> {
    for field in eip712_fields(type_name, types)? {
        let base = eip712_base_type(eip712_field_type(field)?);
        if base != type_name && types.contains_key(base) && !deps.iter().any(|dep| dep == base) {
            deps.push(base.to_string());
            collect_eip712_deps(base, types, deps)?;
        }
    }
    Ok(())
}

pub(crate) fn eip712_type_declaration(
    type_name: &str,
    types: &serde_json::Map<String, Value>,
) -> Result<String, String> {
    let fields = eip712_fields(type_name, types)?;
    let encoded_fields = fields
        .iter()
        .map(|field| {
            Ok(format!(
                "{} {}",
                eip712_field_type(field)?,
                eip712_field_name(field)?
            ))
        })
        .collect::<Result<Vec<String>, String>>()?;
    Ok(format!("{type_name}({})", encoded_fields.join(",")))
}

pub(crate) fn eip712_fields<'a>(
    type_name: &str,
    types: &'a serde_json::Map<String, Value>,
) -> Result<&'a Vec<Value>, String> {
    types
        .get(type_name)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("typed data type {type_name} is not declared"))
}

pub(crate) fn eip712_field_name(field: &Value) -> Result<&str, String> {
    field
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| "typed data field missing name".to_string())
}

pub(crate) fn eip712_field_type(field: &Value) -> Result<&str, String> {
    field
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "typed data field missing type".to_string())
}

pub(crate) fn eip712_base_type(field_type: &str) -> &str {
    field_type.split('[').next().unwrap_or(field_type)
}

pub(crate) fn eip712_is_array(field_type: &str) -> bool {
    field_type.contains('[') && field_type.ends_with(']')
}

pub(crate) fn eip712_encode_value(
    field_type: &str,
    value: &Value,
    types: &serde_json::Map<String, Value>,
) -> Result<[u8; 32], String> {
    let base_type = eip712_base_type(field_type);
    if eip712_is_array(field_type) {
        let values = value
            .as_array()
            .ok_or_else(|| format!("typed data {field_type} value must be an array"))?;
        let mut encoded = Vec::with_capacity(values.len() * 32);
        for item in values {
            encoded.extend_from_slice(&eip712_encode_value(base_type, item, types)?);
        }
        return Ok(keccak256_bytes(&encoded));
    }
    if types.contains_key(base_type) {
        return eip712_hash_struct(base_type, value, types);
    }
    match base_type {
        "string" => value
            .as_str()
            .map(|text| keccak256_bytes(text.as_bytes()))
            .ok_or_else(|| "typed data string value must be a string".to_string()),
        "bytes" => {
            let bytes = value
                .as_str()
                .ok_or_else(|| "typed data bytes value must be hex".to_string())
                .and_then(|text| hex_prefixed_bytes(text, None, "typed data bytes"))?;
            Ok(keccak256_bytes(&bytes))
        }
        "bool" => {
            let mut out = [0u8; 32];
            if value
                .as_bool()
                .ok_or_else(|| "typed data bool value must be boolean".to_string())?
            {
                out[31] = 1;
            }
            Ok(out)
        }
        "address" => {
            let address = value
                .as_str()
                .ok_or_else(|| "typed data address value must be a string".to_string())?;
            validate_evm_address(address)?;
            let bytes = hex_prefixed_bytes(address, Some(20), "typed data address")?;
            Ok(left_pad_32(&bytes))
        }
        _ if base_type == "uint" || base_type.starts_with("uint") => {
            parse_json_uint256(value, "typed data uint")
        }
        _ if base_type == "int" || base_type.starts_with("int") => {
            parse_json_int256(value, "typed data int")
        }
        _ if base_type.starts_with("bytes") => {
            let size: usize = base_type[5..]
                .parse()
                .map_err(|_| "typed data fixed bytes size is invalid".to_string())?;
            if !(1..=32).contains(&size) {
                return Err("typed data fixed bytes size is invalid".to_string());
            }
            let bytes = value
                .as_str()
                .ok_or_else(|| "typed data fixed bytes value must be hex".to_string())
                .and_then(|text| hex_prefixed_bytes(text, Some(size), "typed data fixed bytes"))?;
            let mut out = [0u8; 32];
            out[..bytes.len()].copy_from_slice(&bytes);
            Ok(out)
        }
        _ => Err(format!("unsupported EIP-712 field type {field_type}")),
    }
}

pub(crate) fn parse_json_uint256(value: &Value, label: &str) -> Result<[u8; 32], String> {
    if let Some(raw) = value.as_str() {
        return parse_uint256(raw, label);
    }
    if let Some(raw) = value.as_u64() {
        return Ok(left_pad_32(&raw.to_be_bytes()));
    }
    Err(format!(
        "{label} value must be a string or unsigned integer"
    ))
}

pub(crate) fn parse_json_int256(value: &Value, label: &str) -> Result<[u8; 32], String> {
    if let Some(raw) = value.as_i64() {
        if raw < 0 {
            return parse_negative_i128(raw as i128);
        }
        return Ok(left_pad_32(&(raw as u64).to_be_bytes()));
    }
    if let Some(raw) = value.as_str() {
        if let Some(abs) = raw.strip_prefix('-') {
            let positive = parse_uint256(abs, label)?;
            return twos_complement_256(&positive);
        }
        return parse_uint256(raw, label);
    }
    Err(format!("{label} value must be a string or integer"))
}

pub(crate) fn parse_uint256(value: &str, label: &str) -> Result<[u8; 32], String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{label} value is empty"));
    }
    if let Some(raw) = value.strip_prefix("0x") {
        if raw.is_empty() || raw.len() > 64 || !raw.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(format!("{label} hex value is invalid"));
        }
        let padded = if raw.len() % 2 == 0 {
            raw.to_string()
        } else {
            format!("0{raw}")
        };
        let bytes = hex::decode(padded).map_err(|err| err.to_string())?;
        return Ok(left_pad_32(&bytes));
    }
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("{label} decimal value is invalid"));
    }
    let mut out = [0u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        mul_u256_small(&mut out, 10)?;
        add_u256_small(&mut out, digit)?;
    }
    Ok(out)
}

pub(crate) fn parse_negative_i128(value: i128) -> Result<[u8; 32], String> {
    let abs = value
        .checked_abs()
        .ok_or_else(|| "typed data int value is out of range".to_string())?;
    let positive = parse_uint256(&abs.to_string(), "typed data int")?;
    twos_complement_256(&positive)
}

pub(crate) fn twos_complement_256(value: &[u8; 32]) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    for (target, byte) in out.iter_mut().zip(value.iter()) {
        *target = !*byte;
    }
    add_u256_small(&mut out, 1)?;
    Ok(out)
}

pub(crate) fn mul_u256_small(value: &mut [u8; 32], factor: u8) -> Result<(), String> {
    let mut carry = 0u16;
    for byte in value.iter_mut().rev() {
        let next = (*byte as u16) * (factor as u16) + carry;
        *byte = (next & 0xff) as u8;
        carry = next >> 8;
    }
    if carry != 0 {
        return Err("uint256 value overflow".to_string());
    }
    Ok(())
}

pub(crate) fn add_u256_small(value: &mut [u8; 32], add: u8) -> Result<(), String> {
    let mut carry = add as u16;
    for byte in value.iter_mut().rev() {
        let next = (*byte as u16) + carry;
        *byte = (next & 0xff) as u8;
        carry = next >> 8;
        if carry == 0 {
            return Ok(());
        }
    }
    Err("uint256 value overflow".to_string())
}

/// One test per refusal this hasher raises, each asserting the whole `Err`
/// value. They pin answers the hasher already gives: they add no rule and
/// register no falsifier. They prove the provider's EIP-712 hasher, not
/// confinement: the Runtime decides whether the provider runs at all.
///
/// Where the text carries a format argument, the test names the text this
/// input makes the code produce, not the template.
///
/// Three strings stand at two sites each, and one test covers the string.
/// `typed data fixed bytes size is invalid` and `uint256 value overflow` are
/// reachable at both of their sites, so those tests assert both. `typed data
/// missing types` and `typed data missing primaryType` are not: the hasher's
/// copies (`:48`, `:52`) sit behind `validate_eip712_typed_data_shape` on the
/// only production path, so those tests pin the copy a caller meets and record
/// the dead one here.
#[cfg(test)]
mod uf_typed_data_tests {
    use super::*;
    use serde_json::json;

    fn hash_of(typed_data: Value) -> Result<[u8; 32], String> {
        eip712_payload_hash(&json!({ "typed_data": typed_data }))
    }

    /// A message whose single field is declared as `field_type`, so only that
    /// type decides the answer. `EIP712Domain` is declared empty, so the
    /// domain hashes without asking for a field.
    fn message_with(field_type: &str, value: Value) -> Value {
        json!({
            "types": {
                "EIP712Domain": [],
                "Message": [{ "name": "field", "type": field_type }]
            },
            "primaryType": "Message",
            "domain": {},
            "message": { "field": value }
        })
    }

    /// Falsifier: keep the payload's own text instead of the parsed value, so
    /// malformed canonical JSON reaches the hasher and the reason is lost.
    #[test]
    fn invalid_canonical_typed_data_is_refused() {
        assert_eq!(
            eip712_payload_hash(&json!({ "typed_data_canonical": "{" })).unwrap_err(),
            "invalid typed data: EOF while parsing an object at line 1 column 1"
        );
    }

    /// Falsifier: answer `Ok` on a payload with neither form, so a request
    /// that carries no typed data signs the empty hash.
    #[test]
    fn payload_missing_typed_data_is_refused() {
        assert_eq!(
            eip712_payload_hash(&json!({})).unwrap_err(),
            "Browser typed-data payload missing typed_data"
        );
    }

    /// The shape check refuses first on this path; the hasher holds a second
    /// copy of the same refusal (`:48`) that `eip712_payload_hash` never
    /// reaches, because the shape check runs before it and is the hasher's
    /// only production caller. This test pins the copy a caller meets.
    ///
    /// Falsifier: default `types` to an empty object, so a declaration-less
    /// payload hashes as a bare domain.
    #[test]
    fn missing_types_is_refused() {
        assert_eq!(
            hash_of(json!({ "primaryType": "Message" })).unwrap_err(),
            "typed data missing types"
        );
    }

    /// As with `typed data missing types`, the hasher's copy of this refusal
    /// (`:52`) sits behind the shape check and is never reached from a caller.
    ///
    /// Falsifier: default `primaryType` to the only declared type, so a
    /// payload that names no primary type still hashes.
    #[test]
    fn missing_primary_type_is_refused() {
        assert_eq!(
            hash_of(json!({ "types": {} })).unwrap_err(),
            "typed data missing primaryType"
        );
    }

    /// Falsifier: hash the primary type without checking it is declared, so a
    /// payload naming a type it never declares hashes from a field list the
    /// hasher invents.
    #[test]
    fn undeclared_primary_type_is_refused() {
        assert_eq!(
            hash_of(json!({ "types": { "Other": [] }, "primaryType": "Message" })).unwrap_err(),
            "typed data primaryType is not declared"
        );
    }

    /// Falsifier: default `domain` to an empty object, so a payload that
    /// leaves the domain out hashes against a domain no page asked for.
    #[test]
    fn missing_domain_is_refused() {
        assert_eq!(
            hash_of(json!({ "types": { "Message": [] }, "primaryType": "Message" })).unwrap_err(),
            "typed data missing domain"
        );
    }

    /// Falsifier: default `message` to an empty object, so a payload that
    /// leaves the message out hashes as a message with every field null.
    #[test]
    fn missing_message_is_refused() {
        assert_eq!(
            hash_of(json!({
                "types": { "Message": [] },
                "primaryType": "Message",
                "domain": {}
            }))
            .unwrap_err(),
            "typed data missing message"
        );
    }

    /// Falsifier: hash a struct value that is not an object as if every field
    /// were null, so a nested type declared with fields hashes from nothing.
    #[test]
    fn struct_value_not_an_object_is_refused() {
        assert_eq!(
            hash_of(json!({
                "types": {
                    "EIP712Domain": [],
                    "Message": [{ "name": "nested", "type": "Nested" }],
                    "Nested": [{ "name": "n", "type": "string" }]
                },
                "primaryType": "Message",
                "domain": {},
                "message": { "nested": "oops" }
            }))
            .unwrap_err(),
            "typed data Nested value must be an object"
        );
    }

    /// `EIP712Domain` is the one type the hasher names without the payload
    /// declaring it, so a payload that declares only its message type reaches
    /// this arm through the shape check's blind spot.
    ///
    /// Falsifier: default an undeclared type to an empty field list, so a
    /// domain with no declaration hashes as `EIP712Domain()`.
    #[test]
    fn undeclared_type_is_refused() {
        assert_eq!(
            hash_of(json!({
                "types": { "Message": [] },
                "primaryType": "Message",
                "domain": {},
                "message": {}
            }))
            .unwrap_err(),
            "typed data type EIP712Domain is not declared"
        );
    }

    /// Falsifier: skip a field that names no name, so a declared type encodes
    /// a field the page never described.
    #[test]
    fn field_missing_name_is_refused() {
        assert_eq!(
            hash_of(json!({
                "types": { "EIP712Domain": [], "Message": [{ "type": "string" }] },
                "primaryType": "Message",
                "domain": {},
                "message": {}
            }))
            .unwrap_err(),
            "typed data field missing name"
        );
    }

    /// Falsifier: treat a field with no type as `string`, so the type string
    /// the page omitted is replaced by a guess.
    #[test]
    fn field_missing_type_is_refused() {
        assert_eq!(
            hash_of(json!({
                "types": { "EIP712Domain": [], "Message": [{ "name": "field" }] },
                "primaryType": "Message",
                "domain": {},
                "message": {}
            }))
            .unwrap_err(),
            "typed data field missing type"
        );
    }

    /// Falsifier: hash a scalar as a one-item array, so an array field accepts
    /// a value the page wrote without brackets.
    #[test]
    fn array_value_not_an_array_is_refused() {
        assert_eq!(
            hash_of(message_with("uint256[]", json!(5))).unwrap_err(),
            "typed data uint256[] value must be an array"
        );
    }

    /// Falsifier: accept any JSON as `string` through its serialized form, so
    /// a number signs as text.
    #[test]
    fn string_value_not_a_string_is_refused() {
        assert_eq!(
            hash_of(message_with("string", json!(1))).unwrap_err(),
            "typed data string value must be a string"
        );
    }

    /// Falsifier: treat a non-string `bytes` value as empty bytes, so the
    /// field hashes without the value the page gave.
    #[test]
    fn bytes_value_not_hex_is_refused() {
        assert_eq!(
            hash_of(message_with("bytes", json!(1))).unwrap_err(),
            "typed data bytes value must be hex"
        );
    }

    /// Falsifier: read any non-empty string as `true`, so `"yes"` signs as 1.
    #[test]
    fn bool_value_not_boolean_is_refused() {
        assert_eq!(
            hash_of(message_with("bool", json!("yes"))).unwrap_err(),
            "typed data bool value must be boolean"
        );
    }

    /// Falsifier: read a non-string `address` through its serialized form, so
    /// a number reaches the address validator as text.
    #[test]
    fn address_value_not_a_string_is_refused() {
        assert_eq!(
            hash_of(message_with("address", json!(1))).unwrap_err(),
            "typed data address value must be a string"
        );
    }

    /// Both arms of this branch raise the string: a width that does not parse
    /// (`bytesx`) and a width outside `1..=32` (`bytes33`). One string, one
    /// test, both sites.
    ///
    /// Falsifier: accept any fixed-bytes width, so `bytes33` encodes 33 bytes
    /// into a 32-byte word.
    #[test]
    fn fixed_bytes_size_is_refused() {
        let reason = "typed data fixed bytes size is invalid";
        assert_eq!(
            hash_of(message_with("bytesx", json!("0x"))).unwrap_err(),
            reason
        );
        assert_eq!(
            hash_of(message_with("bytes33", json!("0x"))).unwrap_err(),
            reason
        );
    }

    /// Falsifier: treat a non-string `bytesN` value as empty bytes, so the
    /// field hashes as thirty-two zero bytes.
    #[test]
    fn fixed_bytes_value_not_hex_is_refused() {
        assert_eq!(
            hash_of(message_with("bytes4", json!(1))).unwrap_err(),
            "typed data fixed bytes value must be hex"
        );
    }

    /// Falsifier: read an unknown field type as `bytes`, so a type the hasher
    /// does not implement signs as raw hex.
    #[test]
    fn unsupported_field_type_is_refused() {
        assert_eq!(
            hash_of(message_with("tuple", json!({}))).unwrap_err(),
            "unsupported EIP-712 field type tuple"
        );
    }

    /// Falsifier: read a boolean as `0` or `1`, so a JSON `true` signs as the
    /// number one.
    #[test]
    fn uint_value_not_an_integer_is_refused() {
        assert_eq!(
            hash_of(message_with("uint256", json!(true))).unwrap_err(),
            "typed data uint value must be a string or unsigned integer"
        );
    }

    /// Falsifier: read a boolean as `1`, so a JSON `true` signs as the number
    /// one in a signed field.
    #[test]
    fn int_value_not_an_integer_is_refused() {
        assert_eq!(
            hash_of(message_with("int256", json!(true))).unwrap_err(),
            "typed data int value must be a string or integer"
        );
    }

    /// Falsifier: read an empty text as zero, so a field the page left blank
    /// signs as `0`.
    #[test]
    fn uint_value_empty_is_refused() {
        assert_eq!(
            hash_of(message_with("uint256", json!(""))).unwrap_err(),
            "typed data uint value is empty"
        );
    }

    /// Falsifier: strip the `0x` from empty hex and read it as zero, so a
    /// truncated value signs as `0`.
    #[test]
    fn uint_hex_value_invalid_is_refused() {
        assert_eq!(
            hash_of(message_with("uint256", json!("0x"))).unwrap_err(),
            "typed data uint hex value is invalid"
        );
    }

    /// Falsifier: stop reading decimal text at the first non-digit, so `12a`
    /// signs as `12`.
    #[test]
    fn uint_decimal_value_invalid_is_refused() {
        assert_eq!(
            hash_of(message_with("uint256", json!("12a"))).unwrap_err(),
            "typed data uint decimal value is invalid"
        );
    }

    /// `parse_json_int256` hands this arm an `i64` widened to `i128`, so the
    /// only value that fails `checked_abs` is `i128::MIN`, which no JSON number
    /// reaches. The refusal is reached through the function that raises it.
    ///
    /// Falsifier: keep the wrapping magnitude of `i128::MIN`, so the most
    /// negative value signs as a positive one.
    #[test]
    fn int_value_out_of_range_is_refused() {
        assert_eq!(
            parse_negative_i128(i128::MIN).unwrap_err(),
            "typed data int value is out of range"
        );
    }

    /// Two functions raise this string, so this one test holds both. `2^256`
    /// reaches the sum that carries past the top byte, and `2^256 - 1`
    /// followed by a digit reaches the multiply that carries out of it.
    ///
    /// Falsifier: drop either carry check, and an over-long decimal signs as
    /// its low 256 bits.
    #[test]
    fn uint256_overflow_is_refused() {
        let reason = "uint256 value overflow";
        assert_eq!(
            hash_of(message_with(
                "uint256",
                json!("115792089237316195423570985008687907853269984665640564039457584007913129639936")
            ))
            .unwrap_err(),
            reason
        );
        assert_eq!(
            hash_of(message_with(
                "uint256",
                json!("1157920892373161954235709850086879078532699846656405640394575840079131296399350")
            ))
            .unwrap_err(),
            reason
        );
    }
}
