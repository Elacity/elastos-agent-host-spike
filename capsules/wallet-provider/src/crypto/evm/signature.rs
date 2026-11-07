use elastos_auth::ethereum_signed_message_hash;
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};

pub(crate) fn evm_address_for_signing_key(signing_key: &SigningKey) -> String {
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let digest = Keccak256::digest(&encoded.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..])).to_ascii_lowercase()
}

pub(crate) fn sign_evm_message(signing_key: &SigningKey, message: &[u8]) -> Result<String, String> {
    let hash = ethereum_signed_message_hash(message);
    sign_evm_prehash(signing_key, &hash)
}

pub(crate) fn sign_evm_prehash(
    signing_key: &SigningKey,
    hash: &[u8; 32],
) -> Result<String, String> {
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(hash)
        .map_err(|err| err.to_string())?;
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(recovery_id.to_byte());
    Ok(format!("0x{}", hex::encode(bytes)))
}

pub(crate) fn recover_evm_address_from_hash(
    hash: &[u8; 32],
    signature_hex: &str,
) -> Result<String, String> {
    let signature_hex = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let bytes =
        hex::decode(signature_hex).map_err(|err| format!("invalid signature hex: {err}"))?;
    if bytes.len() != 65 {
        return Err("EVM signature must be 65 bytes".to_string());
    }
    let signature = EcdsaSignature::try_from(&bytes[..64])
        .map_err(|err| format!("invalid EVM signature: {err}"))?;
    let recovery_id = normalize_evm_recovery_id(bytes[64])?;
    let verifying_key = VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        .map_err(|err| format!("failed to recover EVM signer: {err}"))?;
    let encoded = verifying_key.to_encoded_point(false);
    let public_key = encoded.as_bytes();
    if public_key.len() != 65 {
        return Err("unexpected recovered public key length".to_string());
    }
    let digest = Keccak256::digest(&public_key[1..]);
    Ok(format!("0x{}", hex::encode(&digest[12..])))
}

pub(crate) fn canonicalize_evm_signature(signature_hex: &str) -> Result<Vec<u8>, String> {
    let signature_hex = signature_hex.strip_prefix("0x").unwrap_or(signature_hex);
    let bytes =
        hex::decode(signature_hex).map_err(|err| format!("invalid signature hex: {err}"))?;
    if bytes.len() != 65 {
        return Err("EVM signature must be 65 bytes".to_string());
    }
    let signature = EcdsaSignature::try_from(&bytes[..64])
        .map_err(|err| format!("invalid EVM signature: {err}"))?;
    if signature.normalize_s().is_some() {
        return Err("EVM signature must use canonical low-S form".to_string());
    }
    let recovery_id = normalize_evm_recovery_id(bytes[64])?;
    let mut canonical = signature.to_bytes().to_vec();
    canonical.push(recovery_id.to_byte());
    Ok(canonical)
}

pub(crate) fn normalize_evm_recovery_id(v: u8) -> Result<RecoveryId, String> {
    let id = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        _ => return Err("unsupported EVM recovery id".to_string()),
    };
    RecoveryId::try_from(id).map_err(|err| format!("invalid recovery id: {err}"))
}

/// One test per refusal this file raises, each asserting the whole `Err`
/// value. They pin answers the reader already gives: they add no rule and
/// register no falsifier. They prove the provider's signature reader, not
/// confinement: the Runtime decides whether the provider runs at all.
///
/// Two strings are recorded as unreachable instead of tested. `unexpected
/// recovered public key length` (`:47`) follows `to_encoded_point(false)` on a
/// recovered `VerifyingKey`, which always answers the 65 SEC1 bytes the check
/// then accepts; no input reaches that arm. `invalid recovery id: {err}`
/// (`:77`) follows `RecoveryId::try_from` on a value the `match` above has
/// already pinned to `0` or `1`, and `RecoveryId` accepts `0` to `3`, so the
/// mapping never fails.
#[cfg(test)]
mod uf_evm_signature_tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).expect("the fixed test key is valid")
    }

    /// A low-S signature over a fixed message, made by this crate's own
    /// `k256` key, so no signature vector is copied in.
    fn signed_message_bytes() -> Vec<u8> {
        let signature = sign_evm_message(&signing_key(), b"ElastOS unit test")
            .expect("the fixed key signs the fixed message");
        hex::decode(
            signature
                .strip_prefix("0x")
                .expect("the signer answers hex"),
        )
        .expect("the signer answers decodable hex")
    }

    fn hex_of(bytes: &[u8]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    /// Both callers raise this string, so this one test holds both sites.
    ///
    /// Falsifier: drop the `hex::decode` mapping, so unparsed bytes reach the
    /// length check and the reason is lost.
    #[test]
    fn invalid_signature_hex_is_refused() {
        let reason = "invalid signature hex: Invalid character 'z' at position 0";
        assert_eq!(canonicalize_evm_signature("0xzz").unwrap_err(), reason);
        assert_eq!(
            recover_evm_address_from_hash(&[0u8; 32], "0xzz").unwrap_err(),
            reason
        );
    }

    /// Both callers raise this string, so this one test holds both sites.
    ///
    /// Falsifier: accept any length, so a 1-byte signature is padded or sliced
    /// into an answer.
    #[test]
    fn signature_length_is_refused() {
        let reason = "EVM signature must be 65 bytes";
        assert_eq!(canonicalize_evm_signature("0x00").unwrap_err(), reason);
        assert_eq!(
            recover_evm_address_from_hash(&[0u8; 32], "0x00").unwrap_err(),
            reason
        );
    }

    /// Both callers raise this string, so this one test holds both sites.
    ///
    /// Falsifier: accept a zero `r`/`s` pair, so a signature that names no
    /// scalar is read as if it were one.
    #[test]
    fn invalid_signature_scalars_are_refused() {
        let reason = "invalid EVM signature: signature error";
        let zeros = hex_of(&[0u8; 65]);
        assert_eq!(canonicalize_evm_signature(&zeros).unwrap_err(), reason);
        assert_eq!(
            recover_evm_address_from_hash(&[0u8; 32], &zeros).unwrap_err(),
            reason
        );
    }

    /// Both callers reach `normalize_evm_recovery_id`, so this one test holds
    /// both sites. `2` is the first byte the `0 | 1` and `27 | 28` arms turn
    /// away, and `k256` would accept it, so the refusal is the reader's own.
    ///
    /// Falsifier: accept `v = 2` (the x-reduced recovery ids) as a recovery
    /// id, so the reader answers an address Ethereum never asked for.
    #[test]
    fn unsupported_recovery_id_is_refused() {
        let reason = "unsupported EVM recovery id";
        let mut bytes = signed_message_bytes();
        bytes[64] = 2;
        let signature = hex_of(&bytes);
        assert_eq!(canonicalize_evm_signature(&signature).unwrap_err(), reason);
        assert_eq!(
            recover_evm_address_from_hash(&[0u8; 32], &signature).unwrap_err(),
            reason
        );
    }

    /// `r = 5` is an x-coordinate with no secp256k1 point, so recovery fails
    /// after the signature parses. The string is one test across both callers;
    /// `canonicalize_evm_signature` never recovers, so this one uses the
    /// recovering reader.
    ///
    /// Falsifier: swallow the recovery failure and answer the zero address, so
    /// a signature that names no key answers an address.
    #[test]
    fn unrecoverable_signature_is_refused() {
        let mut bytes = vec![0u8; 65];
        bytes[31] = 5;
        bytes[63] = 1;
        assert_eq!(
            recover_evm_address_from_hash(&[0u8; 32], &hex_of(&bytes)).unwrap_err(),
            "failed to recover EVM signer: signature error"
        );
    }

    /// `k256` signs in low-S form, so the high form is the same `s` negated on
    /// the curve order, computed with `k256`'s own scalar arithmetic rather
    /// than pasted in.
    ///
    /// Falsifier: drop the `normalize_s` check, so a malleable twin of a valid
    /// signature is canonicalized and answers.
    #[test]
    fn high_s_signature_is_refused() {
        let mut bytes = signed_message_bytes();
        let signature =
            EcdsaSignature::try_from(&bytes[..64]).expect("the signer answers a signature");
        let high_s = -*signature.s();
        let high_s_bytes = high_s.to_bytes();
        bytes[32..64].copy_from_slice(&high_s_bytes);
        assert_eq!(
            canonicalize_evm_signature(&hex_of(&bytes)).unwrap_err(),
            "EVM signature must use canonical low-S form"
        );
    }
}
