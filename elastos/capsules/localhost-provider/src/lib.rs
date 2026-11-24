//! JSON envelope for localhost files at rest.
//!
//! Home and this provider share these functions so a migrated file is the
//! same compact JSON `encrypt_bytes` writes today: `version`, `nonce`, and
//! `ciphertext`, AES-256-GCM, a 12-byte nonce, and no additional data.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io;

/// On-disk encrypted envelope (same format as the identity crate's fields).
#[derive(Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// Version 1, a 12-byte hex nonce, and hex ciphertext of at least 16 bytes.
///
/// Field names alone are not the envelope. `encrypt_bytes` writes hex.
pub fn is_encrypted_envelope(data: &[u8]) -> bool {
    let Ok(object) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        return false;
    };
    if object.len() != 3 || object.get("version").and_then(|value| value.as_u64()) != Some(1) {
        return false;
    }
    let decode = |key: &str| {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .and_then(|text| hex::decode(text).ok())
    };
    matches!(
        (decode("nonce"), decode("ciphertext")),
        (Some(nonce), Some(ciphertext)) if nonce.len() == 12 && ciphertext.len() >= 16
    )
}

/// Encrypt raw bytes with AES-256-GCM, returning JSON envelope bytes.
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| io::Error::other(format!("encryption: {e}")))?;

    let envelope = EncryptedEnvelope {
        version: 1,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };
    serde_json::to_vec(&envelope).map_err(|e| io::Error::other(format!("envelope serialize: {e}")))
}

/// Decrypt bytes from an `EncryptedEnvelope`.
pub fn decrypt_bytes(key: &[u8; 32], data: &[u8]) -> io::Result<Vec<u8>> {
    let envelope: EncryptedEnvelope = serde_json::from_slice(data).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("not an encrypted envelope: {e}"),
        )
    })?;

    let nonce_bytes = hex::decode(&envelope.nonce)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad nonce hex: {e}")))?;
    let ct = hex::decode(&envelope.ciphertext).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad ciphertext hex: {e}"),
        )
    })?;

    if nonce_bytes.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nonce length {}", nonce_bytes.len()),
        ));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let nonce_array: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"))?;
    let nonce = Nonce::from(nonce_array);

    cipher
        .decrypt(&nonce, ct.as_ref())
        .map_err(|e| io::Error::other(format!("decryption: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_recognition_uses_the_full_hex_form() {
        let key = [7u8; 32];
        let bytes = encrypt_bytes(&key, b"secret").unwrap();
        assert!(is_encrypted_envelope(&bytes));
        assert_eq!(decrypt_bytes(&key, &bytes).unwrap(), b"secret");
        assert!(!is_encrypted_envelope(
            br#"{"version":1,"nonce":"abcd","ciphertext":"deadbeef"}"#
        ));
        assert!(!is_encrypted_envelope(
            br#"{"ciphertext":"00112233445566778899aabbccddeeff","nonce":"00112233445566778899aabb","version":1,"extra":1}"#
        ));
        assert!(!is_encrypted_envelope(br#"{"version":1,"note":"plain"}"#));
    }
}
