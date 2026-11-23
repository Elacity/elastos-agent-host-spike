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

/// Whether `data` parses as the JSON envelope this crate encrypts.
///
/// Extra JSON fields are ignored, matching `decrypt_bytes`.
pub fn is_encrypted_envelope(data: &[u8]) -> bool {
    serde_json::from_slice::<EncryptedEnvelope>(data).is_ok()
}

/// Encrypt raw bytes with AES-256-GCM, returning JSON envelope bytes.
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    // Keep the current aes-gcm API until the upstream generic-array 1.x
    // migration is available through a compatible aes-gcm release.
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
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
    // See encrypt_bytes above for the aes-gcm/generic-array migration context.
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|e| io::Error::other(format!("decryption: {e}")))
}
