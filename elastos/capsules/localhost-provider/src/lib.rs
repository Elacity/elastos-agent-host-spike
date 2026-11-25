//! JSON envelope for localhost files at rest.
//!
//! Home and this provider share these functions so a migrated file is the
//! same compact JSON `encrypt_bytes` writes today: `version`, `nonce`, and
//! `ciphertext`, AES-256-GCM, a 12-byte nonce, and no additional data.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::path::Path;

/// A sealed file larger than this is left alone by the migration walk.
/// A later read loads it only when the header can start an envelope and the
/// file key opens it. Any other file over this cap is refused by name.
pub const ENVELOPE_BYTE_LIMIT: u64 = 32 * 1024 * 1024;
const ENVELOPE_HEADER: usize = 64;

/// On-disk encrypted envelope (same format as the identity crate's fields).
#[derive(Serialize, Deserialize)]
struct EncryptedEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

/// A header rules an envelope out only when it cannot be the start of one.
/// All whitespace, or `{`, can still be an envelope. Any other first byte cannot.
pub fn header_rules_out_envelope(header: &[u8]) -> bool {
    let start = header
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(header.len());
    match header.get(start) {
        None | Some(b'{') => false,
        Some(_) => true,
    }
}

fn over_cap_refusal(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{name} is larger than 32 MiB. Make it readable or move it out of the folder, then restart."
        ),
    )
}

#[cfg(test)]
thread_local! {
    static SEALED_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn note_sealed_bytes(n: u64) {
    #[cfg(test)]
    SEALED_BYTES_READ.with(|slot| slot.set(slot.get().saturating_add(n)));
    #[cfg(not(test))]
    let _ = n;
}

/// Bytes `read_sealed_localhost_file` took from the file since the last take.
#[cfg(test)]
pub fn take_sealed_read_bytes() -> u64 {
    SEALED_BYTES_READ.with(|slot| slot.replace(0))
}

/// Read one sealed localhost file.
///
/// A file at or under [`ENVELOPE_BYTE_LIMIT`] is decrypted as stored. A larger
/// file whose header cannot start an envelope is refused by `name` after that
/// header, and the body is not read. A larger file whose header can start an
/// envelope is opened with `key` when that key matches, and refused by `name`
/// when it does not.
pub fn read_sealed_localhost_file(key: &[u8; 32], path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let len = std::fs::metadata(path)?.len();
    if len <= ENVELOPE_BYTE_LIMIT {
        let raw = std::fs::read(path)?;
        note_sealed_bytes(raw.len() as u64);
        return decrypt_bytes(key, &raw);
    }
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; ENVELOPE_HEADER];
    let read = file.read(&mut header)?;
    note_sealed_bytes(read as u64);
    if header_rules_out_envelope(&header[..read]) {
        return Err(over_cap_refusal(name));
    }
    let mut bytes = header[..read].to_vec();
    let mut rest = Vec::new();
    file.read_to_end(&mut rest)?;
    note_sealed_bytes(rest.len() as u64);
    bytes.extend(rest);
    match decrypt_bytes(key, &bytes) {
        Ok(plain) => Ok(plain),
        Err(_) => Err(over_cap_refusal(name)),
    }
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

    #[test]
    fn an_over_cap_file_is_refused_by_name_unless_the_key_opens_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = [9u8; 32];
        let plain = dir.path().join("video.bin");
        std::fs::write(&plain, b"ftyp").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&plain)
            .unwrap()
            .set_len(ENVELOPE_BYTE_LIMIT + 1)
            .unwrap();
        let _ = take_sealed_read_bytes();
        let err = read_sealed_localhost_file(&key, &plain, "Users/video.bin").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Users/video.bin"), "{text}");
        assert!(text.contains("larger than 32 MiB"), "{text}");
        let read = take_sealed_read_bytes();
        assert!(
            read <= ENVELOPE_HEADER as u64,
            "read the plain body: {read}"
        );

        let brace = dir.path().join("brace.bin");
        std::fs::write(&brace, b"{not-an-envelope").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&brace)
            .unwrap()
            .set_len(ENVELOPE_BYTE_LIMIT + 1)
            .unwrap();
        let err = read_sealed_localhost_file(&key, &brace, "Users/brace.bin").unwrap_err();
        assert!(err.to_string().contains("Users/brace.bin"), "{err}");
        assert!(err.to_string().contains("larger than 32 MiB"), "{err}");

        let small = dir.path().join("small.bin");
        let sealed = encrypt_bytes(&key, b"small").unwrap();
        std::fs::write(&small, &sealed).unwrap();
        assert_eq!(
            read_sealed_localhost_file(&key, &small, "Users/small.bin").unwrap(),
            b"small"
        );
    }
}
