//! JSON envelope for localhost files at rest.
//!
//! Home and this provider share these functions so a migrated file is the
//! same compact JSON `encrypt_bytes` writes today: `version`, `nonce`, and
//! `ciphertext`, AES-256-GCM, a 12-byte nonce, and no additional data.

use aes_gcm::aead::{Aead, AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::path::Path;

/// A sealed file larger than this is a migration concern, not a read refusal
/// for a file this key already opens.
pub const ENVELOPE_BYTE_LIMIT: u64 = 32 * 1024 * 1024;
/// Largest envelope [`read_sealed_localhost_file`] loads.
///
/// Ciphertext is decoded in the file `Vec` and decryption stays in that `Vec`.
pub const SEALED_READ_HARD_LIMIT: u64 = 1024 * 1024 * 1024;
const ENVELOPE_HEADER: usize = 64;
const FILE_KEY_ENVELOPE_VERSION: u8 = 2;

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
        format!("{name} is larger than 32 MiB. Move it out of the folder."),
    )
}

fn hard_limit_refusal(name: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{name} is larger than this process can read. Move it out of the folder."),
    )
}

pub const FILE_KEY_ENVELOPE_PREFIX: &[u8] = br#"{"version":2,"nonce":""#;

pub fn header_is_file_key_envelope(header: &[u8]) -> bool {
    header.starts_with(FILE_KEY_ENVELOPE_PREFIX)
}

/// `encrypt_bytes` has written this since the first localhost provider.
/// Lowercase hex, no spaces: `{"version":1,"nonce":"<24 hex>","ciphertext":"<hex>`.
pub fn header_is_device_key_envelope(header: &[u8]) -> bool {
    const HEAD: &[u8] = br#"{"version":1,"nonce":""#;
    const MID: &[u8] = br#"","ciphertext":""#;
    const NONCE: usize = 24;
    let mid_at = HEAD.len() + NONCE;
    let digit_at = mid_at + MID.len();
    header.len() > digit_at
        && header.starts_with(HEAD)
        && header[HEAD.len()..mid_at]
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && header[mid_at..].starts_with(MID)
        && matches!(header[digit_at], b'0'..=b'9' | b'a'..=b'f')
}

#[rustfmt::skip]
fn open_new_format(key: &[u8; 32], bytes: Vec<u8>, name: &str) -> io::Result<Vec<u8>> {
    let Some((mut body, nonce)) = ciphertext_in_place(bytes) else {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} is cut off. Remove it.")));
    };
    Aes256Gcm::new_from_slice(key).map_err(|e| io::Error::other(format!("AES key init: {e}")))?
        .decrypt_in_place(&Nonce::from(nonce), b"", &mut body)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{name} does not decrypt.")))?;
    Ok(body)
}

thread_local! {
    static SEALED_BYTES_READ: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

fn note_sealed_bytes(n: u64) {
    SEALED_BYTES_READ.with(|slot| slot.set(slot.get().saturating_add(n)));
}

/// Bytes `read_sealed_localhost_file` took from the file since the last take.
pub fn take_sealed_read_bytes() -> u64 {
    SEALED_BYTES_READ.with(|slot| slot.replace(0))
}

#[rustfmt::skip]
fn read_body_within_hard_limit(file: &mut std::fs::File, header: &[u8], len: u64, name: &str) -> io::Result<Vec<u8>> {
    if len > SEALED_READ_HARD_LIMIT { return Err(hard_limit_refusal(name)); }
    let Ok(n) = usize::try_from(len) else { return Err(hard_limit_refusal(name)); };
    if header.len() > n { return Err(io::Error::new(io::ErrorKind::InvalidData, format!("{name} is cut off. Remove it."))); }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(n).is_err() { return Err(hard_limit_refusal(name)); }
    bytes.resize(n, 0);
    bytes[..header.len()].copy_from_slice(header);
    file.read_exact(&mut bytes[header.len()..]).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{name} is cut off. Remove it.")))?;
    note_sealed_bytes((n - header.len()) as u64);
    Ok(bytes)
}

/// Envelope keys are `version`, `nonce`, and `ciphertext`. Over 32 MiB the stream stops at any other key and keeps no value.
#[rustfmt::skip]
mod scan {
    use super::{header_rules_out_envelope, ENVELOPE_BYTE_LIMIT};
    use std::io::{self, Read};
    pub fn reads_as_plain_bytes(header: &[u8], len: u64, rest: &mut dyn Read) -> io::Result<(bool, u64)> {
        // A header this Home writes, new or old, is an envelope at every size. Do not scan the body.
        if super::header_is_file_key_envelope(header) || super::header_is_device_key_envelope(header) {
            return Ok((false, 0));
        }
        if header_rules_out_envelope(header) || len <= ENVELOPE_BYTE_LIMIT { return Ok((header_rules_out_envelope(header), 0)); }
        let mut s = Src { rest, n: 0, b: [0; 8192], i: 0, j: header.len() };
        s.b[..header.len()].copy_from_slice(header);
        Ok((!s.open()?, s.n))
    }
    struct Src<'a> { rest: &'a mut dyn Read, n: u64, b: [u8; 8192], i: usize, j: usize }
    impl Src<'_> {
        fn fill(&mut self) -> io::Result<bool> { self.i = 0; self.j = self.rest.read(&mut self.b)?; self.n += self.j as u64; Ok(self.j != 0) }
        fn byte(&mut self) -> io::Result<Option<u8>> { if self.i == self.j && !self.fill()? { return Ok(None); } self.i += 1; Ok(Some(self.b[self.i - 1])) }
        fn ws(&mut self) -> io::Result<Option<u8>> {
            loop { let Some(b) = self.byte()? else { return Ok(None); }; if !matches!(b, b' ' | b'\t' | b'\n' | b'\r') { return Ok(Some(b)); } }
        }
        fn key(&mut self) -> io::Result<Option<u8>> {
            let (mut name, mut k) = ([0u8; 10], 0);
            while let Some(b) = self.byte()? {
                if b == b'"' { return Ok([b"version".as_slice(), b"nonce", b"ciphertext"].iter().position(|x| *x == &name[..k]).map(|id| id as u8)); }
                if k == 10 || b == b'\\' { return Ok(None); }
                name[k] = b; k += 1;
            }
            Ok(None)
        }
        fn hex(&mut self) -> io::Result<Option<u64>> {
            let mut count = 0u64;
            loop {
                if self.i == self.j && !self.fill()? { return Ok(None); }
                let start = self.i;
                while self.i < self.j && self.b[self.i].is_ascii_hexdigit() { self.i += 1; }
                count += (self.i - start) as u64;
                if self.i < self.j { if self.b[self.i] != b'"' { return Ok(None); } self.i += 1; return Ok(Some(count)); }
            }
        }
        fn open(&mut self) -> io::Result<bool> {
            if self.ws()? != Some(b'{') { return Ok(false); }
            let mut seen = 0u8;
            loop {
                if self.ws()? != Some(b'"') { return Ok(false); }
                let Some(id) = self.key()? else { return Ok(false); };
                if (seen & (1 << id)) != 0 || self.ws()? != Some(b':') { return Ok(false); }
                let lead = self.ws()?;
                let ok = if id == 0 { self.ver(lead)? } else {
                    let n = if lead == Some(b'"') { self.hex()? } else { None };
                    n == Some(24) && id == 1 || n.is_some_and(|n| id == 2 && n >= 32 && n.is_multiple_of(2))
                };
                if !ok { return Ok(false); }
                seen |= 1 << id;
                match self.ws()? {
                    Some(b',') => {}
                    Some(b'}') => return Ok(seen == 7 && self.ws()?.is_none()),
                    _ => return Ok(false),
                }
            }
        }
        fn ver(&mut self, lead: Option<u8>) -> io::Result<bool> {
            let good = matches!(lead, Some(b'1' | b'2'));
            let next = if good { self.byte()? } else { None };
            let bad = matches!(next, Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-'));
            if good && next.is_some() && !bad { self.i -= 1; }
            Ok(good && next.is_some() && !bad)
        }
    }
}
pub use scan::reads_as_plain_bytes;

pub fn is_plain_localhost_file(path: &Path) -> io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut header = [0u8; ENVELOPE_HEADER];
    let n = file.read(&mut header)?;
    note_sealed_bytes(n as u64);
    let (plain, extra) = reads_as_plain_bytes(&header[..n], len, &mut file)?;
    note_sealed_bytes(extra);
    Ok(plain)
}

pub fn read_plain_localhost_range(
    path: &Path,
    name: &str,
    offset: u64,
    length: Option<u64>,
) -> io::Result<Vec<u8>> {
    use std::io::{Seek, SeekFrom};
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    if offset >= len {
        return Ok(Vec::new());
    }
    let available = len - offset;
    let asked = length.unwrap_or(available).min(available);
    // No length on a file past the hard limit is the whole tail. Refuse it
    // even when the tail from this offset would fit: the file is past the limit.
    if asked > SEALED_READ_HARD_LIMIT || (length.is_none() && len > SEALED_READ_HARD_LIMIT) {
        return Err(hard_limit_refusal(name));
    }
    let want = usize::try_from(asked).unwrap_or(usize::MAX);
    file.seek(SeekFrom::Start(offset))?;
    let mut buffer = Vec::new();
    if buffer.try_reserve_exact(want).is_err() {
        return Err(hard_limit_refusal(name));
    }
    buffer.resize(want, 0);
    let mut filled = 0;
    while filled < want {
        let n = file.read(&mut buffer[filled..])?;
        if n == 0 {
            break;
        }
        note_sealed_bytes(n as u64);
        filled += n;
    }
    buffer.truncate(filled);
    Ok(buffer)
}

pub fn stream_plain_localhost_file(
    path: &Path,
    chunk: usize,
    mut each: impl FnMut(&[u8]) -> io::Result<()>,
) -> io::Result<u64> {
    let mut file = std::fs::File::open(path)?;
    let mut buffer = vec![0u8; chunk.max(1)];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            return Ok(total);
        }
        note_sealed_bytes(n as u64);
        each(&buffer[..n])?;
        total += n as u64;
    }
}

#[rustfmt::skip]
pub fn read_sealed_localhost_file(key: &[u8; 32], path: &Path, name: &str) -> io::Result<Vec<u8>> {
    let mut file = std::fs::File::open(path)?;
    let len = file.metadata()?.len();
    let mut header_buf = [0u8; ENVELOPE_HEADER];
    let read = file.read(&mut header_buf)?;
    note_sealed_bytes(read as u64);
    let header = &header_buf[..read];
    let (plain, extra) = reads_as_plain_bytes(header, len, &mut file)?;
    note_sealed_bytes(extra);
    if plain {
        if len > SEALED_READ_HARD_LIMIT { return Err(hard_limit_refusal(name)); }
        drop(file);
        return read_plain_localhost_range(path, name, 0, None);
    }
    if extra > 0 { std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(read as u64))?; }
    if len <= ENVELOPE_BYTE_LIMIT {
        let mut raw = header.to_vec();
        let room = (ENVELOPE_BYTE_LIMIT + 1).saturating_sub(read as u64);
        file.by_ref().take(room).read_to_end(&mut raw)?;
        note_sealed_bytes(raw.len() as u64 - read as u64);
        if raw.len() as u64 > ENVELOPE_BYTE_LIMIT {
            return Err(over_cap_refusal(name));
        }
        if header_is_file_key_envelope(&raw) || header_is_device_key_envelope(&raw) {
            return open_new_format(key, raw, name);
        }
        return decrypt_bytes(key, &raw);
    }
    if header_is_file_key_envelope(header) || header_is_device_key_envelope(header) {
        if len > SEALED_READ_HARD_LIMIT {
            return Err(hard_limit_refusal(name));
        }
        return open_new_format(
            key,
            read_body_within_hard_limit(&mut file, header, len, name)?,
            name,
        );
    }
    open_new_format(key, read_body_within_hard_limit(&mut file, header, len, name)?, name)
}

/// Version 1, a 12-byte hex nonce, and hex ciphertext of at least 16 bytes.
///
/// Field names alone are not the envelope. `encrypt_bytes` writes hex.
pub fn is_encrypted_envelope(data: &[u8]) -> bool {
    let Ok(object) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(data)
    else {
        return false;
    };
    if object.len() != 3
        || !matches!(
            object.get("version").and_then(|value| value.as_u64()),
            Some(1 | 2)
        )
    {
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

/// Encrypt raw bytes with AES-256-GCM, returning a version-1 JSON envelope.
pub fn encrypt_bytes(key: &[u8; 32], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    encrypt_version(key, plaintext, 1)
}

/// The envelope the file key writes. Its header is [`header_is_file_key_envelope`].
pub fn encrypt_file_key_bytes(key: &[u8; 32], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    encrypt_version(key, plaintext, FILE_KEY_ENVELOPE_VERSION)
}

fn encrypt_version(key: &[u8; 32], plaintext: &[u8], version: u8) -> io::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| io::Error::other(format!("encryption: {e}")))?;

    let envelope = EncryptedEnvelope {
        version,
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    };
    serde_json::to_vec(&envelope).map_err(|e| io::Error::other(format!("envelope serialize: {e}")))
}

/// What a device-key envelope became. The file bytes are dropped before the new envelope exists.
pub enum RekeyOutcome {
    /// Sealed with the file key.
    Rewritten(Vec<u8>),
    /// The file key already opens it.
    AlreadyFileKey,
    /// Not an envelope. The caller leaves the bytes alone.
    NotEnvelope,
}

/// Rewrite one device-key envelope.
///
/// The file buffer is reused for the new envelope. The plaintext is the only
/// extra buffer, and it is dropped before the new envelope is built. Peak
/// memory is the file plus the plaintext: under twice the file, because the
/// file is the hex encoding of that plaintext.
pub fn rekey_device_envelope(
    device_key: &[u8; 32],
    file_key: &[u8; 32],
    data: Vec<u8>,
) -> io::Result<RekeyOutcome> {
    let Some((mut buffer, nonce)) = ciphertext_in_place(data) else {
        return Ok(RekeyOutcome::NotEnvelope);
    };
    let mut plain = match decrypt_parts(device_key, &nonce, &buffer) {
        Ok(plain) => plain,
        Err(_) => {
            if let Ok(mut opened) = decrypt_parts(file_key, &nonce, &buffer) {
                opened.fill(0);
                return Ok(RekeyOutcome::AlreadyFileKey);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "does not decrypt",
            ));
        }
    };
    buffer.clear();
    buffer.extend_from_slice(&plain);
    plain.fill(0);
    drop(plain);
    seal_into(&mut buffer, file_key, FILE_KEY_ENVELOPE_VERSION)?;
    Ok(RekeyOutcome::Rewritten(buffer))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BorrowedEnvelope<'a> {
    version: u8,
    #[serde(borrow)]
    nonce: &'a str,
    #[serde(borrow)]
    ciphertext: &'a str,
}

/// Decode the ciphertext into the front of `data` and keep its allocation.
fn ciphertext_in_place(mut data: Vec<u8>) -> Option<(Vec<u8>, [u8; 12])> {
    let (start, hex_len, nonce) = {
        let envelope = serde_json::from_slice::<BorrowedEnvelope>(&data).ok()?;
        if envelope.version != 1 && envelope.version != 2 {
            return None;
        }
        let nonce_bytes = hex::decode(envelope.nonce).ok()?;
        let nonce: [u8; 12] = nonce_bytes.try_into().ok()?;
        let base = data.as_ptr() as usize;
        let ptr = envelope.ciphertext.as_ptr() as usize;
        if ptr < base || ptr + envelope.ciphertext.len() > base + data.len() {
            return None;
        }
        (ptr - base, envelope.ciphertext.len(), nonce)
    };
    if hex_len < 32 || hex_len % 2 != 0 || start + hex_len > data.len() {
        return None;
    }
    let n = hex_len / 2;
    for i in 0..n {
        let hi = hex_nibble(data[start + 2 * i])?;
        let lo = hex_nibble(data[start + 2 * i + 1])?;
        data[start + i] = (hi << 4) | lo;
    }
    data.copy_within(start..start + n, 0);
    data.truncate(n);
    Some((data, nonce))
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// `buffer` holds plaintext. The new envelope is written into that same allocation.
fn seal_into(buffer: &mut Vec<u8>, key: &[u8; 32], version: u8) -> io::Result<()> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    cipher
        .encrypt_in_place(&Nonce::from(nonce_bytes), b"", buffer)
        .map_err(|e| io::Error::other(format!("encryption: {e}")))?;
    let n = buffer.len();
    let prefix = format!(
        "{{\"version\":{version},\"nonce\":\"{}\",\"ciphertext\":\"",
        hex::encode(nonce_bytes)
    );
    let start = prefix.len();
    buffer.resize(start + n * 2, 0);
    buffer.copy_within(0..n, start);
    buffer[..start].copy_from_slice(prefix.as_bytes());
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    for i in (0..n).rev() {
        let byte = buffer[start + i];
        buffer[start + 2 * i] = HEX_DIGITS[(byte >> 4) as usize];
        buffer[start + 2 * i + 1] = HEX_DIGITS[(byte & 0x0f) as usize];
    }
    buffer.truncate(start + n * 2);
    buffer.extend_from_slice(br#""}"#);
    Ok(())
}

fn decrypt_parts(key: &[u8; 32], nonce: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    if nonce.len() != 12 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid nonce length {}", nonce.len()),
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| io::Error::other(format!("AES key init: {e}")))?;
    let nonce_array: [u8; 12] = nonce
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce length"))?;
    cipher
        .decrypt(&Nonce::from(nonce_array), ciphertext)
        .map_err(|e| io::Error::other(format!("decryption: {e}")))
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

    decrypt_parts(key, &nonce_bytes, &ct)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain_bytes(bytes: &[u8], len: u64) -> bool {
        let n = bytes.len().min(ENVELOPE_HEADER);
        reads_as_plain_bytes(&bytes[..n], len, &mut &bytes[n..])
            .unwrap()
            .0
    }

    struct Boom;

    impl Read for Boom {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("a file-key header was scanned");
        }
    }

    #[test]
    fn a_file_key_header_is_an_envelope_without_a_scan() {
        let (plain, extra) =
            reads_as_plain_bytes(FILE_KEY_ENVELOPE_PREFIX, ENVELOPE_BYTE_LIMIT + 1, &mut Boom)
                .unwrap();
        assert!(!plain);
        assert_eq!(extra, 0);
        let (plain, extra) = reads_as_plain_bytes(
            FILE_KEY_ENVELOPE_PREFIX,
            SEALED_READ_HARD_LIMIT + 1,
            &mut Boom,
        )
        .unwrap();
        assert!(!plain);
        assert_eq!(extra, 0);
    }

    #[test]
    fn an_old_header_is_an_envelope_without_a_scan() {
        let sealed = encrypt_bytes(&[4; 32], b"x").unwrap();
        assert!(header_is_device_key_envelope(&sealed));
        assert!(!header_is_file_key_envelope(&sealed));
        let (plain, extra) = reads_as_plain_bytes(
            &sealed[..ENVELOPE_HEADER],
            ENVELOPE_BYTE_LIMIT + 1,
            &mut Boom,
        )
        .unwrap();
        assert!(!plain);
        assert_eq!(extra, 0);
        let (plain, extra) = reads_as_plain_bytes(
            &sealed[..ENVELOPE_HEADER],
            SEALED_READ_HARD_LIMIT + 1,
            &mut Boom,
        )
        .unwrap();
        assert!(!plain);
        assert_eq!(extra, 0);
        assert!(!header_is_device_key_envelope(
            br#"{"version":1,"nonce":"00112233445566778899aabb","ciphertext":"g"#
        ));
        assert!(plain_bytes(
            br#"{"version":1,"name":"ada""#,
            ENVELOPE_BYTE_LIMIT + 1
        ));
        assert!(!header_is_device_key_envelope(FILE_KEY_ENVELOPE_PREFIX));
    }

    #[test]
    fn a_device_envelope_is_rewritten_in_its_own_buffer() {
        let device = [1u8; 32];
        let file = [2u8; 32];
        let sealed = encrypt_bytes(&device, b"hello").unwrap();
        match rekey_device_envelope(&device, &file, sealed).unwrap() {
            RekeyOutcome::Rewritten(next) => {
                assert!(header_is_file_key_envelope(&next));
                assert_eq!(decrypt_bytes(&file, &next).unwrap(), b"hello");
                assert!(decrypt_bytes(&device, &next).is_err());
            }
            RekeyOutcome::AlreadyFileKey | RekeyOutcome::NotEnvelope => {
                panic!("a device envelope was not rewritten")
            }
        }
        let again = encrypt_file_key_bytes(&file, b"hello").unwrap();
        assert!(matches!(
            rekey_device_envelope(&device, &file, again).unwrap(),
            RekeyOutcome::AlreadyFileKey
        ));
        assert!(matches!(
            rekey_device_envelope(&device, &file, b"plain".to_vec()).unwrap(),
            RekeyOutcome::NotEnvelope
        ));
    }

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
        let opened = read_sealed_localhost_file(&key, &plain, "Users/video.bin").unwrap();
        assert!(opened.starts_with(b"ftyp"), "{:?}", &opened[..4]);
        assert_eq!(opened.len() as u64, ENVELOPE_BYTE_LIMIT + 1);
        assert!(
            opened.capacity() <= opened.len() + 8,
            "capacity {}",
            opened.capacity()
        );
        let slice = read_plain_localhost_range(&plain, "Users/video.bin", 0, Some(4)).unwrap();
        assert_eq!(slice, b"ftyp");
        assert!(slice.capacity() <= 8);

        let brace = dir.path().join("brace.bin");
        std::fs::write(&brace, b"{not-an-envelope").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&brace)
            .unwrap()
            .set_len(ENVELOPE_BYTE_LIMIT + 1)
            .unwrap();
        let opened = read_sealed_localhost_file(&key, &brace, "Users/brace.bin").unwrap();
        assert!(
            opened.starts_with(b"{not-an-envelope"),
            "{:?}",
            &opened[..16]
        );
        assert_eq!(opened.len() as u64, ENVELOPE_BYTE_LIMIT + 1);

        let small = dir.path().join("small.bin");
        let sealed = encrypt_bytes(&key, b"small").unwrap();
        std::fs::write(&small, &sealed).unwrap();
        assert_eq!(
            read_sealed_localhost_file(&key, &small, "Users/small.bin").unwrap(),
            b"small"
        );
    }

    #[test]
    fn a_file_over_the_hard_limit_is_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.bin");
        std::fs::write(&path, b"{not-loaded").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(SEALED_READ_HARD_LIMIT + 1)
            .unwrap();
        let _ = take_sealed_read_bytes();
        let err = read_sealed_localhost_file(&[3u8; 32], &path, "Users/huge.bin").unwrap_err();
        let text = err.to_string();
        assert!(text.contains("Users/huge.bin"), "{text}");
        assert!(text.contains("larger than this process can read"), "{text}");
        assert!(text.contains("Move it out of the folder."), "{text}");
        assert!(!text.contains("then restart"), "{text}");
        assert!(take_sealed_read_bytes() <= ENVELOPE_HEADER as u64);
        assert!(header_is_file_key_envelope(
            &encrypt_file_key_bytes(&[3u8; 32], b"mark").unwrap()
        ));
    }

    #[test]
    fn a_40_mib_plain_file_is_one_buffer_a_slice_and_a_stream() {
        const SIZE: u64 = 40 * 1024 * 1024;
        assert!(plain_bytes(b"ftyp", SIZE));
        assert!(plain_bytes(br#"{"note":"plain"#, SIZE));
        assert!(plain_bytes(b"{\n  \"records\":[", SIZE));
        assert!(plain_bytes(b"{ \"records\":[", SIZE));
        assert!(!plain_bytes(
            br#"{"version":1,"nonce":"00112233445566778899aabb","ciphertext":"00112233445566778899aabbccddeeff"}"#,
            SIZE
        ));
        assert!(!plain_bytes(
            br#"{"version":2,"nonce":"00112233445566778899aabb","ciphertext":"00112233445566778899aabbccddeeff"}"#,
            SIZE
        ));
        assert!(!plain_bytes(
            b"{\n\"version\": 2,\"nonce\":\"00112233445566778899aabb\",\"ciphertext\":\"00112233445566778899aabbccddeeff\"}",
            SIZE
        ));
        assert!(!plain_bytes(br#"{"note":"plain"#, 32));
        let mut spaced = vec![b'{'];
        spaced.extend(std::iter::repeat_n(b' ', 80));
        spaced.extend(br#""records":["#);
        assert!(
            plain_bytes(&spaced, SIZE),
            "a records key past the 64-byte look stayed sealed"
        );

        let dir = tempfile::tempdir().unwrap();
        let key = [9u8; 32];
        let video = dir.path().join("video.bin");
        std::fs::write(&video, b"ftyp").unwrap();
        let marker_at = 20 * 1024 * 1024;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&video)
            .unwrap();
        use std::io::{Seek, Write};
        file.seek(std::io::SeekFrom::Start(marker_at)).unwrap();
        file.write_all(b"MARK").unwrap();
        file.set_len(SIZE).unwrap();
        drop(file);

        let _ = take_sealed_read_bytes();
        assert!(is_plain_localhost_file(&video).unwrap());
        let slice =
            read_plain_localhost_range(&video, "Users/video.bin", marker_at, Some(4)).unwrap();
        assert_eq!(slice, b"MARK");
        assert!(slice.capacity() <= 8);
        let peeked = take_sealed_read_bytes();
        assert!(peeked <= 4 + 64, "a slice read the body: {peeked}");

        let _ = take_sealed_read_bytes();
        let mut digest = 0u64;
        let mut widest = 0usize;
        let streamed = stream_plain_localhost_file(&video, 64 * 1024, |chunk| {
            widest = widest.max(chunk.len());
            for byte in chunk {
                digest = digest.wrapping_add(*byte as u64);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(streamed, SIZE);
        assert_eq!(digest, 750);
        assert!(widest <= 64 * 1024);
        assert!(take_sealed_read_bytes() <= SIZE + 64);

        let _ = take_sealed_read_bytes();
        let whole = read_sealed_localhost_file(&key, &video, "Users/video.bin").unwrap();
        assert_eq!(whole.len() as u64, SIZE);
        assert!(whole.starts_with(b"ftyp"));
        assert_eq!(&whole[marker_at as usize..marker_at as usize + 4], b"MARK");
        assert!(whole.capacity() <= SIZE as usize + 8);
        assert!(take_sealed_read_bytes() <= SIZE + 64);
        drop(whole);

        let json_path = dir.path().join("note.json");
        std::fs::write(&json_path, br#"{"note":"plain"#).unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&json_path)
            .unwrap()
            .set_len(SIZE)
            .unwrap();
        let _ = take_sealed_read_bytes();
        assert!(is_plain_localhost_file(&json_path).unwrap());
        let json_slice =
            read_plain_localhost_range(&json_path, "Users/note.json", 0, Some(7)).unwrap();
        assert_eq!(json_slice, br#"{"note""#);
        assert!(take_sealed_read_bytes() <= 7 + 64);
        let json_whole = read_sealed_localhost_file(&key, &json_path, "Users/note.json").unwrap();
        assert_eq!(json_whole.len() as u64, SIZE);
        assert!(json_whole.starts_with(br#"{"note":"plain"#));
        assert!(json_whole.capacity() <= SIZE as usize + 8);

        let small = dir.path().join("small.json");
        std::fs::write(&small, br#"{"note":"plain"}"#).unwrap();
        let err = read_sealed_localhost_file(&key, &small, "Users/small.json").unwrap_err();
        assert!(
            err.to_string().contains("not an encrypted envelope"),
            "{err}"
        );

        let sealed_compact = encrypt_file_key_bytes(&key, b"secret-envelope").unwrap();
        let compact_path = dir.path().join("compact.bin");
        std::fs::write(&compact_path, &sealed_compact).unwrap();
        assert_eq!(
            read_sealed_localhost_file(&key, &compact_path, "Users/compact.bin").unwrap(),
            b"secret-envelope"
        );
        let mut sealed = sealed_compact;
        sealed.insert(1, b'\n');
        assert!(
            !plain_bytes(&sealed, SIZE),
            "a version envelope with white space was plain"
        );
        assert_eq!(decrypt_bytes(&key, &sealed).unwrap(), b"secret-envelope");
        let spaced_path = dir.path().join("spaced.bin");
        std::fs::write(&spaced_path, &sealed).unwrap();
        assert_eq!(
            read_sealed_localhost_file(&key, &spaced_path, "Users/spaced.bin").unwrap(),
            b"secret-envelope"
        );
    }

    struct Fill<'a> {
        pre: &'a [u8],
        pre_at: usize,
        left: u64,
        post: &'a [u8],
        post_at: usize,
    }

    impl Read for Fill<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.pre_at < self.pre.len() {
                let n = (self.pre.len() - self.pre_at).min(buf.len());
                buf[..n].copy_from_slice(&self.pre[self.pre_at..self.pre_at + n]);
                self.pre_at += n;
                return Ok(n);
            }
            if self.left > 0 {
                let n = (self.left as usize).min(buf.len());
                buf[..n].fill(b'a');
                self.left -= n as u64;
                return Ok(n);
            }
            if self.post_at < self.post.len() {
                let n = (self.post.len() - self.post_at).min(buf.len());
                buf[..n].copy_from_slice(&self.post[self.post_at..self.post_at + n]);
                self.post_at += n;
                return Ok(n);
            }
            Ok(0)
        }
    }

    fn envelope_parts(order: [&str; 3], version: &str, nonce: &str) -> (Vec<u8>, Vec<u8>) {
        let mut pre = vec![b'{'];
        let mut post = Vec::new();
        let mut after = false;
        for (i, key) in order.iter().enumerate() {
            let dest = if after { &mut post } else { &mut pre };
            if i > 0 {
                dest.push(b',');
            }
            dest.extend(format!("\"{key}\":").bytes());
            match *key {
                "version" => dest.extend(version.bytes()),
                "nonce" => {
                    dest.push(b'"');
                    dest.extend(nonce.bytes());
                    dest.push(b'"');
                }
                "ciphertext" => dest.push(b'"'),
                _ => panic!("{key}"),
            }
            if *key == "ciphertext" {
                after = true;
                post.push(b'"');
            }
        }
        post.push(b'}');
        (pre, post)
    }

    fn decide(mut body: impl Read, len: u64) -> (bool, u64) {
        let mut header = [0u8; ENVELOPE_HEADER];
        let n = body.read(&mut header).unwrap();
        let (plain, extra) = reads_as_plain_bytes(&header[..n], len, &mut body).unwrap();
        (plain, n as u64 + extra)
    }

    #[test]
    fn an_envelope_is_what_the_openers_could_open() {
        const MID: u64 = 40 * 1024 * 1024;
        const BIG: u64 = SEALED_READ_HARD_LIMIT + 1;
        let nonce = "00112233445566778899aabb";
        let orders = [
            ["version", "nonce", "ciphertext"],
            ["version", "ciphertext", "nonce"],
            ["nonce", "version", "ciphertext"],
            ["nonce", "ciphertext", "version"],
            ["ciphertext", "version", "nonce"],
            ["ciphertext", "nonce", "version"],
        ];
        for order in orders {
            for len in [MID, BIG] {
                let (pre, mut post) = envelope_parts(order, "1", nonce);
                let mut span = pre.len() + post.len();
                if (len - span as u64) % 2 == 1 {
                    let end = post.len() - 1;
                    post.insert(end, b' ');
                    span += 1;
                }
                let fill = len - span as u64;
                assert!(fill >= 32 && fill.is_multiple_of(2), "{fill}");
                let started = std::time::Instant::now();
                let (plain, read) = decide(
                    Fill {
                        pre: &pre,
                        pre_at: 0,
                        left: fill,
                        post: &post,
                        post_at: 0,
                    },
                    len,
                );
                let elapsed = started.elapsed();
                assert!(!plain, "{order:?} at {len} was plain");
                assert_eq!(read, len, "{order:?} stopped at {read}");
                if len == BIG && order[0] == "ciphertext" {
                    eprintln!("1 GiB envelope scan: {elapsed:?} order {order:?}");
                }
            }
        }
        let shapes = [
            r#"{"version":10,"records":["#,
            r#"{"version":2026,"records":["#,
            r#"{"version":"1","records":["#,
            r#"{"version":1.0,"records":["#,
            r#"{"version":{"version":1},"records":["#,
            r#"{"version":1,"version":1,"nonce":"aa""#,
        ];
        for shape in shapes {
            for len in [MID, BIG] {
                let (plain, read) = decide(
                    Fill {
                        pre: shape.as_bytes(),
                        pre_at: 0,
                        left: len.saturating_sub(shape.len() as u64),
                        post: b"",
                        post_at: 0,
                    },
                    len,
                );
                assert!(plain, "{shape} at {len} was an envelope");
                assert!(read <= ENVELOPE_HEADER as u64, "{shape} read {read}");
            }
        }
        let mut past = vec![b'{'];
        past.extend(std::iter::repeat_n(b' ', 80));
        past.extend(br#""records":["#);
        for len in [MID, BIG] {
            let (plain, read) = decide(
                Fill {
                    pre: &past,
                    pre_at: 0,
                    left: len.saturating_sub(past.len() as u64),
                    post: b"",
                    post_at: 0,
                },
                len,
            );
            assert!(plain, "records past the look at {len}");
            assert!(
                read <= ENVELOPE_HEADER as u64 + 8192,
                "records past the look read {read}"
            );
        }

        let key = [9u8; 32];
        let sealed = encrypt_bytes(&key, b"secret").unwrap();
        let v10 = String::from_utf8(sealed.clone()).unwrap().replacen(
            "\"version\":1",
            "\"version\":10",
            1,
        );
        assert_eq!(decrypt_bytes(&key, v10.as_bytes()).unwrap(), b"secret");
        assert!(plain_bytes(v10.as_bytes(), MID));
        assert!(matches!(
            rekey_device_envelope(&key, &[3u8; 32], v10.into_bytes()).unwrap(),
            RekeyOutcome::NotEnvelope
        ));
        let dup = format!(
            r#"{{"version":1,"version":1,"nonce":"{nonce}","ciphertext":"00112233445566778899aabbccddeeff"}}"#
        );
        assert!(decrypt_bytes(&key, dup.as_bytes()).is_err());
        assert!(plain_bytes(dup.as_bytes(), MID));

        let plain_text = vec![0u8; 20 * 1024 * 1024];
        let real = encrypt_bytes(&key, &plain_text).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&real).unwrap();
        let object = value.as_object().unwrap();
        let mut map = serde_json::Map::new();
        for name in ["ciphertext", "nonce", "version"] {
            map.insert(name.to_string(), object[name].clone());
        }
        let reordered = serde_json::to_vec(&serde_json::Value::Object(map)).unwrap();
        assert!(reordered.starts_with(br#"{"ciphertext":"#));
        assert!(!plain_bytes(&reordered, reordered.len() as u64));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reordered.bin");
        std::fs::write(&path, &reordered).unwrap();
        assert_eq!(
            read_sealed_localhost_file(&key, &path, "Users/reordered.bin").unwrap(),
            plain_text
        );
    }
}
