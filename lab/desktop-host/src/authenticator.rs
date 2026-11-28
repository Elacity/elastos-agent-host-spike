//! The app's own passkeys for Home (ELASTOS-DESKTOP-APP P6, LAB DRAFT).
//!
//! macOS gives an app's web view passkeys only for web domains linked to the app,
//! and Home's passkeys belong to `localhost`. So the app answers Home's passkey
//! requests itself, as a browser's built-in authenticator does: keys live in this
//! Mac's Secure Enclave and sign only after Touch ID or the Mac password. Home's
//! server sees a normal passkey (`none` attestation, ES256) from its own origin.
//! On Linux the keys live in the TPM security chip instead (`tpm.rs`).

use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8090";
const ES256: i64 = -7;

#[cfg(target_os = "linux")]
use crate::tpm as key;

#[cfg(target_os = "macos")]
mod key {
    use std::ffi::CString;

    extern "C" {
        fn elastos_enclave_epoch() -> u64;
        fn elastos_enclave_cancel();
        fn elastos_enclave_create(
            expected: u64,
            reason: *const libc::c_char,
            blob: *mut u8,
            blob_cap: usize,
            blob_len: *mut usize,
            public_key: *mut u8,
        ) -> i32;
        fn elastos_enclave_sign(
            expected: u64,
            blob: *const u8,
            blob_len: usize,
            message: *const u8,
            message_len: usize,
            reason: *const libc::c_char,
            signature: *mut u8,
            signature_cap: usize,
            signature_len: *mut usize,
        ) -> i32;
    }

    pub fn epoch() -> u64 {
        unsafe { elastos_enclave_epoch() }
    }

    pub fn cancel() {
        unsafe { elastos_enclave_cancel() }
    }

    pub fn create(expected: u64) -> Result<(Vec<u8>, [u8; 65]), ()> {
        let reason = CString::new("save a passkey for your ElastOS Home").unwrap();
        let mut blob = vec![0u8; 4096];
        let mut blob_len = 0usize;
        let mut point = [0u8; 65];
        let status = unsafe {
            elastos_enclave_create(
                expected,
                reason.as_ptr(),
                blob.as_mut_ptr(),
                blob.len(),
                &mut blob_len,
                point.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(());
        }
        blob.truncate(blob_len);
        Ok((blob, point))
    }

    pub fn sign(expected: u64, blob: &[u8], message: &[u8], reason: &str) -> Result<Vec<u8>, ()> {
        let reason = CString::new(reason).map_err(|_| ())?;
        let mut signature = [0u8; 128];
        let mut signature_len = 0usize;
        let status = unsafe {
            elastos_enclave_sign(
                expected,
                blob.as_ptr(),
                blob.len(),
                message.as_ptr(),
                message.len(),
                reason.as_ptr(),
                signature.as_mut_ptr(),
                signature.len(),
                &mut signature_len,
            )
        };
        if status != 0 {
            return Err(());
        }
        Ok(signature[..signature_len].to_vec())
    }
}

/// The answer to one request from the Home window, in the form the window script
/// returns to Home: base64url JSON with the credential or a refusal name. A new
/// passkey also returns its id: it stays pending until `settle`.
pub fn answer(request: &str) -> (String, Option<String>) {
    let epoch = key::epoch();
    let parsed = B64
        .decode(request)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let id = parsed
        .as_ref()
        .and_then(|value| value["id"].as_str())
        .unwrap_or_default()
        .to_owned();
    let result = parsed.as_ref().ok_or("NotAllowedError").and_then(|value| {
        let options = &value["publicKey"];
        match value["kind"].as_str() {
            Some("create") => create(options, epoch),
            Some("get") => get(options, epoch),
            _ => Err("NotSupportedError"),
        }
    });
    let created = result
        .as_ref()
        .ok()
        .filter(|_| {
            parsed
                .as_ref()
                .is_some_and(|value| value["kind"] == "create")
        })
        .and_then(|credential| credential["id"].as_str())
        .map(str::to_owned);
    let body = match result {
        Ok(credential) => json!({ "v": 1, "id": id, "ok": true, "credential": credential }),
        Err(name) => json!({ "v": 1, "id": id, "ok": false, "name": name }),
    };
    (B64.encode(body.to_string()), created)
}

/// Ends a Touch ID in progress for a page that is gone; a request still waiting
/// (for example on the account dialog) is refused before Touch ID.
pub fn cancel() {
    key::cancel()
}

/// Keeps a pending passkey once the page that asked has it; otherwise deletes it,
/// so sign-in never offers a passkey Home was never given.
pub fn settle(id: &str, delivered: bool) {
    let (Some(pending), Some(kept)) = (pending_path(id), credential_path(id)) else {
        return;
    };
    if !delivered || fs::rename(&pending, kept).is_err() {
        let _ = fs::remove_file(pending);
    }
}

fn store() -> PathBuf {
    let home = crate::runtime::lab_home()
        .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
        .unwrap_or_default();
    if cfg!(target_os = "macos") {
        home.join("Library/Application Support/ElastOS Lab/passkeys")
    } else {
        home.join(".local/share/elastos-lab/passkeys")
    }
}

fn credential_path(id: &str) -> Option<PathBuf> {
    let valid = !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    valid.then(|| store().join(format!("{id}.json")))
}

fn pending_path(id: &str) -> Option<PathBuf> {
    credential_path(id).map(|path| path.with_extension("pending"))
}

fn challenge(options: &Value) -> Result<&str, &'static str> {
    let challenge = options["challenge"].as_str().ok_or("NotAllowedError")?;
    B64.decode(challenge).map_err(|_| "NotAllowedError")?;
    Ok(challenge)
}

fn client_data(kind: &str, challenge: &str) -> String {
    json!({ "type": kind, "challenge": challenge, "origin": ORIGIN, "crossOrigin": false })
        .to_string()
}

fn rp_id_hash() -> [u8; 32] {
    Sha256::digest(RP_ID.as_bytes()).into()
}

fn cbor_head(major: u8, value: usize, out: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => out.extend([major | 24, value as u8]),
        _ => {
            out.push(major | 25);
            out.extend((value as u16).to_be_bytes());
        }
    }
}

fn cbor_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    cbor_head(2, bytes.len(), out);
    out.extend(bytes);
}

fn cbor_text(text: &str, out: &mut Vec<u8>) {
    cbor_head(3, text.len(), out);
    out.extend(text.as_bytes());
}

/// COSE_Key for an ES256 public key: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
fn cose_key(point: &[u8; 65]) -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21];
    cbor_bytes(&point[1..33], &mut out);
    out.push(0x22);
    cbor_bytes(&point[33..], &mut out);
    out
}

fn create(options: &Value, epoch: u64) -> Result<Value, &'static str> {
    if options["rp"]["id"].as_str().is_some_and(|rp| rp != RP_ID) {
        return Err("SecurityError");
    }
    let es256 = options["pubKeyCredParams"]
        .as_array()
        .is_some_and(|params| params.iter().any(|p| p["alg"].as_i64() == Some(ES256)));
    if !es256 {
        return Err("NotSupportedError");
    }
    let challenge = challenge(options)?;
    let user_id = options["user"]["id"].as_str().ok_or("NotAllowedError")?;
    B64.decode(user_id).map_err(|_| "NotAllowedError")?;
    let excluded = options["excludeCredentials"]
        .as_array()
        .into_iter()
        .flatten();
    for credential in excluded {
        let held = credential["id"]
            .as_str()
            .and_then(credential_path)
            .is_some_and(|path| path.exists());
        if held {
            return Err("InvalidStateError");
        }
    }

    let (blob, point) = key::create(epoch).map_err(|()| "NotAllowedError")?;

    let mut raw_id = [0u8; 32];
    #[cfg(target_os = "macos")]
    unsafe {
        libc::arc4random_buf(raw_id.as_mut_ptr().cast(), raw_id.len())
    };
    #[cfg(target_os = "linux")]
    if unsafe { libc::getrandom(raw_id.as_mut_ptr().cast(), raw_id.len(), 0) } != 32 {
        return Err("UnknownError");
    }
    let id = B64.encode(raw_id);
    let path = pending_path(&id).ok_or("UnknownError")?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(store())
        .map_err(|_| "UnknownError")?;
    let record = json!({
        "rp_id": RP_ID,
        "user_id": user_id,
        "user_name": options["user"]["name"].as_str().unwrap_or_default(),
        "key": B64.encode(&blob),
        "created": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_default(),
    });
    fs::File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(record.to_string().as_bytes()))
        .map_err(|_| "UnknownError")?;

    let mut auth_data = rp_id_hash().to_vec();
    auth_data.push(0x45); // user present, user verified, attested credential data
    auth_data.extend(0u32.to_be_bytes());
    auth_data.extend([0u8; 16]);
    auth_data.extend((raw_id.len() as u16).to_be_bytes());
    auth_data.extend(raw_id);
    auth_data.extend(cose_key(&point));
    let mut attestation = vec![0xa3];
    cbor_text("fmt", &mut attestation);
    cbor_text("none", &mut attestation);
    cbor_text("attStmt", &mut attestation);
    attestation.push(0xa0);
    cbor_text("authData", &mut attestation);
    cbor_bytes(&auth_data, &mut attestation);

    Ok(json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "clientDataJSON": B64.encode(client_data("webauthn.create", challenge)),
            "attestationObject": B64.encode(attestation),
        },
    }))
}

fn held(id: &str) -> Option<Value> {
    let record: Value = serde_json::from_slice(&fs::read(credential_path(id)?).ok()?).ok()?;
    (record["rp_id"] == RP_ID).then_some(record)
}

fn account(record: &Value) -> String {
    let name: String = record["user_name"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    if name.is_empty() {
        "this account".to_owned()
    } else {
        name
    }
}

/// When the passkey was saved, in local time ("31 Oct 2026, 17:05").
fn saved_at(record: &Value) -> String {
    let Some(time) = record["created"].as_i64() else {
        return String::new();
    };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&time, &mut tm) }.is_null() {
        return String::new();
    }
    let mut out = [0u8; 64];
    let len = unsafe {
        libc::strftime(
            out.as_mut_ptr().cast(),
            out.len(),
            c"%e %b %Y, %H:%M".as_ptr(),
            &tm,
        )
    };
    String::from_utf8_lossy(&out[..len]).trim().to_owned()
}

/// With more than one passkey saved, the person picks the account, newest first.
fn choose(mut passkeys: Vec<(String, Value)>) -> Option<(String, Value)> {
    if passkeys.len() < 2 {
        return passkeys.pop();
    }
    let count = passkeys.len();
    let mut n = 0;
    loop {
        let shown = rfd::MessageDialog::new()
            .set_title("ElastOS")
            .set_description(format!(
                "Sign in to your ElastOS Home as {}? This passkey was saved {}. (passkey {} of {count})",
                account(&passkeys[n].1),
                saved_at(&passkeys[n].1),
                n + 1
            ))
            .set_buttons(rfd::MessageButtons::YesNoCancelCustom(
                "Sign In".to_owned(),
                "Other Account".to_owned(),
                "Cancel".to_owned(),
            ))
            .show();
        match shown {
            rfd::MessageDialogResult::Custom(button) if button == "Sign In" => {
                return Some(passkeys.swap_remove(n))
            }
            rfd::MessageDialogResult::Custom(button) if button == "Other Account" => {
                n = (n + 1) % count
            }
            _ => return None,
        }
    }
}

fn get(options: &Value, epoch: u64) -> Result<Value, &'static str> {
    if options["rpId"].as_str().is_some_and(|rp| rp != RP_ID) {
        return Err("SecurityError");
    }
    let challenge = challenge(options)?;
    let allowed: Vec<&str> = options["allowCredentials"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|credential| credential["id"].as_str())
        .collect();
    let chosen = if allowed.is_empty() {
        let mut saved: Vec<(String, Value)> = fs::read_dir(store())
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let id = name.strip_suffix(".json")?.to_owned();
                held(&id).map(|record| (id, record))
            })
            .collect();
        saved.sort_by_key(|(_, record)| {
            std::cmp::Reverse(record["created"].as_u64().unwrap_or_default())
        });
        choose(saved)
    } else {
        allowed
            .into_iter()
            .find_map(|id| held(id).map(|record| (id.to_owned(), record)))
    };
    let (id, record) = chosen.ok_or("NotAllowedError")?;
    let blob = record["key"]
        .as_str()
        .and_then(|key| B64.decode(key).ok())
        .ok_or("UnknownError")?;

    let client_data = client_data("webauthn.get", challenge);
    let mut auth_data = rp_id_hash().to_vec();
    auth_data.push(0x05); // user present, user verified
    auth_data.extend(0u32.to_be_bytes());
    let mut message = auth_data.clone();
    message.extend(Sha256::digest(client_data.as_bytes()));

    let reason = format!("sign in to your ElastOS Home as {}", account(&record));
    let signature =
        key::sign(epoch, &blob, &message, &reason).map_err(|()| "NotAllowedError")?;

    Ok(json!({
        "id": id,
        "rawId": id,
        "type": "public-key",
        "response": {
            "clientDataJSON": B64.encode(client_data),
            "authenticatorData": B64.encode(auth_data),
            "signature": B64.encode(&signature),
            "userHandle": record["user_id"],
        },
    }))
}
