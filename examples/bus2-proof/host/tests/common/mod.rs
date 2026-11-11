//! Shared by the proof tests: the built guests, componentized.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// A guest's core module from `target/wasm32-unknown-unknown/release`,
/// componentized. `verify.sh` builds the guests first.
pub fn guest(name: &str) -> Vec<u8> {
    let path = root()
        .join("target/wasm32-unknown-unknown/release")
        .join(format!("{name}.wasm"));
    let core = std::fs::read(&path).unwrap_or_else(|err| {
        panic!(
            "{}: {err}; build the guests first (./verify.sh)",
            path.display()
        )
    });
    bus2_host::componentize(&core).unwrap()
}

pub fn fixture(name: &str) -> Vec<u8> {
    wat::parse_file(root().join("fixtures").join(name)).unwrap()
}

/// Runs `f` on its own thread with a single-threaded tokio runtime, and fails
/// if it gives no result within `limit`. A guest that starves the executor
/// cannot time itself out, so the watchdog is outside it.
pub fn within<R: Send + 'static>(
    limit: std::time::Duration,
    f: impl std::future::Future<Output = R> + Send + 'static,
) -> R {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let local = tokio::task::LocalSet::new();
        let _ = sender.send(local.block_on(&runtime, f));
    });
    match receiver.recv_timeout(limit) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            panic!("watchdog: no result within {limit:?}")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            panic!("the run panicked; see its output above")
        }
    }
}

// ---- Test credentials ----
//
// The photo guest pins the test publisher's key in its capsule.json. The
// seeds are the SHA-256 of fixed labels: test keys, not real ones.

pub const PUBLISHER_LABEL: &[u8] = b"elastos bus2-proof test publisher (not a real key)";
pub const OTHER_LABEL: &[u8] = b"elastos bus2-proof other key (not a real key)";
pub const PUBLISHER_DID: &str = "did:key:z6MkoJQGyiFajdmdvoaFYk6g6FotMRiqSJHbssfFhFR2J7n4";
pub const OTHER_DID: &str = "did:key:z6Mkk5hSU3e5gkYprGUeXwEV1oq8DCopYapGbJ51BSmuxfvS";
pub const KIND: &str = "elastos.bus2-proof.licence/v1";
pub const TAG: &str = "elastos:bus2-proof:credential:v1";

pub fn key(label: &[u8]) -> ed25519_dalek::SigningKey {
    use sha2::Digest as _;
    ed25519_dalek::SigningKey::from_bytes(&sha2::Sha256::digest(label).into())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// The message the guest checks: tag, kind and subject hash, one per line.
pub fn message(tag: &str, kind: &str, subject_sha256: &str) -> Vec<u8> {
    format!("{tag}\n{kind}\n{subject_sha256}").into_bytes()
}

pub fn credential(
    kind: &str,
    signer: &str,
    subject_sha256: &str,
    key: &ed25519_dalek::SigningKey,
    message: &[u8],
) -> bus2_host::Credential {
    use ed25519_dalek::Signer as _;
    bus2_host::Credential {
        kind: kind.to_string(),
        signer: signer.to_string(),
        subject_sha256: subject_sha256.to_string(),
        body: key.sign(message).to_bytes().to_vec(),
    }
}

/// A good licence for `bytes` from the pinned publisher.
pub fn licence(bytes: &[u8]) -> bus2_host::Credential {
    let subject = sha256_hex(bytes);
    credential(
        KIND,
        PUBLISHER_DID,
        &subject,
        &key(PUBLISHER_LABEL),
        &message(TAG, KIND, &subject),
    )
}
