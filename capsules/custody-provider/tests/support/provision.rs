//! Custody fixtures use the product provisioning launcher.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use elastos_runtime::provider::{CheckedExecutable, ProviderBridge, CUSTODY_STATE_ROOT_RELATIVE};
use sha2::{Digest, Sha256};

/// Prepare exactly the state directory that the product fence admits.
pub fn state_root(data_dir: &Path) -> PathBuf {
    let data_dir = fs::canonicalize(data_dir).unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let state = data_dir.join(CUSTODY_STATE_ROOT_RELATIVE);
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&state)
        .unwrap();
    state
}

pub(super) fn checked(binary: &Path, data_dir: &Path) -> CheckedExecutable {
    let checksum = format!("sha256:{:x}", Sha256::digest(fs::read(binary).unwrap()));
    CheckedExecutable::pinned(binary, &checksum)
        .unwrap()
        .with_home_data_dir(data_dir)
}

/// A separate thread also permits use inside an existing async test runtime.
pub fn provision(binary: &Path, state: &Path, issuer: &str) -> Vec<u8> {
    let data_dir = state.ancestors().nth(3).expect("custody data directory");
    assert_eq!(state_root(data_dir), state, "use the product custody root");
    let executable = checked(binary, data_dir);
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(ProviderBridge::spawn_custody_provision(
                        &executable,
                        data_dir,
                        issuer,
                        8 * 1024,
                        Duration::from_secs(5),
                    ))
                    .unwrap_or_else(|error| panic!("fenced custody provisioning: {error}"))
            })
            .join()
            .unwrap()
    })
}
