//! Windows has no digest-checked native provider start.
//! The public types stay available. Verification and spawn preparation refuse
//! before the installed file is opened, so Windows never runs it unchecked.

use std::path::{Path, PathBuf};

pub(super) const WINDOWS_CHECKED_PROVIDER: &str =
    "verified native providers are not supported on Windows yet";

#[derive(Debug)]
pub struct PreparedExecutable {
    exec_path: PathBuf,
}

impl PreparedExecutable {
    pub(super) fn exec_path(&self) -> &Path {
        &self.exec_path
    }
}

/// Copy recovery belongs to macOS. Windows has no verified copies to remove.
pub fn recover_verified_copies(data_dir: &Path) -> Result<(), String> {
    let _ = data_dir;
    Ok(())
}

/// The release owner supplies the signed component checksum. On Windows the
/// pin is still parsed, and every start refuses.
pub struct CheckedExecutable {
    path: PathBuf,
    refusal: Option<String>,
}

fn accepted_pin(checksum: &str) -> Result<(), String> {
    let hex_digits = checksum.strip_prefix("sha256:").unwrap_or("");
    let bytes = hex::decode(hex_digits)
        .map_err(|_| "provider executable has an invalid SHA-256 release pin")?;
    let _digest: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "provider executable has an invalid SHA-256 release pin")?;
    Ok(())
}

impl CheckedExecutable {
    pub fn pinned(path: &Path, checksum: &str) -> Result<Self, String> {
        accepted_pin(checksum)?;
        Ok(Self {
            path: path.to_path_buf(),
            refusal: None,
        })
    }

    pub fn refused(path: &Path, reason: String) -> Self {
        Self {
            path: path.to_path_buf(),
            refusal: Some(reason),
        }
    }

    /// Bind the verified provider's private copy to the Home it serves.
    /// Windows does not make that copy.
    pub fn with_home_data_dir(self, data_dir: &Path) -> Self {
        let _ = data_dir;
        self
    }

    /// Names a companion file the provider finds beside its own executable.
    /// Windows does not start the provider, so the companion is not linked.
    pub fn with_sibling(self, name: &'static str) -> Self {
        let _ = name;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn verify_at_spawn(&self) -> Result<PreparedExecutable, String> {
        // A stored admission refusal and a fresh pin both stop here.
        // The prepared value is dropped. Windows does not open or start the file.
        let _ = &self.refusal;
        let prepared = PreparedExecutable {
            exec_path: self.path.clone(),
        };
        let _ = prepared.exec_path();
        Err(WINDOWS_CHECKED_PROVIDER.to_owned())
    }
}

impl std::ops::Deref for CheckedExecutable {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.path()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    #[tokio::test]
    async fn windows_checked_native_provider_refuses_verify_and_spawn() {
        let home = tempfile::tempdir().expect("home");
        let path = home.path().join("provider.exe");
        let bytes = b"verified-provider-bytes";
        std::fs::write(&path, bytes).expect("write");
        assert!(CheckedExecutable::pinned(&path, "sha256:nope").is_err());

        let pin = format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)));
        let checked = CheckedExecutable::pinned(&path, &pin)
            .expect("pin")
            .with_home_data_dir(home.path())
            .with_sibling("cloudflared");
        let error = checked.verify_at_spawn().expect_err("verify must refuse");
        assert_eq!(error, WINDOWS_CHECKED_PROVIDER);

        let refused = CheckedExecutable::refused(&path, "admission refused".into());
        assert_eq!(
            refused.verify_at_spawn().expect_err("refused verify"),
            WINDOWS_CHECKED_PROVIDER
        );

        let spawned = super::super::bridge::ProviderBridge::spawn(
            &checked,
            super::super::bridge::ProviderConfig::default(),
        )
        .await;
        let Err(spawned) = spawned else {
            panic!("spawn must refuse");
        };
        match spawned {
            super::super::bridge::BridgeError::Refused(reason) => {
                assert_eq!(reason, WINDOWS_CHECKED_PROVIDER);
            }
            other => panic!("spawn must refuse, got {other:?}"),
        }
        assert_eq!(std::fs::read(&path).expect("read"), bytes);
        assert!(recover_verified_copies(home.path()).is_ok());
    }
}
