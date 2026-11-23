//! Windows has no held, digest-checked executable start yet. Every
//! constructor refuses, so no installed component starts on Windows unchecked.

use anyhow::Result;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct VerifiedExecutable {
    path: PathBuf,
}

impl VerifiedExecutable {
    pub fn prepare(_path: &Path, _checksum: &str) -> Result<Self> {
        Err(super::windows_unsupported("Verified executable start"))
    }

    pub(crate) fn unchecked(_path: &Path) -> Result<Self> {
        Err(super::windows_unsupported("Unchecked executable start"))
    }

    pub fn exec_path(&self) -> &Path {
        &self.path
    }

    /// Native providers require a signed digest. Windows has no held executable,
    /// so admission refuses before a start.
    pub fn signed_checksum(&self) -> Result<&str> {
        Err(super::windows_unsupported("Verified executable start"))
    }

    pub fn attach_std(&self, _command: &mut std::process::Command, _clear_env: bool) -> Result<()> {
        Err(super::windows_unsupported("Verified executable start"))
    }

    pub fn attach_tokio(
        &self,
        command: &mut tokio::process::Command,
        clear_env: bool,
    ) -> Result<()> {
        self.attach_std(command.as_std_mut(), clear_env)
    }
}
