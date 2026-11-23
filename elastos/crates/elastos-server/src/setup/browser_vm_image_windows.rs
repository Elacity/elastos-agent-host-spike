//! Local Browser VM image admission requires Unix file identities and sockets.
//! Windows refuses each entry point before any image file can be trusted.

use super::{ComponentsManifest, PlatformInfo};
use std::path::Path;

pub(super) const NAME: &str = "browser-vm-image";
pub(super) const INSTALL_PATH: &str = "browser-vm/image-set";

fn unsupported() -> anyhow::Error {
    super::windows_unsupported("Browser local Engine image admission")
}

pub(crate) struct BackgroundVerification;

impl BackgroundVerification {
    pub(crate) async fn shutdown(self) {}
}

pub(crate) fn start_background_verification(
    _data: &Path,
    _platform: &str,
) -> Option<BackgroundVerification> {
    None
}

pub(crate) fn verified_seed_identity(
    _rootfs: &Path,
    _platform: &str,
) -> anyhow::Result<elastos_common::browser_vm_seed::BrowserVmSeedIdentity> {
    Err(unsupported())
}

pub(super) fn component_info<'a>(
    _manifest: &'a ComponentsManifest,
    _platform: &str,
) -> anyhow::Result<&'a PlatformInfo> {
    Err(unsupported())
}

pub(super) fn validate_request(
    _data: &Path,
    _info: &PlatformInfo,
    _dest: &Path,
    _platform: &str,
) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn verify_legacy_or_missing_release(
    _data: &Path,
    _platform: &str,
) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn verify_installed(
    _data: &Path,
    _info: &PlatformInfo,
    _platform: &str,
) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn require_space(_dest: &Path, _info: &PlatformInfo) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn receipts_match(_data: &Path, _info: &PlatformInfo) -> bool {
    false
}
