//! Local Browser VM image admission requires Unix file identities and sockets.
//! Windows refuses each entry point before any image file can be trusted.

use super::{ComponentsManifest, FirstPartyCarrierContext, PlatformInfo};
use std::path::Path;

pub(super) const NAME: &str = "browser-vm-image";
pub(super) const INSTALL_PATH: &str = "browser-vm/image-set";

fn unsupported() -> anyhow::Error {
    super::windows_unsupported("Browser local Engine image admission")
}

/// The signed image is not admitted on Windows. Callers still match this error.
#[derive(Debug)]
pub(crate) struct BrowserVmImageInvalid(anyhow::Error);

impl BrowserVmImageInvalid {
    pub(crate) fn new(error: anyhow::Error) -> Self {
        Self(error)
    }
}

impl std::fmt::Display for BrowserVmImageInvalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BrowserVmImageInvalid {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

pub(super) struct VmImageEntry;

pub(super) fn signed_image(_info: &PlatformInfo) -> anyhow::Result<Option<VmImageEntry>> {
    Err(unsupported())
}

#[cfg(test)]
pub(crate) fn install_signed_browser_vm_image_fixture(_data: &Path) {
    panic!("Browser VM image fixture is refused: {}", unsupported());
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

pub(super) async fn install_via_carrier(
    _data: &Path,
    _row: &crate::capsule_record::AdmittedRow,
    _dest: &Path,
    _platform: &str,
    _context: FirstPartyCarrierContext,
) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn require_space(_dest: &Path, _info: &PlatformInfo) -> anyhow::Result<()> {
    Err(unsupported())
}

pub(super) fn receipts_match(_data: &Path, _info: &PlatformInfo) -> bool {
    false
}
