//! Windows has no Linux KVM host setup. Refuse before touching host files.

use std::path::Path;

pub(crate) const SETUP_MESSAGE: &str = "Browser Linux host setup is unsupported on Windows";
pub(crate) const KVM_MESSAGE: &str = "Browser KVM host setup is unsupported on Windows";

pub(super) async fn enable(_data: &Path, _platform: &str) -> anyhow::Result<()> {
    Err(super::windows_unsupported("Browser Linux host setup"))
}

pub(super) fn kvm_present(_path: &Path) -> bool {
    false
}
