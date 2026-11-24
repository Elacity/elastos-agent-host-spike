//! VM image admission requires Unix file identities. Windows refuses the check.

use super::windows_unsupported;
use std::fs::File;
use std::path::Path;

#[derive(Debug)]
pub struct CheckedVmImage {
    pub rootfs: File,
    pub rootfs_sha256: String,
    pub kernel: File,
}

pub fn checked_vm_image(
    _data: &Path,
    _dir: &Path,
    _name: &str,
    _entrypoint: &str,
    _kernel_override: Option<&str>,
) -> anyhow::Result<CheckedVmImage> {
    Err(windows_unsupported("VM image launch"))
}

#[cfg(test)]
mod tests {
    use super::checked_vm_image;
    use std::path::Path;

    #[test]
    fn windows_refuses_checked_vm_image() {
        let error = checked_vm_image(
            Path::new("C:\\unused"),
            Path::new("C:\\unused"),
            "shell",
            "rootfs.ext4",
            None,
        )
        .expect_err("VM image launch must refuse");
        assert!(
            error
                .to_string()
                .contains("VM image launch is unsupported on Windows"),
            "{error}"
        );
    }
}
