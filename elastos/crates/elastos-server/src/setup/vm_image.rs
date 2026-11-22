//! Load admission for the selected VM rootfs.

use super::{
    browser_vm_image::signed_image, installed_release_source, ComponentsManifest, PlatformInfo,
};
use anyhow::{ensure, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::path::Path;

pub fn checked_vm_image(
    data: &Path,
    dir: &Path,
    name: &str,
    entrypoint: &str,
) -> Result<(File, String)> {
    let source =
        installed_release_source(data)?.context("Unsigned VM image refused: no signed release")?;
    let binary = fs::canonicalize(&source.install_path)?;
    let bytes = crate::installed_release::read_signed_components(data, &binary, &source, false)?;
    let manifest: ComponentsManifest = serde_json::from_slice(&bytes)?;
    let platform = super::detect_platform();
    let (component, info) = selected_info(&manifest, name, &platform)?;
    checked_capsule_install_dir(data, dir, component, info)?;
    open_signed_image(dir, entrypoint, info)
}

fn checked_capsule_install_dir(
    data: &Path,
    dir: &Path,
    component: &super::Component,
    info: &PlatformInfo,
) -> Result<()> {
    let metadata = component
        .capsule_metadata
        .as_ref()
        .context("Unsigned VM image refused: no signed capsule metadata")?;
    let install = super::resolve_component_capsule_metadata_install_path(metadata, Some(info))
        .context("Unsigned VM image refused: no install path")?;
    ensure!(
        Path::new(install)
            .components()
            .all(|part| matches!(part, std::path::Component::Normal(_))),
        "VM image path refused: signed install path is not relative"
    );
    ensure!(
        dir == data.join(install),
        "VM image path refused: selected directory differs from signed install path"
    );
    Ok(())
}

fn selected_info<'a>(
    manifest: &'a ComponentsManifest,
    name: &str,
    platform: &str,
) -> Result<(&'a super::Component, &'a PlatformInfo)> {
    let component = manifest
        .external
        .get(name)
        .context("Unsigned VM image refused: no signed component")?;
    let metadata = component
        .capsule_metadata
        .as_ref()
        .context("Unsigned VM image refused: no signed capsule metadata")?;
    let info = super::resolve_component_capsule_metadata_platform_info(metadata, platform)
        .context("Wrong VM image platform refused")?;
    Ok((component, info))
}

fn open_signed_image(dir: &Path, entrypoint: &str, info: &PlatformInfo) -> Result<(File, String)> {
    let entry = signed_image(info)?.context("Unsigned VM image refused: no signed image entry")?;
    ensure!(
        entrypoint == entry.path,
        "VM image path refused: entrypoint differs from signed image"
    );
    let path = dir.join(&entry.path);
    ensure!(
        fs::symlink_metadata(&path)?.file_type().is_file(),
        "VM image path refused: image is not a regular file"
    );
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let image = options
        .open(&path)
        .context("VM image path refused: open failed")?;
    ensure!(
        image.metadata()?.len() == entry.size,
        "Changed VM image refused: size differs from signed entry"
    );
    Ok((image, entry.sha256))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elastos_compute::ComputeProvider;
    use elastos_crosvm::{CrosvmConfig, CrosvmProvider, RootfsManager};
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek};

    const KERNEL: &[u8] = b"ext4 virtio_blk virtio_pci";
    const INITRD: &[u8] = b"signed initrd";

    fn write_image_set(dir: &Path, rootfs: &[u8]) {
        fs::write(dir.join("rootfs.ext4"), rootfs).unwrap();
        fs::write(dir.join("vmlinux"), KERNEL).unwrap();
        fs::write(dir.join("initrd"), INITRD).unwrap();
    }

    fn row(bytes: &[u8]) -> PlatformInfo {
        let digest = format!("{:x}", Sha256::digest(bytes));
        serde_json::from_value(serde_json::json!({
            "strategy":"prebuilt", "vm_image":{"path":"rootfs.ext4", "size":bytes.len(),
                "sha256":digest, "cid":super::super::catalog_head_cid(bytes).unwrap(),
                "kernel":{"path":"vmlinux","size":KERNEL.len(),
                    "sha256":format!("{:x}", Sha256::digest(KERNEL))},
                "initrd":{"path":"initrd","size":INITRD.len(),
                    "sha256":format!("{:x}", Sha256::digest(INITRD))}}
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn signed_vm_image_loads_and_changed_image_refuses_before_start() {
        let temp = tempfile::tempdir().unwrap();
        let image_path = temp.path().join("rootfs.ext4");
        write_image_set(temp.path(), b"signed image");
        let info = row(b"signed image");
        let (image, digest) = open_signed_image(temp.path(), "rootfs.ext4", &info).unwrap();
        let overlays = RootfsManager::new(temp.path().join("cache"));
        overlays.init().await.unwrap();
        let (overlay, mut file) = overlays
            .create_verified_overlay("valid", &image, &image_path, &digest)
            .await
            .unwrap();
        assert!(!overlay.exists());
        file.rewind().unwrap();
        let mut checked = Vec::new();
        file.read_to_end(&mut checked).unwrap();
        assert_eq!(checked, b"signed image");
        let kernel = temp.path().join("vmlinux");
        let binary = temp.path().join("crosvm");
        fs::write(&binary, b"test placeholder").unwrap();
        let provider = CrosvmProvider::new(
            CrosvmConfig::new()
                .with_crosvm_bin(binary)
                .with_kernel_path(kernel)
                .with_socket_dir(temp.path().join("sockets"))
                .with_rootfs_cache_dir(temp.path().join("provider-cache")),
        )
        .unwrap();
        provider.init().await.unwrap();
        let manifest: elastos_common::CapsuleManifest =
            serde_json::from_str(include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../capsules/shell/capsule.json"
            )))
            .unwrap();
        assert!(provider
            .load(temp.path(), manifest.clone())
            .await
            .unwrap_err()
            .to_string()
            .contains("Unsigned VM image refused"));
        let handle = provider
            .load_verified(temp.path(), manifest, &image, &digest)
            .await
            .unwrap();
        assert_eq!(
            provider.status(&handle).await.unwrap(),
            elastos_common::CapsuleStatus::Loading
        );
        #[cfg(not(target_os = "linux"))]
        assert!(provider
            .start(&handle)
            .await
            .unwrap_err()
            .to_string()
            .contains("/dev/kvm"));
        fs::write(&image_path, b"short").unwrap();
        assert!(open_signed_image(temp.path(), "rootfs.ext4", &info)
            .unwrap_err()
            .to_string()
            .contains("size differs"));
        fs::write(&image_path, b"other  image").unwrap();
        let (image, digest) = open_signed_image(temp.path(), "rootfs.ext4", &info).unwrap();
        let err = overlays
            .create_verified_overlay("changed", &image, &image_path, &digest)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Changed VM image refused"),
            "{err}"
        );
        assert!(!temp.path().join("cache/overlays/changed.ext4").exists());
    }

    #[tokio::test]
    async fn stale_overlay_and_replaced_image_path_refuse() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rootfs.ext4");
        write_image_set(temp.path(), b"signed image");
        let info = row(b"signed image");
        let (image, digest) = open_signed_image(temp.path(), "rootfs.ext4", &info).unwrap();
        let overlays = RootfsManager::new(temp.path().join("cache"));
        overlays.init().await.unwrap();
        fs::write(temp.path().join("cache/overlays/stale.ext4"), b"old").unwrap();
        let err = overlays
            .create_verified_overlay("stale", &image, &path, &digest)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("Stale VM overlay refused"),
            "{err}"
        );
        assert_eq!(
            fs::read(temp.path().join("cache/overlays/stale.ext4")).unwrap(),
            b"old"
        );
        fs::rename(&path, temp.path().join("old.ext4")).unwrap();
        fs::write(&path, b"signed image").unwrap();
        let err = overlays
            .create_verified_overlay("replaced", &image, &path, &digest)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("path replaced"), "{err}");
    }

    #[test]
    fn unsigned_path_and_wrong_platform_refuse() {
        let temp = tempfile::tempdir().unwrap();
        write_image_set(temp.path(), b"signed image");
        assert!(
            checked_vm_image(temp.path(), temp.path(), "vm", "rootfs.ext4")
                .unwrap_err()
                .to_string()
                .contains("Unsigned VM image refused")
        );
        let mut info = row(b"signed image");
        assert!(open_signed_image(temp.path(), "other.ext4", &info)
            .unwrap_err()
            .to_string()
            .contains("path refused"));
        info.extra.remove("vm_image");
        assert!(open_signed_image(temp.path(), "rootfs.ext4", &info)
            .unwrap_err()
            .to_string()
            .contains("Unsigned VM image refused"));
        let mut invalid = row(b"signed image");
        invalid.extra["vm_image"]["cid"] =
            serde_json::json!(super::super::catalog_head_cid(b"changed").unwrap());
        assert!(open_signed_image(temp.path(), "rootfs.ext4", &invalid).is_err());
        let manifest: ComponentsManifest = serde_json::from_value(serde_json::json!({"external":{"vm":{
            "install_path":"bin/vm", "platforms":{"darwin-arm64":{}},
            "capsule_metadata":{"install_path":"capsules/vm","platforms":{"darwin-arm64":row(b"signed image")}}
        }},"profiles":{}})).unwrap();
        assert!(selected_info(&manifest, "vm", "linux-amd64")
            .err()
            .unwrap()
            .to_string()
            .contains("Wrong VM image platform refused"));
        let (component, info) = selected_info(&manifest, "vm", "darwin-arm64").unwrap();
        let capsule = temp.path().join("capsules/vm");
        fs::create_dir_all(&capsule).unwrap();
        write_image_set(&capsule, b"signed image");
        checked_capsule_install_dir(temp.path(), &capsule, component, info).unwrap();
        let (image, digest) = open_signed_image(&capsule, "rootfs.ext4", info).unwrap();
        assert_eq!(
            image.metadata().unwrap().len(),
            b"signed image".len() as u64
        );
        assert_eq!(digest, format!("{:x}", Sha256::digest(b"signed image")));
        assert!(checked_capsule_install_dir(
            temp.path(),
            &temp.path().join("bin/vm"),
            component,
            info
        )
        .is_err());
    }

    #[test]
    fn signed_capsule_metadata_reaches_checked_vm_image() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path();
        let capsule = data.join("capsules/shell");
        fs::create_dir_all(&capsule).unwrap();
        write_image_set(&capsule, b"signed image");
        let platform = super::super::detect_platform();
        let components = serde_json::json!({
            "external":{"shell":{
                "install_path":"bin/shell", "platforms":{(platform.clone()):{}},
                "capsule_metadata":{
                    "install_path":"capsules/shell",
                    "platforms":{(platform.clone()):row(b"signed image")}
                }
            }}, "profiles":{}
        });
        fs::write(
            data.join("components.json"),
            serde_json::to_vec(&components).unwrap(),
        )
        .unwrap();
        crate::installed_release::tests::sign_test_install(data);

        let (mut image, digest) = checked_vm_image(data, &capsule, "shell", "rootfs.ext4").unwrap();
        let mut bytes = Vec::new();
        image.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"signed image");
        assert_eq!(digest, format!("{:x}", Sha256::digest(&bytes)));
        let error =
            checked_vm_image(data, &data.join("bin/shell"), "shell", "rootfs.ext4").unwrap_err();
        assert!(
            error.to_string().contains("selected directory differs"),
            "{error}"
        );
    }
}
