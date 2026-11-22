//! Load admission for the selected VM rootfs and boot kernel.

use super::{
    browser_vm_image::signed_image, installed_release_source, ComponentsManifest, PlatformInfo,
};
use anyhow::{ensure, Context, Result};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Component, Path};

#[derive(Debug)]
pub struct CheckedVmImage {
    pub rootfs: File,
    pub rootfs_sha256: String,
    pub kernel: File,
}

pub fn checked_vm_image(
    data: &Path,
    dir: &Path,
    name: &str,
    entrypoint: &str,
    kernel_override: Option<&str>,
) -> Result<CheckedVmImage> {
    let source =
        installed_release_source(data)?.context("Unsigned VM image refused: no signed release")?;
    let binary = fs::canonicalize(&source.install_path)?;
    let bytes = crate::installed_release::read_signed_components(data, &binary, &source, false)?;
    let manifest: ComponentsManifest = serde_json::from_slice(&bytes)?;
    let platform = super::detect_platform();
    let (component, info) = selected_info(&manifest, name, &platform)?;
    checked_capsule_install_dir(data, dir, component, info)?;
    open_signed_image(dir, entrypoint, kernel_override, info)
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

fn open_signed_image(
    dir: &Path,
    entrypoint: &str,
    kernel_override: Option<&str>,
    info: &PlatformInfo,
) -> Result<CheckedVmImage> {
    let entry = signed_image(info)?.context("Unsigned VM image refused: no signed image entry")?;
    // crosvm boots /init from the rootfs and has no initrd argument. The
    // signed entry's initrd is release packaging, not a capsule boot input.
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
    // The manifest may select another file only when its bytes match the
    // signed kernel. Boot the private copy of those bytes, not this file.
    let kernel_name = kernel_override.unwrap_or(&entry.kernel.path);
    ensure!(
        Path::new(kernel_name)
            .components()
            .all(|part| matches!(part, Component::Normal(_))),
        "VM kernel path refused: override is not relative"
    );
    let kernel_path = dir.join(kernel_name);
    ensure!(
        fs::symlink_metadata(&kernel_path)?.file_type().is_file(),
        "VM kernel path refused: kernel is not a regular file"
    );
    let mut source = options
        .open(&kernel_path)
        .context("VM kernel path refused: open failed")?;
    ensure!(
        source.metadata()?.len() == entry.kernel.size,
        "Changed VM kernel refused: size differs from signed entry"
    );
    let kernel = private_kernel_copy(
        dir,
        &mut source,
        &kernel_path,
        entry.kernel.size,
        &entry.kernel.sha256,
    )?;
    drop(source);
    Ok(CheckedVmImage {
        rootfs: image,
        rootfs_sha256: entry.sha256,
        kernel,
    })
}

/// Copy the opened kernel into an unnamed file, hashing the bytes written.
///
/// The digest that is compared is the digest of that private file. The capsule
/// file is not the descriptor that boots.
fn private_kernel_copy(
    directory: &Path,
    kernel: &mut File,
    kernel_path: &Path,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<File> {
    let mut private =
        elastos_crosvm::open_private_file(directory).context("VM kernel private copy refused")?;
    let mut written = Sha256::new();
    let mut copied = 0u64;
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let count = kernel.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        private
            .write_all(&chunk[..count])
            .context("VM kernel private copy refused: write failed")?;
        written.update(&chunk[..count]);
        copied = copied
            .checked_add(count as u64)
            .context("VM kernel private copy refused: size overflow")?;
    }
    ensure!(
        copied == expected_size,
        "Changed VM kernel refused: size differs from signed entry"
    );
    ensure!(
        format!("{:x}", written.finalize()) == expected_sha256,
        "Changed VM kernel refused: digest differs from signed entry"
    );
    private
        .rewind()
        .context("VM kernel private copy refused: rewind failed")?;
    let mut stored = Sha256::new();
    let mut checked = 0u64;
    loop {
        let count = private.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        stored.update(&chunk[..count]);
        checked = checked
            .checked_add(count as u64)
            .context("VM kernel private copy refused: size overflow")?;
    }
    ensure!(
        checked == expected_size && format!("{:x}", stored.finalize()) == expected_sha256,
        "Changed VM kernel refused: private copy digest differs from signed entry"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = kernel.metadata()?;
        let selected = fs::symlink_metadata(kernel_path)?;
        ensure!(
            selected.file_type().is_file()
                && opened.dev() == selected.dev()
                && opened.ino() == selected.ino(),
            "VM kernel path replaced after verification"
        );
        let copied_meta = private.metadata()?;
        ensure!(
            copied_meta.dev() != opened.dev() || copied_meta.ino() != opened.ino(),
            "VM kernel private copy refused: copy shares the source file"
        );
    }
    private
        .sync_all()
        .context("VM kernel private copy refused: sync failed")?;
    private
        .rewind()
        .context("VM kernel private copy refused: rewind failed")?;
    Ok(private)
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
        let checked = open_signed_image(temp.path(), "rootfs.ext4", None, &info).unwrap();
        let image = checked.rootfs;
        let digest = checked.rootfs_sha256;
        let overlays = RootfsManager::new(temp.path().join("cache"));
        overlays.init().await.unwrap();
        let (overlay, mut file) = overlays
            .create_verified_overlay("valid", &image, &image_path, &digest)
            .await
            .unwrap();
        assert!(!overlay.exists());
        file.rewind().unwrap();
        let mut copied_rootfs = Vec::new();
        file.read_to_end(&mut copied_rootfs).unwrap();
        assert_eq!(copied_rootfs, b"signed image");
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
            .load_verified(temp.path(), manifest, &image, &digest, checked.kernel)
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
        assert!(open_signed_image(temp.path(), "rootfs.ext4", None, &info)
            .unwrap_err()
            .to_string()
            .contains("size differs"));
        fs::write(&image_path, b"other  image").unwrap();
        let checked = open_signed_image(temp.path(), "rootfs.ext4", None, &info).unwrap();
        let image = checked.rootfs;
        let digest = checked.rootfs_sha256;
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
        let checked = open_signed_image(temp.path(), "rootfs.ext4", None, &info).unwrap();
        let image = checked.rootfs;
        let digest = checked.rootfs_sha256;
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
            checked_vm_image(temp.path(), temp.path(), "vm", "rootfs.ext4", None)
                .unwrap_err()
                .to_string()
                .contains("Unsigned VM image refused")
        );
        let mut info = row(b"signed image");
        assert!(open_signed_image(temp.path(), "other.ext4", None, &info)
            .unwrap_err()
            .to_string()
            .contains("path refused"));
        info.extra.remove("vm_image");
        assert!(open_signed_image(temp.path(), "rootfs.ext4", None, &info)
            .unwrap_err()
            .to_string()
            .contains("Unsigned VM image refused"));
        let mut invalid = row(b"signed image");
        invalid.extra["vm_image"]["cid"] =
            serde_json::json!(super::super::catalog_head_cid(b"changed").unwrap());
        assert!(open_signed_image(temp.path(), "rootfs.ext4", None, &invalid).is_err());
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
        let checked = open_signed_image(&capsule, "rootfs.ext4", None, info).unwrap();
        let image = checked.rootfs;
        let digest = checked.rootfs_sha256;
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
    fn changed_kernel_and_unsigned_override_refuse_before_load() {
        let temp = tempfile::tempdir().unwrap();
        write_image_set(temp.path(), b"signed image");
        let info = row(b"signed image");
        let changed = vec![b'x'; KERNEL.len()];
        fs::write(temp.path().join("other-vmlinux"), &changed).unwrap();
        let error = open_signed_image(temp.path(), "rootfs.ext4", Some("other-vmlinux"), &info)
            .unwrap_err();
        assert!(error.to_string().contains("digest differs"), "{error}");
        let error =
            open_signed_image(temp.path(), "rootfs.ext4", Some("../vmlinux"), &info).unwrap_err();
        assert!(
            error.to_string().contains("VM kernel path refused"),
            "{error}"
        );

        fs::write(temp.path().join("other-vmlinux"), KERNEL).unwrap();
        let mut checked =
            open_signed_image(temp.path(), "rootfs.ext4", Some("other-vmlinux"), &info).unwrap();
        fs::rename(
            temp.path().join("other-vmlinux"),
            temp.path().join("old-vmlinux"),
        )
        .unwrap();
        fs::write(temp.path().join("other-vmlinux"), &changed).unwrap();
        let mut held = Vec::new();
        checked.kernel.read_to_end(&mut held).unwrap();
        assert_eq!(held, KERNEL);

        fs::write(temp.path().join("vmlinux"), &changed).unwrap();
        let error = open_signed_image(temp.path(), "rootfs.ext4", None, &info).unwrap_err();
        assert!(error.to_string().contains("digest differs"), "{error}");
    }

    #[test]
    fn source_write_after_kernel_check_does_not_change_booted_bytes() {
        let temp = tempfile::tempdir().unwrap();
        write_image_set(temp.path(), b"signed image");
        let info = row(b"signed image");
        let mut checked = open_signed_image(temp.path(), "rootfs.ext4", None, &info).unwrap();
        let kernel_path = temp.path().join("vmlinux");
        #[cfg(unix)]
        let source_id = {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::symlink_metadata(&kernel_path).unwrap();
            (meta.dev(), meta.ino())
        };
        let tampered = vec![b'Z'; KERNEL.len()];
        // Truncate the same inode. Replacing the path would leave the old
        // descriptor on the hashed bytes and hide this fault.
        fs::write(&kernel_path, &tampered).unwrap();
        assert_eq!(fs::read(&kernel_path).unwrap(), tampered);
        let mut booted = Vec::new();
        checked.kernel.read_to_end(&mut booted).unwrap();
        assert_eq!(
            booted, KERNEL,
            "booted kernel changed after the source write"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&booted)),
            format!("{:x}", Sha256::digest(KERNEL))
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::symlink_metadata(&kernel_path).unwrap();
            assert_eq!(
                (meta.dev(), meta.ino()),
                source_id,
                "write replaced the kernel inode"
            );
            checked.kernel.rewind().unwrap();
            let booted_meta = checked.kernel.metadata().unwrap();
            assert_ne!(
                (booted_meta.dev(), booted_meta.ino()),
                source_id,
                "booted kernel is still the capsule file"
            );
        }
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

        let checked = checked_vm_image(data, &capsule, "shell", "rootfs.ext4", None).unwrap();
        let mut image = checked.rootfs;
        let digest = checked.rootfs_sha256;
        let mut bytes = Vec::new();
        image.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"signed image");
        assert_eq!(digest, format!("{:x}", Sha256::digest(&bytes)));
        let error = checked_vm_image(data, &data.join("bin/shell"), "shell", "rootfs.ext4", None)
            .unwrap_err();
        assert!(
            error.to_string().contains("selected directory differs"),
            "{error}"
        );
    }
}
