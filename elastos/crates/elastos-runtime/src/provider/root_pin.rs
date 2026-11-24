//! Device and inode check for a directory the installer is about to confine.
//!
//! Linux opens with `O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY`. macOS has no
//! `O_PATH`; the same open uses `O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY`. A failed
//! open is that errno. A descriptor whose device or inode differs is `ESTALE`.

use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

#[cfg(target_os = "linux")]
pub(super) const DIRECTORY_OPEN_FLAGS: libc::c_int =
    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;

#[cfg(not(target_os = "linux"))]
pub(super) const DIRECTORY_OPEN_FLAGS: libc::c_int =
    libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY;

fn last_errno() -> i32 {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location()
    }
    #[cfg(not(target_os = "linux"))]
    unsafe {
        *libc::__error()
    }
}

fn stat_identity(info: &libc::stat) -> (u64, u64) {
    #[cfg(target_os = "linux")]
    let dev = info.st_dev;
    #[cfg(not(target_os = "linux"))]
    let dev = info.st_dev as u64;
    (dev, info.st_ino)
}

/// Open `path` with `flags` and require the pinned device and inode.
///
/// The caller passes [`DIRECTORY_OPEN_FLAGS`]. The returned descriptor is the
/// directory those flags opened. A mismatch returns [`libc::ESTALE`] and does
/// not leave the descriptor open.
pub(super) fn open_pinned_directory(
    path: &CStr,
    flags: libc::c_int,
    dev: u64,
    ino: u64,
) -> Result<OwnedFd, i32> {
    let fd = unsafe { libc::open(path.as_ptr(), flags) };
    if fd < 0 {
        return Err(last_errno());
    }
    // The descriptor was just opened and is not owned by anyone else.
    let directory = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(directory.as_raw_fd(), info.as_mut_ptr()) } < 0 {
        return Err(last_errno());
    }
    let info = unsafe { info.assume_init() };
    let is_dir = info.st_mode & libc::S_IFMT == libc::S_IFDIR;
    let (found_dev, found_ino) = stat_identity(&info);
    if !is_dir || found_dev != dev || found_ino != ino {
        return Err(libc::ESTALE);
    }
    Ok(directory)
}

#[cfg(unix)]
#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    #[test]
    fn a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer() {
        let installer = include_str!("preexec_installer.rs");
        let add = installer
            .split_once("let directory = if let Some(pin) = pinned")
            .expect("pinned root open")
            .1;
        let add = add
            .split_once("SYS_landlock_add_rule")
            .expect("landlock add")
            .0;
        assert!(
            add.contains("open_pinned_directory"),
            "every pinned root is identified before its Landlock rule is added"
        );
        assert!(
            add.contains("DIRECTORY_OPEN_FLAGS"),
            "the installer opens pinned roots with the no-follow directory flags"
        );
        assert!(
            !add.contains("STORAGE_ROOT"),
            "the identity check is every pinned root, not only STORAGE_ROOT"
        );
        let flags = include_str!("root_pin.rs");
        assert!(
            flags.contains("libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY"),
            "Linux opens a pinned root with O_PATH|O_NOFOLLOW|O_DIRECTORY"
        );

        // A symlink to identity has a different inode. A symlink whose target
        // is the same directory still must not be followed: O_NOFOLLOW fails
        // closed, and the link's own inode is not the pinned directory.
        for same_directory in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path();
            std::fs::create_dir(data.join("identity")).unwrap();
            let root = data.join("chain-provider");
            std::fs::create_dir(&root).unwrap();
            let executable = Path::new("/opt/elastos/helper-provider");
            let admitted = super::super::rights::admit_runtime_grant(
                super::super::rights_table::RuntimeProviderId::Chain,
            );
            let (_confinement, plan) = super::super::path_allow::render_with_plan(
                super::super::rights_table::RuntimeProviderId::Chain,
                &admitted,
                data,
                executable,
                5,
            )
            .unwrap_or_else(|err| panic!("render before the swap: {err}"));
            assert_eq!(plan.rules[0].0, "chain-provider");
            let dev = plan.root_dev[0];
            let ino = plan.root_ino[0];
            let before = std::fs::symlink_metadata(&root).unwrap();
            assert_eq!((dev, ino), (before.dev(), before.ino()));
            let target = if same_directory {
                let saved = data.join("saved-root");
                std::fs::rename(&root, &saved).unwrap();
                saved
            } else {
                std::fs::remove_dir(&root).unwrap();
                data.join("identity")
            };
            std::os::unix::fs::symlink(&target, &root).unwrap();
            let rendered_again = super::super::path_allow::render_with_plan(
                super::super::rights_table::RuntimeProviderId::Chain,
                &admitted,
                data,
                executable,
                5,
            );
            assert!(
                rendered_again.is_err(),
                "render after the swap must refuse the symlink"
            );
            let path = CString::new(root.as_os_str().as_bytes()).unwrap();
            let error = super::open_pinned_directory(&path, super::DIRECTORY_OPEN_FLAGS, dev, ino)
                .expect_err("the installer must refuse the swapped root");
            assert_ne!(
                error, 0,
                "same_directory={same_directory}: the no-follow open refuses a swapped symlink"
            );
            assert!(
                error == libc::ELOOP || error == libc::ENOTDIR || error == libc::ESTALE,
                "same_directory={same_directory}: open refused with {error}"
            );
        }
    }
}
