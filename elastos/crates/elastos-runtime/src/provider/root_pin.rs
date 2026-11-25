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

    // Open of a symlink with DIRECTORY_OPEN_FLAGS.
    // Linux (O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY) returns ENOTDIR.
    // macOS (O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY) returns ENOTDIR.
    // ELOOP is the other refusal O_NOFOLLOW can return; these flags return ENOTDIR.
    const SYMLINK_OPEN_ERRNO: i32 = libc::ENOTDIR;

    fn chain_plan(data: &Path) -> super::super::landlock_plan::Plan {
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
        plan
    }

    #[test]
    fn a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer() {
        // A symlink whose target is the same directory must not be followed.
        // The open returns ENOTDIR and no descriptor, so the dev/ino compare
        // never sees that target. A symlink to another directory is the same
        // open refusal.
        for same_directory in [true, false] {
            let tmp = tempfile::tempdir().unwrap();
            let data = tmp.path();
            std::fs::create_dir(data.join("identity")).unwrap();
            let root = data.join("chain-provider");
            std::fs::create_dir(&root).unwrap();
            let plan = chain_plan(data);
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
            let admitted = super::super::rights::admit_runtime_grant(
                super::super::rights_table::RuntimeProviderId::Chain,
            );
            let rendered_again = super::super::path_allow::render_with_plan(
                super::super::rights_table::RuntimeProviderId::Chain,
                &admitted,
                data,
                Path::new("/opt/elastos/helper-provider"),
                5,
            );
            assert!(
                rendered_again.is_err(),
                "render after the swap must refuse the symlink"
            );
            let path = CString::new(root.as_os_str().as_bytes()).unwrap();
            let error = match super::open_pinned_directory(
                &path,
                super::DIRECTORY_OPEN_FLAGS,
                dev,
                ino,
            ) {
                Err(error) => error,
                Ok(_) => panic!(
                    "same_directory={same_directory}: the open refuses a swapped symlink with ENOTDIR"
                ),
            };
            assert_eq!(
                error, SYMLINK_OPEN_ERRNO,
                "same_directory={same_directory}: the open refuses a swapped symlink with ENOTDIR (errno {error})"
            );
        }

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
    }

    #[test]
    fn a_different_directory_swapped_in_at_the_same_name_is_refused_with_estale() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        let root = data.join("chain-provider");
        std::fs::create_dir(&root).unwrap();
        let plan = chain_plan(data);
        let dev = plan.root_dev[0];
        let ino = plan.root_ino[0];
        let other = data.join("other-directory");
        std::fs::create_dir(&other).unwrap();
        let aside = data.join("aside-root");
        std::fs::rename(&root, &aside).unwrap();
        std::fs::rename(&other, &root).unwrap();
        let swapped = std::fs::symlink_metadata(&root).unwrap();
        assert!(swapped.is_dir(), "the swapped name is a real directory");
        assert_ne!(
            (dev, ino),
            (swapped.dev(), swapped.ino()),
            "the renamed directory is a different directory"
        );
        let admitted = super::super::rights::admit_runtime_grant(
            super::super::rights_table::RuntimeProviderId::Chain,
        );
        super::super::path_allow::render_with_plan(
            super::super::rights_table::RuntimeProviderId::Chain,
            &admitted,
            data,
            Path::new("/opt/elastos/helper-provider"),
            5,
        )
        .expect("a real directory at the same name still renders");
        let path = CString::new(root.as_os_str().as_bytes()).unwrap();
        let error = super::open_pinned_directory(&path, super::DIRECTORY_OPEN_FLAGS, dev, ino)
            .expect_err("a different directory at the pinned name is refused");
        assert_eq!(
            error,
            libc::ESTALE,
            "a different directory swapped in at the same name is refused with ESTALE (errno {error})"
        );
    }

    /// The inode above stays the rendered inode. Only `root_dev` changes, so
    /// this refusal is the device comparison. No second volume is mounted.
    #[test]
    fn a_rendered_plan_with_a_changed_root_dev_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        std::fs::create_dir(data.join("chain-provider")).unwrap();
        let mut plan = chain_plan(data);
        let path = CString::new(plan.rules[0].1.as_os_str().as_bytes()).unwrap();
        let real = std::fs::symlink_metadata(&plan.rules[0].1).unwrap();
        assert_eq!(
            (plan.root_dev[0], plan.root_ino[0]),
            (real.dev(), real.ino())
        );
        plan.root_dev[0] = plan.root_dev[0].wrapping_add(1);
        let error = super::open_pinned_directory(
            &path,
            super::DIRECTORY_OPEN_FLAGS,
            plan.root_dev[0],
            plan.root_ino[0],
        )
        .expect_err("a changed root_dev is refused");
        assert_eq!(error, libc::ESTALE, "errno {error}");
    }
}
