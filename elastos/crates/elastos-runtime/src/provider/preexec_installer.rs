//! Linux provider attachment. Prepare owned buffers before fork; install in the child.
#![allow(dead_code)] // The spawn caller arrives in a later B3 slice.

use super::super::{
    landlock_plan, rights::AdmittedRights, rights_table::RuntimeProviderId,
    seccomp_list::AuditArch, seccomp_program,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{ffi::CString, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    CloseRange,
    NoNewPrivileges,
    Create,
    Add(usize),
    Restrict,
    Seccomp,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Failure(Step, i32);

impl Failure {
    // Three native-endian words. The child copies only stack bytes to the pipe.
    pub(super) fn record(&self) -> [u8; 12] {
        let (tag, index) = match self.0 {
            Step::CloseRange => (1u32, 0),
            Step::Create => (2, 0),
            Step::Add(index) => (3, index as u32),
            Step::NoNewPrivileges => (4, 0),
            Step::Restrict => (5, 0),
            Step::Seccomp => (6, 0),
        };
        let [t0, t1, t2, t3] = tag.to_ne_bytes();
        let [i0, i1, i2, i3] = index.to_ne_bytes();
        let [e0, e1, e2, e3] = self.1.to_ne_bytes();
        [t0, t1, t2, t3, i0, i1, i2, i3, e0, e1, e2, e3]
    }

    pub(super) fn from_record(tag: u32, index: u32, errno: i32) -> Option<Self> {
        let step = match tag {
            1 => Step::CloseRange,
            2 => Step::Create,
            3 => Step::Add(index as usize),
            4 => Step::NoNewPrivileges,
            5 => Step::Restrict,
            6 => Step::Seccomp,
            _ => return None,
        };
        Some(Self(step, errno))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self(step, errno) = self;
        match step {
            Step::CloseRange => write!(f, "the probe child could not close inherited descriptors: errno {errno}"),
            Step::NoNewPrivileges => write!(f, "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno {errno}"),
            Step::Create => write!(f, "landlock install refused: the ruleset could not be created with errno {errno}"),
            Step::Add(index) => write!(f, "landlock install refused: the path rule {index} could not be added with errno {errno}"),
            Step::Restrict => write!(f, "landlock install refused: landlock_restrict_self failed with errno {errno}"),
            Step::Seccomp => write!(f, "seccomp install refused: the filter install failed with errno {errno}"),
        }
    }
}

fn sequence(count: usize, mut run: impl FnMut(Step) -> Result<(), i32>) -> Result<(), Failure> {
    let mut apply = |step| run(step).map_err(|errno| Failure(step, errno));
    apply(Step::CloseRange)?;
    apply(Step::Create)?;
    for index in 0..count {
        apply(Step::Add(index))?;
    }
    // Match the lab's Landlock installer: confine.rs:9057-9062.
    apply(Step::NoNewPrivileges)?;
    apply(Step::Restrict)?;
    apply(Step::Seccomp)
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}
#[repr(C)]
struct PathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[derive(Clone, Copy)]
struct RootPin {
    index: usize,
    dev: u64,
    ino: u64,
}

pub(super) struct Prepared {
    plan: landlock_plan::Plan,
    paths: Vec<CString>,
    filters: Vec<libc::sock_filter>,
    /// Every directory root. The child opens each one with no-follow and
    /// compares its device and inode before adding that Landlock rule.
    root_pins: Vec<RootPin>,
}

pub(super) fn prepare(
    provider: RuntimeProviderId,
    admitted: &AdmittedRights,
    bindings: &landlock_plan::Bindings,
) -> Result<Prepared, String> {
    let plan = landlock_plan::build(provider, admitted, bindings, landlock_plan::kernel_abi()?)?;
    let paths = plan
        .rules
        .iter()
        .map(|rule| {
            CString::new(std::os::unix::ffi::OsStrExt::as_bytes(rule.1.as_os_str()))
                .map_err(|_| format!("Landlock path contains NUL: {}", rule.0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let arch = if cfg!(target_arch = "x86_64") {
        AuditArch::X86_64
    } else {
        AuditArch::Aarch64
    };
    let filters = seccomp_program::program(provider, admitted, arch)
        .into_iter()
        .map(|[code, jt, jf, k]| libc::sock_filter {
            code: code as u16,
            jt: jt as u8,
            jf: jf as u8,
            k,
        })
        .collect::<Vec<_>>();
    if filters.len() > 256 {
        return Err("seccomp install refused: the filter is too long".into());
    }
    // The single-root plan has one directory root, named STORAGE_ROOT.
    // Allow-list plans pin every root in `prepare_path_allow`.
    let root_pins = plan
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| rule.0 == "STORAGE_ROOT")
        .map(|(index, _)| RootPin {
            index,
            dev: plan.storage_dev,
            ino: plan.storage_ino,
        })
        .collect();
    Ok(Prepared {
        plan,
        paths,
        filters,
        root_pins,
    })
}

/// # Safety
/// Call only in a forked child before exec. The caller owns fds 0–2, passes
/// its open failure-record write descriptor and the verified executable
/// descriptor (both at least 3, with FD_CLOEXEC), and writes any returned
/// failure to the report descriptor before exiting the child. Tests use -1
/// when there is no executable descriptor.
pub(super) unsafe fn install(
    prepared: &Prepared,
    keep: i32,
    executable: i32,
) -> Result<(), Failure> {
    let mut ruleset = -1;
    let result = sequence(prepared.plan.rules.len(), |step| {
        let answer = match step {
            Step::CloseRange => {
                if keep < 3 || (executable != -1 && (executable < 3 || executable == keep)) {
                    return Err(libc::EINVAL);
                }
                let (first, second) = if executable == -1 || keep < executable {
                    (keep, executable)
                } else {
                    (executable, keep)
                };
                if first > 3
                    && unsafe {
                        libc::syscall(libc::SYS_close_range, 3u32, (first - 1) as u32, 0u32)
                    } < 0
                {
                    return Err(unsafe { *libc::__errno_location() });
                }
                if second != -1 {
                    if second > first + 1
                        && unsafe {
                            libc::syscall(
                                libc::SYS_close_range,
                                (first + 1) as u32,
                                (second - 1) as u32,
                                0u32,
                            )
                        } < 0
                    {
                        return Err(unsafe { *libc::__errno_location() });
                    }
                    if unsafe {
                        libc::syscall(libc::SYS_close_range, (second + 1) as u32, u32::MAX, 0u32)
                    } < 0
                    {
                        return Err(unsafe { *libc::__errno_location() });
                    }
                } else if unsafe {
                    libc::syscall(libc::SYS_close_range, (first + 1) as u32, u32::MAX, 0u32)
                } < 0
                {
                    return Err(unsafe { *libc::__errno_location() });
                }
                0
            }
            Step::NoNewPrivileges => unsafe {
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as libc::c_long
            },
            Step::Create => {
                let attr = RulesetAttr {
                    handled_access_fs: prepared.plan.handled,
                };
                let fd = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_create_ruleset,
                        &attr,
                        std::mem::size_of::<RulesetAttr>(),
                        0u32,
                    )
                };
                if fd >= 0 {
                    ruleset = fd as i32;
                }
                fd
            }
            Step::Add(index) => {
                let Some(path) = prepared.paths.get(index) else {
                    return Err(libc::EINVAL);
                };
                let Some(rule) = prepared.plan.rules.get(index) else {
                    return Err(libc::EINVAL);
                };
                let allowed = rule.2;
                // Every directory root was opened before fork. Open it again
                // without following a symlink and require the same device and
                // inode. DIRECTORY_OPEN_FLAGS is
                // O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY on Linux.
                let pinned = prepared
                    .root_pins
                    .iter()
                    .find(|pin| pin.index == index)
                    .copied();
                let directory = if let Some(pin) = pinned {
                    match super::super::root_pin::open_pinned_directory(
                        path,
                        super::super::root_pin::DIRECTORY_OPEN_FLAGS,
                        pin.dev,
                        pin.ino,
                    ) {
                        Ok(directory) => directory,
                        Err(errno) => return Err(errno),
                    }
                } else {
                    let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    if fd < 0 {
                        return Err(unsafe { *libc::__errno_location() });
                    }
                    // The descriptor was just opened and is not owned elsewhere.
                    unsafe { OwnedFd::from_raw_fd(fd) }
                };
                let attr = PathAttr {
                    allowed_access: allowed,
                    parent_fd: directory.as_raw_fd(),
                };
                let answer = unsafe {
                    libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1u32, &attr, 0u32)
                };
                let errno = unsafe { *libc::__errno_location() };
                drop(directory);
                if answer < 0 {
                    return Err(errno);
                }
                answer
            }
            Step::Restrict => unsafe {
                libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32)
            },
            Step::Seccomp => {
                let filter = libc::sock_fprog {
                    len: prepared.filters.len() as u16,
                    filter: prepared.filters.as_ptr().cast_mut(),
                };
                unsafe {
                    libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &filter)
                        as libc::c_long
                }
            }
        };
        if answer < 0 {
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(())
        }
    });
    if ruleset >= 0 {
        unsafe { libc::close(ruleset) };
    }
    result
}

fn prepare_path_allow(plan: landlock_plan::PathAllowPlan) -> Result<Prepared, String> {
    if plan.root_dev.len() != plan.root_ino.len() || plan.root_dev.is_empty() {
        return Err("provider start is refused: a path root has no identity".into());
    }
    let mut root_pins = Vec::with_capacity(plan.root_dev.len());
    for (index, (dev, ino)) in plan
        .root_dev
        .iter()
        .copied()
        .zip(plan.root_ino.iter().copied())
        .enumerate()
    {
        let Some(rule) = plan.rules.get(index) else {
            return Err("provider start is refused: a path root has no Landlock rule".into());
        };
        if matches!(
            rule.0,
            "PROVIDER_EXECUTABLE" | "LANDLOCK_LOADER_PATHS" | "STORAGE_ROOT" | "STORAGE_PARENT"
        ) {
            return Err(format!(
                "provider start is refused: {} is not a path allow-list root",
                rule.0
            ));
        }
        root_pins.push(RootPin { index, dev, ino });
    }
    let paths = plan
        .rules
        .iter()
        .map(|rule| {
            CString::new(std::os::unix::ffi::OsStrExt::as_bytes(rule.1.as_os_str()))
                .map_err(|_| format!("Landlock path contains NUL: {}", rule.0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first = root_pins[0];
    Ok(Prepared {
        plan: landlock_plan::Plan {
            abi: plan.abi,
            handled: plan.handled,
            rules: plan.rules,
            storage_dev: first.dev,
            storage_ino: first.ino,
        },
        paths,
        filters: Vec::new(),
        root_pins,
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::{path_allow, root_pin};
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    fn bindings_for(root: &Path, executable: &Path) -> landlock_plan::Bindings {
        let meta = std::fs::symlink_metadata(root).unwrap();
        landlock_plan::Bindings {
            storage_root: root.to_path_buf(),
            provider_executable: executable.to_path_buf(),
            storage_dev: meta.dev(),
            storage_ino: meta.ino(),
        }
    }

    #[test]
    fn fixed_failure_record_preserves_step_index_and_errno() {
        for (step, errno) in [
            (Step::CloseRange, libc::EBADF),
            (Step::Create, libc::EINVAL),
            (Step::Add(3), libc::EACCES),
            (Step::NoNewPrivileges, libc::EPERM),
            (Step::Restrict, libc::ENOENT),
            (Step::Seccomp, libc::E2BIG),
        ] {
            let failure = Failure(step, errno);
            let record = failure.record();
            let tag = u32::from_ne_bytes(record[..4].try_into().unwrap());
            let index = u32::from_ne_bytes(record[4..8].try_into().unwrap());
            let observed = i32::from_ne_bytes(record[8..].try_into().unwrap());
            assert_eq!(Failure::from_record(tag, index, observed), Some(failure));
        }
    }

    #[test]
    fn installed_child_closes_fds_and_denies_outside_file_and_socket() {
        landlock_plan::kernel_abi().expect("Landlock ABI 5 is required for this kernel row");
        let root = tempfile::tempdir().unwrap();
        let allowed_path = root.path().join("allowed");
        std::fs::write(&allowed_path, b"ok").unwrap();
        let allowed_path = CString::new(allowed_path.as_os_str().as_bytes()).unwrap();
        let marker = std::fs::File::open("/dev/null").unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        let upper_marker = std::fs::File::open("/dev/null").unwrap();
        assert!(report.as_raw_fd() > 3);
        assert!(upper_marker.as_raw_fd() > report.as_raw_fd());
        let admitted = super::super::super::rights::admit_runtime_grant(RuntimeProviderId::Did);
        let prepared = prepare(
            RuntimeProviderId::Did,
            &admitted,
            &bindings_for(root.path(), Path::new("/bin/true")),
        )
        .unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { install(&prepared, report.as_raw_fd(), -1) }.is_err() {
                unsafe { libc::_exit(80) };
            }
            let kept_open = unsafe { libc::close(report.as_raw_fd()) } == 0;
            let fd_closed = unsafe { libc::close(marker.as_raw_fd()) } == -1
                && unsafe { *libc::__errno_location() } == libc::EBADF;
            let upper_fd_closed = unsafe { libc::close(upper_marker.as_raw_fd()) } == -1
                && unsafe { *libc::__errno_location() } == libc::EBADF;
            let allowed = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    allowed_path.as_ptr(),
                    libc::O_RDONLY,
                )
            };
            let file_allowed = allowed >= 0;
            if file_allowed {
                unsafe { libc::close(allowed as i32) };
            }
            let outside = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/passwd".as_ptr(),
                    libc::O_RDONLY,
                )
            };
            let file_denied = outside == -1 && unsafe { *libc::__errno_location() } == libc::EACCES;
            let socket =
                unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) };
            let socket_denied =
                socket == -1 && unsafe { *libc::__errno_location() } == libc::EACCES;
            unsafe {
                libc::_exit(
                    if kept_open
                        && fd_closed
                        && upper_fd_closed
                        && file_allowed
                        && file_denied
                        && socket_denied
                    {
                        0
                    } else {
                        81
                    },
                )
            };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "child install or confinement probe failed with wait status {status}"
        );
    }

    fn order() -> [Step; 7] {
        [
            Step::CloseRange,
            Step::Create,
            Step::Add(0),
            Step::Add(1),
            Step::NoNewPrivileges,
            Step::Restrict,
            Step::Seccomp,
        ]
    }

    #[test]
    fn every_step_applies_in_order() {
        let mut seen = Vec::new();
        sequence(2, |step| {
            seen.push(step);
            Ok(())
        })
        .unwrap();
        assert_eq!(seen, order());
    }

    fn refusal(failed: Step, expected: &str) {
        let mut seen = Vec::new();
        let error = sequence(2, |step| {
            seen.push(step);
            if step == failed {
                Err(22)
            } else {
                Ok(())
            }
        })
        .expect_err("the failed step must refuse the launch");
        assert_eq!(error.to_string(), expected, "{failed:?}");
        let position = order().iter().position(|step| *step == failed).unwrap();
        assert_eq!(seen, order()[..=position], "{failed:?} must stop here");
    }

    #[test]
    fn close_range_refusal() {
        refusal(
            Step::CloseRange,
            "the probe child could not close inherited descriptors: errno 22",
        );
    }
    #[test]
    fn no_new_privileges_refusal() {
        refusal(
            Step::NoNewPrivileges,
            "landlock install refused: PR_SET_NO_NEW_PRIVS failed with errno 22",
        );
    }
    #[test]
    fn create_ruleset_refusal() {
        refusal(
            Step::Create,
            "landlock install refused: the ruleset could not be created with errno 22",
        );
    }
    #[test]
    fn add_rule_refusal() {
        refusal(
            Step::Add(0),
            "landlock install refused: the path rule 0 could not be added with errno 22",
        );
    }
    #[test]
    fn restrict_self_refusal() {
        refusal(
            Step::Restrict,
            "landlock install refused: landlock_restrict_self failed with errno 22",
        );
    }
    #[test]
    fn seccomp_refusal() {
        refusal(
            Step::Seccomp,
            "seccomp install refused: the filter install failed with errno 22",
        );
    }

    #[test]
    fn a_root_swapped_for_a_symlink_between_render_and_install_is_refused_by_the_installer() {
        landlock_plan::kernel_abi().expect("Landlock ABI 5 is required for this kernel row");
        assert_eq!(
            root_pin::DIRECTORY_OPEN_FLAGS,
            libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            "Linux pinned roots are opened with O_PATH|O_NOFOLLOW|O_DIRECTORY"
        );
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path();
        std::fs::create_dir(data.join("identity")).unwrap();
        std::fs::create_dir(data.join("chain-provider")).unwrap();
        let executable = Path::new("/opt/elastos/helper-provider");
        let (_confinement, plan) =
            path_allow::render_with_plan("chain-provider", data, executable, 5)
                .unwrap_or_else(|err| panic!("render before the swap: {err}"));
        let root_index = plan
            .rules
            .iter()
            .position(|rule| rule.0 == "chain-provider")
            .expect("chain root");
        let prepared = prepare_path_allow(plan).unwrap();
        let root = data.join("chain-provider");
        std::fs::remove_dir(&root).unwrap();
        std::os::unix::fs::symlink(data.join("identity"), &root).unwrap();
        let report = std::fs::File::open("/dev/null").unwrap();
        assert!(report.as_raw_fd() >= 3);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let code = match unsafe { install(&prepared, report.as_raw_fd(), -1) } {
                Err(Failure(Step::Add(index), errno))
                    if index == root_index && errno == libc::ESTALE =>
                {
                    0
                }
                Err(Failure(Step::Add(index), errno)) if index == root_index => errno,
                Err(_) => 91,
                Ok(()) => 92,
            };
            unsafe { libc::_exit(code) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert_eq!(
            status, 0,
            "a root swapped for a symlink must be refused by dev/ino mismatch (wait status {status}, exit {})",
            libc::WEXITSTATUS(status)
        );
    }
}
