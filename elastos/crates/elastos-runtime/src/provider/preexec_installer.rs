//! Linux provider attachment. Prepare owned buffers before fork; install in the child.
#![allow(dead_code)] // The spawn caller arrives in a later B3 slice.

use super::{
    landlock_plan, rights_table::RuntimeProviderId, seccomp_list::AuditArch, seccomp_program,
};
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

pub(super) struct Prepared {
    plan: landlock_plan::Plan,
    paths: Vec<CString>,
    filters: Vec<libc::sock_filter>,
}

pub(super) fn prepare(
    provider: RuntimeProviderId,
    bindings: &landlock_plan::Bindings,
) -> Result<Prepared, String> {
    let plan = landlock_plan::build(provider, bindings, landlock_plan::kernel_abi()?)?;
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
    let filters = seccomp_program::program(provider, arch)
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
    Ok(Prepared {
        plan,
        paths,
        filters,
    })
}

/// # Safety
/// Call only in a forked child before exec. The caller owns fds 0–2, passes
/// its open failure-record write descriptor (at least 3, with FD_CLOEXEC), and writes any
/// returned failure to that descriptor before exiting the child.
pub(super) unsafe fn install(prepared: &Prepared, keep: i32) -> Result<(), Failure> {
    let mut ruleset = -1;
    let result = sequence(prepared.plan.rules.len(), |step| {
        let answer = match step {
            Step::CloseRange => {
                if keep < 3 {
                    return Err(libc::EINVAL);
                }
                if keep > 3
                    && unsafe {
                        libc::syscall(libc::SYS_close_range, 3u32, (keep as u32) - 1, 0u32)
                    } < 0
                {
                    return Err(unsafe { *libc::__errno_location() });
                }
                if unsafe {
                    libc::syscall(libc::SYS_close_range, (keep as u32) + 1, u32::MAX, 0u32)
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
                let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd < 0 {
                    return Err(unsafe { *libc::__errno_location() });
                }
                let attr = PathAttr {
                    allowed_access: rule.2,
                    parent_fd: fd,
                };
                let answer = unsafe {
                    libc::syscall(libc::SYS_landlock_add_rule, ruleset, 1u32, &attr, 0u32)
                };
                let errno = unsafe { *libc::__errno_location() };
                unsafe { libc::close(fd) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;

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
        let prepared = prepare(
            RuntimeProviderId::Did,
            &landlock_plan::Bindings {
                storage_root: root.path().to_path_buf(),
                provider_executable: "/bin/true".into(),
            },
        )
        .unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if unsafe { install(&prepared, report.as_raw_fd()) }.is_err() {
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
}
