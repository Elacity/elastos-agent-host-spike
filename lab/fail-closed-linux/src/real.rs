//! The real kernel: Linux system calls, and a fork that reports the guard's
//! fault through a close-on-exec pipe.
//!
//! Everything after `fork` in the child is a system call on data `Plan`
//! built before the fork. It does not allocate, lock or panic.

use crate::{confine_and_exec, landlock, Errno, Fault, Kernel, Plan, Step, REFUSAL_EXIT_CODE};
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::os::raw::{c_int, c_long};

pub struct RealKernel;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

fn errno() -> Errno {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

fn check(ret: c_long) -> Result<c_long, Errno> {
    if ret < 0 {
        Err(errno())
    } else {
        Ok(ret)
    }
}

/// Writes `data` to `path` in one `write`, as `/proc/self/*_map` requires.
fn write_file(path: &CStr, data: &[u8]) -> Result<(), Errno> {
    // SAFETY: `path` is NUL-terminated; `data` is valid for its length.
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(errno());
        }
        let written = libc::write(fd, data.as_ptr().cast(), data.len());
        let result = if written < 0 {
            Err(errno())
        } else if written as usize != data.len() {
            Err(libc::EIO)
        } else {
            Ok(())
        };
        libc::close(fd);
        result
    }
}

fn read_u32(path: &CStr) -> Result<u32, Errno> {
    let mut buf = [0u8; 16];
    // SAFETY: `path` is NUL-terminated; `buf` is valid for its length.
    let len = unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return Err(errno());
        }
        let len = libc::read(fd, buf.as_mut_ptr().cast(), buf.len());
        let err = errno();
        libc::close(fd);
        if len < 0 {
            return Err(err);
        }
        len as usize
    };
    let mut value: u32 = 0;
    let mut digits = 0;
    for &byte in buf.iter().take(len) {
        match byte {
            b'0'..=b'9' => {
                value = value
                    .checked_mul(10)
                    .and_then(|v| v.checked_add(u32::from(byte - b'0')))
                    .ok_or(libc::ERANGE)?;
                digits += 1;
            }
            b'\n' => break,
            _ => return Err(libc::EINVAL),
        }
    }
    if digits == 0 {
        return Err(libc::EINVAL);
    }
    Ok(value)
}

impl Kernel for RealKernel {
    fn unshare_user_namespace(&mut self) -> Result<(), Errno> {
        // SAFETY: unshare takes a flag word only.
        check(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into()).map(drop)
    }

    fn write_uid_map(&mut self, map: &[u8]) -> Result<(), Errno> {
        write_file(c"/proc/self/uid_map", map)
    }

    fn deny_setgroups(&mut self) -> Result<(), Errno> {
        write_file(c"/proc/self/setgroups", b"deny")
    }

    fn write_gid_map(&mut self, map: &[u8]) -> Result<(), Errno> {
        write_file(c"/proc/self/gid_map", map)
    }

    fn last_capability(&mut self) -> Result<u32, Errno> {
        read_u32(c"/proc/sys/kernel/cap_last_cap")
    }

    fn drop_bounding_capability(&mut self, cap: u32) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(
            unsafe { libc::prctl(libc::PR_CAPBSET_DROP, libc::c_ulong::from(cap), 0, 0, 0) }.into(),
        )
        .map(drop)
    }

    fn clear_ambient_capabilities(&mut self) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(
            unsafe {
                libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_CLEAR_ALL,
                    0,
                    0,
                    0,
                )
            }
            .into(),
        )
        .map(drop)
    }

    fn clear_capability_sets(&mut self) -> Result<(), Errno> {
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        // SAFETY: header and data match the version 3 layout and outlive the call.
        check(unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) }).map(drop)
    }

    fn set_no_new_privs(&mut self) -> Result<(), Errno> {
        // SAFETY: prctl with integer arguments only.
        check(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) }.into()).map(drop)
    }

    fn install_seccomp_filter(&mut self, filter: &[libc::sock_filter]) -> Result<(), Errno> {
        let len = u16::try_from(filter.len()).map_err(|_| libc::EINVAL)?;
        let prog = libc::sock_fprog {
            len,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: `prog` points at `filter`, which outlives the call; the
        // kernel copies the program.
        check(unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const libc::sock_fprog,
            )
        })
        .map(drop)
    }

    fn landlock_abi(&mut self) -> Result<u32, Errno> {
        // SAFETY: the version query takes a NULL attribute and size 0.
        let abi = check(unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                landlock::CREATE_RULESET_VERSION,
            )
        })?;
        u32::try_from(abi).map_err(|_| libc::ERANGE)
    }

    fn landlock_create_ruleset(
        &mut self,
        handled_fs: u64,
        handled_net: u64,
    ) -> Result<RawFd, Errno> {
        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: handled_net,
        };
        // SAFETY: `attr` is valid for its size for the duration of the call.
        let fd = check(unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        })?;
        RawFd::try_from(fd).map_err(|_| libc::EBADF)
    }

    fn landlock_add_path_rule(
        &mut self,
        ruleset: RawFd,
        path: &CStr,
        access: u64,
    ) -> Result<(), Errno> {
        // SAFETY: `path` is NUL-terminated; `attr` outlives the call.
        unsafe {
            let parent_fd = libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
            if parent_fd < 0 {
                return Err(errno());
            }
            let attr = PathBeneathAttr {
                allowed_access: access,
                parent_fd,
            };
            let ret = libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset,
                landlock::RULE_PATH_BENEATH,
                &attr as *const PathBeneathAttr,
                0u32,
            );
            let err = errno();
            libc::close(parent_fd);
            if ret < 0 {
                Err(err)
            } else {
                Ok(())
            }
        }
    }

    fn landlock_restrict_self(&mut self, ruleset: RawFd) -> Result<(), Errno> {
        // SAFETY: integer arguments only.
        check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) }).map(drop)
    }

    fn exec(&mut self, plan: &Plan) -> Result<(), Errno> {
        // SAFETY: the path, argv and envp come from `plan`, which keeps every
        // pointed-to string alive and NULL-terminates both vectors.
        unsafe { libc::execve(plan.executable().as_ptr(), plan.argv(), plan.envp()) };
        Err(errno())
    }

    fn spawn_confined(&mut self, plan: &Plan) -> Result<u32, Fault> {
        let mut fds: [c_int; 2] = [-1, -1];
        // SAFETY: `fds` has room for the two descriptors.
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(Fault::os(Step::Pipe, errno()));
        }
        let [read_end, write_end] = fds;

        // SAFETY: the child runs only system calls on `plan` and then
        // `_exit`s or execs; see the module comment.
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            let err = errno();
            // SAFETY: both descriptors came from pipe2 above.
            unsafe {
                libc::close(read_end);
                libc::close(write_end);
            }
            return Err(Fault::os(Step::Fork, err));
        }
        if pid == 0 {
            // SAFETY: closing our copy of the read end, then reporting and exiting.
            unsafe { libc::close(read_end) };
            let fault = match confine_and_exec(&mut RealKernel, plan) {
                Err(fault) => fault,
                Ok(()) => Fault::os(Step::Execve, 0),
            };
            let bytes = fault.encode();
            // SAFETY: `bytes` is valid for its length; `_exit` does not return.
            unsafe {
                libc::write(write_end, bytes.as_ptr().cast(), bytes.len());
                libc::_exit(REFUSAL_EXIT_CODE);
            }
        }

        // SAFETY: the parent closes its copy of the write end.
        unsafe { libc::close(write_end) };
        let mut buf = [0u8; Fault::ENCODED_LEN];
        let mut got = 0usize;
        let mut read_error = None;
        while got < buf.len() {
            // SAFETY: the destination is inside `buf`.
            let n =
                unsafe { libc::read(read_end, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
            if n < 0 {
                let err = errno();
                if err == libc::EINTR {
                    continue;
                }
                read_error = Some(err);
                break;
            }
            if n == 0 {
                break;
            }
            got += n as usize;
        }
        // SAFETY: the read end came from pipe2 above.
        unsafe { libc::close(read_end) };

        if got == 0 && read_error.is_none() {
            return Ok(pid as u32);
        }
        if read_error.is_some() {
            // SAFETY: `pid` is our child; we do not know its state, so stop it.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        reap(pid);
        match read_error {
            Some(err) => Err(Fault::os(Step::Report, err)),
            None => {
                Err(Fault::decode(&buf[..got]).unwrap_or(Fault::os(Step::Report, libc::EPROTO)))
            }
        }
    }
}

fn reap(pid: libc::pid_t) {
    let mut status = 0;
    loop {
        // SAFETY: `status` is a valid out pointer.
        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        if ret >= 0 || errno() != libc::EINTR {
            return;
        }
    }
}
