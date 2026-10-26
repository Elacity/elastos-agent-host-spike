//! The real kernel: Linux system calls, and a fork that reports the guard's
//! fault through a close-on-exec pipe.
//!
//! Everything after `fork` in the child is a system call on data `Plan`
//! built before the fork. It does not allocate, lock or panic.
//!
//! `launch` returns the PID-namespace init. The helper that unshares the
//! namespace writes that host pid and exits. Init reaps every child. SIGKILL
//! of init kills the namespace. A start is EOF on the close-on-exec pipe
//! after `execve`; any bytes are a fault.

use crate::{
    confine_and_exec, interpret_fault_pipe, landlock, ruleset_attr_size, Errno, Fault, FaultPipe,
    Kernel, Plan, Step, REFUSAL_EXIT_CODE,
};
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::os::raw::{c_int, c_long};
use std::sync::atomic::{AtomicI32, Ordering};

/// The real kernel. `fault_write` is the child's end of the close-on-exec
/// pipe. Reapers close their copy so a successful `execve` produces EOF.
pub struct RealKernel {
    fault_write: RawFd,
    lie_rights: bool,
}

impl RealKernel {
    pub fn new() -> RealKernel {
        RealKernel {
            fault_write: -1,
            lie_rights: false,
        }
    }
}

impl Default for RealKernel {
    fn default() -> RealKernel {
        RealKernel::new()
    }
}

/// Write end of the helper-to-parent handoff pipe for init's host pid.
static HANDOFF_WRITE: AtomicI32 = AtomicI32::new(-1);

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
    scoped: u64,
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

extern "C" fn init_take_down(sig: c_int) {
    // SAFETY: kill and _exit are async-signal-safe. PID 1 kill(-1) hits
    // every other process in the namespace.
    unsafe {
        libc::kill(-1, libc::SIGKILL);
        libc::_exit(128 + sig);
    }
}

fn install_init_signals() {
    // SAFETY: the handler only calls kill and _exit.
    unsafe {
        for sig in [
            libc::SIGHUP,
            libc::SIGINT,
            libc::SIGQUIT,
            libc::SIGTERM,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGALRM,
        ] {
            libc::signal(sig, init_take_down as libc::sighandler_t);
        }
    }
}

fn exit_from_wait_status(status: c_int) -> ! {
    // SAFETY: WIF* macros only read the status word; _exit does not return.
    unsafe {
        if libc::WIFEXITED(status) {
            libc::_exit(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            libc::_exit(128 + libc::WTERMSIG(status));
        }
        libc::_exit(70);
    }
}

fn reap_namespace() -> ! {
    let mut first: Option<c_int> = None;
    loop {
        let mut status = 0;
        // SAFETY: `status` is a valid out pointer. waitpid(-1) reaps every
        // child in the namespace, including orphans and daemonize leftovers.
        let ret = unsafe { libc::waitpid(-1, &mut status, 0) };
        if ret > 0 {
            if first.is_none() {
                first = Some(status);
            }
            continue;
        }
        if ret < 0 && errno() == libc::EINTR {
            continue;
        }
        if ret < 0 && errno() == libc::ECHILD {
            match first {
                Some(status) => exit_from_wait_status(status),
                None => unsafe { libc::_exit(0) },
            }
        }
        unsafe { libc::_exit(70) };
    }
}

fn close_fault_write(kernel: &mut RealKernel) {
    if kernel.fault_write >= 0 {
        // SAFETY: this is our copy of the pipe write end.
        unsafe { libc::close(kernel.fault_write) };
        kernel.fault_write = -1;
    }
}

fn process_alive(pid: u32) -> bool {
    // SAFETY: kill(pid, 0) only probes existence.
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn read_all(fd: RawFd, buf: &mut [u8]) -> (usize, Option<Errno>) {
    let mut got = 0usize;
    let mut read_error = None;
    while got < buf.len() {
        // SAFETY: the destination is inside `buf`.
        let n = unsafe { libc::read(fd, buf[got..].as_mut_ptr().cast(), buf.len() - got) };
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
    (got, read_error)
}

impl Kernel for RealKernel {
    fn unshare_user_namespace(&mut self) -> Result<(), Errno> {
        // SAFETY: unshare takes a flag word only.
        check(unsafe { libc::unshare(libc::CLONE_NEWUSER) }.into()).map(drop)
    }

    fn unshare_pid_namespace(&mut self) -> Result<(), Errno> {
        // SAFETY: unshare takes a flag word only. The caller stays in the
        // old PID namespace; later children enter the new one.
        check(unsafe { libc::unshare(libc::CLONE_NEWPID) }.into()).map(drop)
    }

    fn detach_into_pid_namespace(&mut self) -> Result<(), Errno> {
        // SAFETY: the child of this fork is PID 1 in the new namespace.
        let init = unsafe { libc::fork() };
        if init < 0 {
            return Err(errno());
        }
        if init > 0 {
            let fd = HANDOFF_WRITE.load(Ordering::Relaxed);
            if fd >= 0 {
                let bytes = (init as u32).to_le_bytes();
                unsafe {
                    libc::write(fd, bytes.as_ptr().cast(), bytes.len());
                    libc::close(fd);
                }
                HANDOFF_WRITE.store(-1, Ordering::Relaxed);
            }
            close_fault_write(self);
            unsafe { libc::_exit(0) };
        }
        // Init is PID 1. Do not set PDEATHSIG here: the helper (creator)
        // is about to exit. The provider sets PDEATHSIG toward this init.
        // SAFETY: integer prctl only.
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        install_init_signals();
        // SAFETY: this child (init) forks the provider so the provider is
        // not PID 1. PID-1 death still kills the namespace.
        let provider = unsafe { libc::fork() };
        if provider < 0 {
            return Err(errno());
        }
        if provider > 0 {
            close_fault_write(self);
            reap_namespace();
        }
        // SAFETY: if init dies, the provider dies with it.
        unsafe {
            libc::prctl(
                libc::PR_SET_PDEATHSIG,
                libc::SIGKILL as libc::c_ulong,
                0,
                0,
                0,
            )
        };
        Ok(())
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
        scoped: u64,
    ) -> Result<RawFd, Errno> {
        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: handled_net,
            scoped,
        };
        let size = ruleset_attr_size(handled_net, scoped);
        // SAFETY: `attr` is valid for `size` bytes for the duration of the call.
        let fd = check(unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                size,
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

    fn landlock_can_handle_fs(&mut self, access: u64) -> Result<bool, Errno> {
        if self.lie_rights {
            return Ok(false);
        }
        match self.landlock_create_ruleset(access, 0, 0) {
            Ok(fd) => {
                // SAFETY: fd came from create_ruleset above.
                unsafe { libc::close(fd) };
                Ok(true)
            }
            Err(errno) if errno == libc::EINVAL => Ok(false),
            Err(errno) => Err(errno),
        }
    }

    fn exec(&mut self, plan: &Plan) -> Result<(), Errno> {
        // SAFETY: the path, argv and envp come from `plan`, which keeps every
        // pointed-to string alive and NULL-terminates both vectors. The write
        // end is O_CLOEXEC, so a successful execve closes it and the parent
        // sees EOF. Any bytes written before execve are a fault.
        unsafe { libc::execve(plan.executable().as_ptr(), plan.argv(), plan.envp()) };
        Err(errno())
    }

    fn spawn_confined(&mut self, plan: &Plan) -> Result<u32, Fault> {
        // SAFETY: integer prctl. We adopt init after the helper exits.
        if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
            return Err(Fault::os(Step::Prepare, errno()));
        }

        let mut fault_fds: [c_int; 2] = [-1, -1];
        // SAFETY: `fault_fds` has room for the two descriptors.
        if unsafe { libc::pipe2(fault_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(Fault::os(Step::Pipe, errno()));
        }
        let [fault_read, fault_write] = fault_fds;

        let mut handoff_fds: [c_int; 2] = [-1, -1];
        // SAFETY: `handoff_fds` has room for the two descriptors.
        if unsafe { libc::pipe2(handoff_fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            unsafe {
                libc::close(fault_read);
                libc::close(fault_write);
            }
            return Err(Fault::os(Step::Pipe, errno()));
        }
        let [handoff_read, handoff_write] = handoff_fds;

        // SAFETY: the child runs only system calls on `plan` and then
        // `_exit`s or execs; see the module comment.
        let helper = unsafe { libc::fork() };
        if helper < 0 {
            let err = errno();
            unsafe {
                libc::close(fault_read);
                libc::close(fault_write);
                libc::close(handoff_read);
                libc::close(handoff_write);
            }
            return Err(Fault::os(Step::Fork, err));
        }
        if helper == 0 {
            unsafe {
                libc::close(fault_read);
                libc::close(handoff_read);
            }
            HANDOFF_WRITE.store(handoff_write, Ordering::Relaxed);
            if plan.test_empty_pipe {
                unsafe { libc::_exit(REFUSAL_EXIT_CODE) };
            }
            if plan.test_confine_ready {
                let bytes = Fault::confine_ready().encode();
                unsafe {
                    libc::write(fault_write, bytes.as_ptr().cast(), bytes.len());
                    libc::_exit(REFUSAL_EXIT_CODE);
                }
            }
            let fault = match confine_and_exec(
                &mut RealKernel {
                    fault_write,
                    lie_rights: plan.test_lie_rights,
                },
                plan,
            ) {
                Err(fault) => fault,
                Ok(()) => Fault::os(Step::Execve, 0),
            };
            let bytes = fault.encode();
            unsafe {
                libc::write(fault_write, bytes.as_ptr().cast(), bytes.len());
                libc::_exit(REFUSAL_EXIT_CODE);
            }
        }

        unsafe {
            libc::close(fault_write);
            libc::close(handoff_write);
        }

        let mut pid_buf = [0u8; 4];
        let (got_pid, _) = read_all(handoff_read, &mut pid_buf);
        unsafe { libc::close(handoff_read) };
        // The helper writes the pid and `_exit`s. Do not block forever if a
        // plant keeps it alive: wait up to 100 ms, then leave it.
        reap_if_exited(helper, 100);

        let init_pid = (got_pid == 4).then(|| u32::from_le_bytes(pid_buf));

        let mut buf = [0u8; Fault::ENCODED_LEN * 2];
        let (got, read_error) = read_all(fault_read, &mut buf);
        unsafe { libc::close(fault_read) };

        match interpret_fault_pipe(&buf[..got], read_error) {
            FaultPipe::Started => match init_pid {
                Some(pid) if pid > 0 && process_alive(pid) => Ok(pid),
                Some(pid) => {
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    reap(pid as libc::pid_t);
                    Err(Fault::empty_pipe())
                }
                None => Err(Fault::empty_pipe()),
            },
            FaultPipe::Refused(fault) => {
                if let Some(pid) = init_pid {
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    reap(pid as libc::pid_t);
                }
                Err(fault)
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

fn reap_if_exited(pid: libc::pid_t, tries: u32) {
    for _ in 0..tries {
        let mut status = 0;
        // SAFETY: WNOHANG does not block; `status` is a valid out pointer.
        let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if ret == pid {
            return;
        }
        if ret < 0 && errno() != libc::EINTR {
            return;
        }
        unsafe { libc::usleep(1000) };
    }
}
