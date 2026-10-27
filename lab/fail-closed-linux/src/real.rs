//! The real kernel: Linux system calls, and a fork that reports the guard's
//! fault through a close-on-exec pipe.
//!
//! Everything after `fork` in the child is a system call on data `Plan`
//! built before the fork. It does not allocate, lock or panic.
//!
//! `launch` returns the PID-namespace init. The helper that unshares the
//! namespace writes that host pid and exits. Init reaps every child. SIGKILL
//! of init kills the namespace. A start is EOF on the close-on-exec pipe
//! plus `/proc/<provider pid>/exe` matching the expected binary. The
//! identity pipe stays close-on-exec, so it does not leak into the
//! provider. The parent samples `/proc/<pid>/exe` while it waits for the
//! fault pipe. Any bytes are a fault.

use crate::{
    confine_and_exec, exe_identity_ok, interpret_fault_pipe, landlock, proc_exe_dev_ino,
    ruleset_attr_size, Errno, Fault, FaultPipe, Kernel, Plan, Step, ENFORCEMENT_BROKEN,
    REFUSAL_EXIT_CODE,
};
use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;
use std::os::raw::{c_int, c_long};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// The real kernel. `fault_write` is the child's end of the close-on-exec
/// pipe. Reapers close their copy so a successful `execve` produces EOF.
/// `identity_write` is close-on-exec: the provider does not inherit it.
pub struct RealKernel {
    fault_write: RawFd,
    identity_write: RawFd,
    lie_rights: bool,
    lie_enforcement: bool,
    keep: [RawFd; 8],
    keep_n: usize,
    fault_found: u32,
}

impl RealKernel {
    pub fn new() -> RealKernel {
        RealKernel {
            fault_write: -1,
            identity_write: -1,
            lie_rights: false,
            lie_enforcement: false,
            keep: [-1; 8],
            keep_n: 0,
            fault_found: 0,
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
/// Read end of the parent-to-init ack pipe. Init waits here before reaping
/// so `/proc/<provider>/exe` stays visible.
static ACK_READ: AtomicI32 = AtomicI32::new(-1);

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

/// True when fd 0, 1 or 2 is a terminal or a socket. A missing fd is left
/// alone. Any other `fstat` error refuses the launch.
fn stdio_is_terminal_or_socket(fd: RawFd) -> Result<bool, Errno> {
    // SAFETY: isatty and fstat only inspect the fd.
    if unsafe { libc::isatty(fd) } != 0 {
        return Ok(true);
    }
    let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = errno();
        return if err == libc::EBADF {
            Ok(false)
        } else {
            Err(err)
        };
    }
    Ok((st.st_mode & libc::S_IFMT) == libc::S_IFSOCK)
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

fn close_identity_write(kernel: &mut RealKernel) {
    if kernel.identity_write >= 0 {
        // SAFETY: this is our copy of the identity write end.
        unsafe { libc::close(kernel.identity_write) };
        kernel.identity_write = -1;
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
            close_identity_write(self);
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
            close_identity_write(self);
            wait_for_identity_ack();
            reap_namespace();
        }
        close_ack();
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

    fn set_not_dumpable(&mut self, executable: &CStr) -> Result<(), Errno> {
        // After maps and capset, dumpable may already be 0. Set it again so
        // a later exec of a readable file is the only reset. Then make the
        // granted binary execute-only: execve of a readable file sets
        // dumpable back to 1, and a same-uid host can PTRACE_ATTACH.
        // SAFETY: integer prctl only.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(errno());
        }
        // SAFETY: `executable` is a NUL-terminated path from Plan.
        if unsafe { libc::chmod(executable.as_ptr(), 0o111) } != 0 {
            return Err(errno());
        }
        Ok(())
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
        // SAFETY: integer arguments only. Close the ruleset after apply so
        // the provider does not inherit it.
        let result =
            check(unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) })
                .map(drop);
        unsafe { libc::close(ruleset) };
        result
    }

    fn close_unneeded_fds(&mut self) -> Result<(), Errno> {
        let mut keep = [0i32; 16];
        let mut n = 0;
        keep[n] = 0;
        n += 1;
        keep[n] = 1;
        n += 1;
        keep[n] = 2;
        n += 1;
        if self.fault_write >= 0 {
            keep[n] = self.fault_write;
            n += 1;
        }
        for fd in self.keep.iter().take(self.keep_n).copied() {
            if fd >= 0 && !keep[..n].contains(&fd) {
                keep[n] = fd;
                n += 1;
            }
        }
        close_except(&keep[..n])
    }

    fn sanitize_stdio(&mut self) -> Result<(), Errno> {
        for fd in [0, 1, 2] {
            if !stdio_is_terminal_or_socket(fd)? {
                continue;
            }
            self.fault_found = fd as u32;
            // SAFETY: open/dup2/close on /dev/null and a stdio fd.
            let null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if null < 0 {
                return Err(errno());
            }
            if unsafe { libc::dup2(null, fd) } < 0 {
                let err = errno();
                unsafe { libc::close(null) };
                return Err(err);
            }
            unsafe { libc::close(null) };
        }
        Ok(())
    }

    fn named_fault_found(&self) -> u32 {
        self.fault_found
    }

    fn install_no_exec_filter(&mut self, plan: &Plan) -> Result<(), Errno> {
        let path = plan.executable().as_ptr() as usize as u64;
        if path == 0 {
            return Err(libc::EINVAL);
        }
        self.install_seccomp_filter(&crate::seccomp::no_exec_filter(path))
    }

    fn enforcement_self_test(&mut self, plan: &Plan) -> Result<(), Errno> {
        if self.lie_enforcement {
            return Err(ENFORCEMENT_BROKEN);
        }
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(errno());
        }
        if child == 0 {
            run_enforcement_child(plan);
        }
        let mut status = 0;
        loop {
            let ret = unsafe { libc::waitpid(child, &mut status, 0) };
            if ret == child {
                break;
            }
            if ret < 0 && errno() != libc::EINTR {
                return Err(errno());
            }
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else {
            Err(ENFORCEMENT_BROKEN)
        }
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
        if plan.test_close_pipe {
            close_fault_write(self);
            unsafe { libc::_exit(0) };
        }
        // The no-exec filter is already stacked. It allows only this
        // pathname pointer. After the image is replaced, every later
        // execve and execveat returns EPERM.
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

        let [fault_read, fault_write] = match pipe2_cloexec() {
            Ok(pair) => pair,
            Err(err) => return Err(Fault::os(Step::Pipe, err)),
        };
        let [handoff_read, handoff_write] = match pipe2_cloexec() {
            Ok(pair) => pair,
            Err(err) => {
                close_pair(fault_read, fault_write);
                return Err(Fault::os(Step::Pipe, err));
            }
        };
        let [ack_read, ack_write] = match pipe2_cloexec() {
            Ok(pair) => pair,
            Err(err) => {
                close_pair(fault_read, fault_write);
                close_pair(handoff_read, handoff_write);
                return Err(Fault::os(Step::Pipe, err));
            }
        };
        let [identity_read, identity_write] = match pipe2_cloexec() {
            Ok(pair) => pair,
            Err(err) => {
                close_pair(fault_read, fault_write);
                close_pair(handoff_read, handoff_write);
                close_pair(ack_read, ack_write);
                return Err(Fault::os(Step::Pipe, err));
            }
        };

        // SAFETY: the child runs only system calls on `plan` and then
        // `_exit`s or execs; see the module comment.
        let helper = unsafe { libc::fork() };
        if helper < 0 {
            let err = errno();
            close_pair(fault_read, fault_write);
            close_pair(handoff_read, handoff_write);
            close_pair(ack_read, ack_write);
            close_pair(identity_read, identity_write);
            return Err(Fault::os(Step::Fork, err));
        }
        if helper == 0 {
            unsafe {
                libc::close(fault_read);
                libc::close(handoff_read);
                libc::close(ack_write);
                libc::close(identity_read);
            }
            HANDOFF_WRITE.store(handoff_write, Ordering::Relaxed);
            ACK_READ.store(ack_read, Ordering::Relaxed);
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
                    identity_write,
                    lie_rights: plan.test_lie_rights,
                    lie_enforcement: plan.test_lie_enforcement,
                    keep: [handoff_write, ack_read, identity_write, -1, -1, -1, -1, -1],
                    keep_n: 3,
                    fault_found: 0,
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
            libc::close(ack_read);
            libc::close(identity_write);
        }

        let mut pid_buf = [0u8; 4];
        let (got_pid, _) = read_all(handoff_read, &mut pid_buf);
        unsafe { libc::close(handoff_read) };

        let init_pid = (got_pid == 4).then(|| u32::from_le_bytes(pid_buf));

        let expected = plan.exe_dev_ino();
        let mut matched =
            init_pid.is_some_and(|init| spin_exe_identity(init, expected, fault_read));
        let mut buf = [0u8; Fault::ENCODED_LEN * 2];
        let (got, read_error) = read_all(fault_read, &mut buf);
        if !matched {
            matched = init_pid.is_some_and(|init| any_child_matches(init, expected));
        }
        unsafe { libc::close(fault_read) };
        unsafe { libc::close(identity_read) };

        // The helper writes the pid and `_exit`s. One WNOHANG now; do not
        // sleep here or a fast provider can exit before we sample /proc/exe.
        reap_if_exited(helper, 1);

        match interpret_fault_pipe(&buf[..got], read_error) {
            FaultPipe::Started => {
                let init = match init_pid {
                    Some(pid) if pid > 0 && process_alive(pid) => pid,
                    Some(pid) => {
                        unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                        reap(pid as libc::pid_t);
                        unsafe { libc::close(ack_write) };
                        reap_if_exited(helper, 1);
                        return Err(Fault::empty_pipe());
                    }
                    None => {
                        unsafe { libc::close(ack_write) };
                        reap_if_exited(helper, 1);
                        return Err(Fault::empty_pipe());
                    }
                };
                // Init is landlocked and cannot read /proc. The parent is
                // outside. `/proc/<pid>/exe` is stated after fault-pipe EOF
                // while init still holds the namespace.
                if !matched {
                    unsafe { libc::kill(init as libc::pid_t, libc::SIGKILL) };
                    reap(init as libc::pid_t);
                    unsafe { libc::close(ack_write) };
                    reap_if_exited(helper, 1);
                    return Err(Fault::exec_identity());
                }
                let ack = [1u8];
                unsafe {
                    libc::write(ack_write, ack.as_ptr().cast(), ack.len());
                    libc::close(ack_write);
                }
                reap_if_exited(helper, 1);
                Ok(init)
            }
            FaultPipe::Refused(fault) => {
                if let Some(pid) = init_pid {
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                    reap(pid as libc::pid_t);
                }
                unsafe { libc::close(ack_write) };
                reap_if_exited(helper, 1);
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

fn pipe2_cloexec() -> Result<[RawFd; 2], Errno> {
    let mut fds: [c_int; 2] = [-1, -1];
    // SAFETY: `fds` has room for the two descriptors.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(errno());
    }
    Ok(fds)
}

fn close_pair(a: RawFd, b: RawFd) {
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

/// Poll the fault pipe without sleeping so `/proc/<pid>/exe` is sampled
/// in the same thread while the post-exec image still holds the identity fd.
fn spin_exe_identity(init: u32, expected: (u64, u64), fault_read: RawFd) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if any_child_matches(init, expected) {
            return true;
        }
        let mut pfd = libc::pollfd {
            fd: fault_read,
            events: libc::POLLIN,
            revents: 0,
        };
        let pret = unsafe { libc::poll(&mut pfd, 1, 0) };
        if pret < 0 && errno() != libc::EINTR {
            return false;
        }
        if pret > 0 || Instant::now() >= deadline || !process_alive(init) {
            return any_child_matches(init, expected);
        }
    }
}

fn any_child_matches(init: u32, expected: (u64, u64)) -> bool {
    for pid in children_of(init) {
        if exe_identity_ok(expected, proc_exe_dev_ino(pid)) {
            return true;
        }
    }
    false
}

fn children_of(init: u32) -> Vec<u32> {
    let mut pids = Vec::new();
    let path = format!("/proc/{init}/task/{init}/children");
    if let Ok(text) = std::fs::read_to_string(path) {
        for word in text.split_whitespace() {
            if let Ok(pid) = word.parse::<u32>() {
                // The children file can name a namespace-local pid. Keep it
                // only when that pid's host PPid is init.
                if pid > 0 && pid_has_ppid(pid, init) && !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }
    }
    pids
}

fn pid_has_ppid(pid: u32, init: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| parse_ppid(&stat))
        == Some(init)
}

fn parse_ppid(stat: &str) -> Option<u32> {
    let close = stat.rfind(')')?;
    let mut parts = stat[close + 1..].split_whitespace();
    let _state = parts.next()?;
    parts.next()?.parse().ok()
}

fn wait_for_identity_ack() {
    let fd = ACK_READ.load(Ordering::Relaxed);
    if fd < 0 {
        unsafe {
            libc::kill(-1, libc::SIGKILL);
            libc::_exit(REFUSAL_EXIT_CODE);
        }
    }
    let mut byte = [0u8; 1];
    let n = loop {
        let ret = unsafe { libc::read(fd, byte.as_mut_ptr().cast(), 1) };
        if ret < 0 && errno() == libc::EINTR {
            continue;
        }
        break ret;
    };
    unsafe { libc::close(fd) };
    ACK_READ.store(-1, Ordering::Relaxed);
    if n != 1 || byte[0] != 1 {
        unsafe {
            libc::kill(-1, libc::SIGKILL);
            libc::_exit(REFUSAL_EXIT_CODE);
        }
    }
}

fn close_ack() {
    let fd = ACK_READ.swap(-1, Ordering::Relaxed);
    if fd >= 0 {
        unsafe { libc::close(fd) };
    }
}

fn close_except(keep: &[RawFd]) -> Result<(), Errno> {
    let mut held = [0i32; 16];
    if keep.len() > held.len() {
        return Err(libc::ENOMEM);
    }
    held[..keep.len()].copy_from_slice(keep);
    let n = keep.len();
    for i in 1..n {
        let mut j = i;
        while j > 0 && held[j - 1] > held[j] {
            held.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut start = 3i32;
    for &fd in &held[..n] {
        if fd < 3 {
            continue;
        }
        if start < fd {
            close_fd_range(start as u32, (fd - 1) as u32)?;
        }
        start = fd + 1;
    }
    close_fd_range(start as u32, u32::MAX)
}

fn close_fd_range(first: u32, last: u32) -> Result<(), Errno> {
    if first > last {
        return Ok(());
    }
    // SAFETY: close_range takes only integer bounds.
    let ret = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0u32) };
    if ret == 0 {
        return Ok(());
    }
    if errno() != libc::ENOSYS {
        return Err(errno());
    }
    close_fd_range_by_proc(first, last)
}

fn close_fd_range_by_proc(first: u32, last: u32) -> Result<(), Errno> {
    // SAFETY: /proc/self/fd is a directory; getdents64 writes into `buf`.
    unsafe {
        let dir = libc::open(
            c"/proc/self/fd".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        );
        if dir < 0 {
            return Err(errno());
        }
        let mut buf = [0u8; 1024];
        loop {
            let n = libc::syscall(libc::SYS_getdents64, dir, buf.as_mut_ptr(), buf.len());
            if n == 0 {
                break;
            }
            if n < 0 {
                let err = errno();
                libc::close(dir);
                return Err(err);
            }
            let mut off = 0usize;
            let total = n as usize;
            while off + 19 <= total {
                let reclen = u16::from_le_bytes([buf[off + 16], buf[off + 17]]) as usize;
                if reclen < 20 || off + reclen > total {
                    break;
                }
                let name = std::ffi::CStr::from_ptr(buf[off + 19..].as_ptr().cast());
                if let Ok(text) = name.to_str() {
                    if let Ok(fd) = text.parse::<u32>() {
                        if fd != dir as u32 && fd >= first && fd <= last {
                            libc::close(fd as i32);
                        }
                    }
                }
                off += reclen;
            }
        }
        libc::close(dir);
    }
    Ok(())
}

fn fill_path(buf: &mut [u8], root: &[u8], suffix: &[u8]) -> Option<*const libc::c_char> {
    if root.len() + suffix.len() + 1 > buf.len() {
        return None;
    }
    buf[..root.len()].copy_from_slice(root);
    buf[root.len()..root.len() + suffix.len()].copy_from_slice(suffix);
    buf[root.len() + suffix.len()] = 0;
    Some(buf.as_ptr().cast())
}

fn run_enforcement_child(plan: &Plan) -> ! {
    const TIOCGWINSZ: u64 = 0x5413;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const MFD_CLOEXEC: u32 = 1;
    // SAFETY: paths come from Plan; the child only makes system calls.
    unsafe {
        let fd = libc::open(
            plan.enforce_file().as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC,
        );
        if fd >= 0 {
            let n = libc::write(fd, b"x".as_ptr().cast(), 1);
            libc::close(fd);
            if n > 0 {
                libc::_exit(1);
            }
        }
        if libc::truncate(plan.enforce_file().as_ptr(), 0) == 0 {
            libc::_exit(2);
        }
        let tty = libc::open(
            plan.enforce_tty().as_ptr(),
            libc::O_RDONLY | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if tty >= 0 {
            let mut winsize = [0u16; 4];
            let ret = libc::ioctl(tty, TIOCGWINSZ, winsize.as_mut_ptr());
            libc::close(tty);
            if ret == 0 {
                libc::_exit(3);
            }
        }

        let mem = libc::syscall(
            libc::SYS_memfd_create,
            c"e".as_ptr(),
            libc::c_uint::from(MFD_CLOEXEC),
        );
        if mem >= 0 {
            libc::write(mem as i32, b"x".as_ptr().cast(), 1);
            let ret = libc::syscall(
                libc::SYS_execveat,
                mem,
                c"".as_ptr(),
                std::ptr::null::<*const libc::c_char>(),
                std::ptr::null::<*const libc::c_char>(),
                AT_EMPTY_PATH,
            );
            let err = errno();
            libc::close(mem as i32);
            if ret == 0 || (err != libc::EPERM && err != libc::EACCES) {
                libc::_exit(4);
            }
        }

        let root = plan.storage_root().to_bytes();
        let mut dir_a = [0u8; 256];
        let mut dir_b = [0u8; 256];
        let mut file_a = [0u8; 256];
        let mut file_b = [0u8; 256];
        let Some(path_a) = fill_path(&mut dir_a, root, b"/_a") else {
            libc::_exit(5);
        };
        let Some(path_b) = fill_path(&mut dir_b, root, b"/_b") else {
            libc::_exit(5);
        };
        let Some(path_af) = fill_path(&mut file_a, root, b"/_a/f") else {
            libc::_exit(5);
        };
        let Some(path_bf) = fill_path(&mut file_b, root, b"/_b/f") else {
            libc::_exit(5);
        };
        if libc::mkdir(path_a, 0o700) == 0 && libc::mkdir(path_b, 0o700) == 0 {
            let created = libc::open(
                path_af,
                libc::O_WRONLY | libc::O_CREAT | libc::O_CLOEXEC,
                0o600,
            );
            if created >= 0 {
                libc::close(created);
                if libc::rename(path_af, path_bf) == 0 {
                    libc::_exit(5);
                }
            }
        }

        let mut special = [0u8; 256];
        if let Some(fifo) = fill_path(&mut special, root, b"/_fifo") {
            if libc::mkfifo(fifo, 0o600) == 0 {
                libc::_exit(6);
            }
        }
        if let Some(sym) = fill_path(&mut special, root, b"/_sym") {
            if libc::symlink(c"t".as_ptr(), sym) == 0 {
                libc::_exit(7);
            }
        }
        if let Some(chr) = fill_path(&mut special, root, b"/_chr") {
            if libc::mknod(chr, libc::S_IFCHR | 0o600, libc::makedev(1, 3)) == 0 {
                libc::_exit(8);
            }
        }
        if let Some(blk) = fill_path(&mut special, root, b"/_blk") {
            if libc::mknod(blk, libc::S_IFBLK | 0o600, libc::makedev(7, 0)) == 0 {
                libc::_exit(9);
            }
        }
        if let Some(sock) = fill_path(&mut special, root, b"/_sock") {
            if libc::mknod(sock, libc::S_IFSOCK | 0o600, 0) == 0 {
                libc::_exit(10);
            }
        }
        libc::_exit(0);
    }
}
