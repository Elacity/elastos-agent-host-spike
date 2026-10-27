//! Stand-in provider for the real-kernel tests.
//!
//! usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR
//!        [--tty-path PATH] [--inherited-fd N] [--kill-host PID] [--exit CODE]
//!        [--daemonize] [--orphan-exit] [--memfd-exec] [--memfd-child]
//!        [--memfd-procfd] [--reexec] [--reexec-child] [--scm-recv]
//!        [--stdio-check]
//!
//! It writes STORAGE_ROOT/probe-ran first, prints one line per check, prints
//! `nspid=` from `/proc/self/status`, prints `ready`, then waits until stdin
//! closes so the test can read the running process. `--tty-path` is a pty
//! slave the probe opens after confine so Landlock can deny `ioctl`.
//! `--kill-host` tries `kill(PID, 0)` and a kill of its own child. `--exit`
//! ends with that code instead of waiting. `--daemonize` forks and the parent
//! exits. `--orphan-exit` double-forks a grandchild that exits so init must
//! reap it.

use std::ffi::CString;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn fork() -> i32;
    fn pause() -> i32;
    fn getpid() -> i32;
    fn waitpid(pid: i32, wstatus: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
    fn truncate(path: *const std::ffi::c_char, length: i64) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn isatty(fd: i32) -> i32;
    fn fcntl(fd: i32, cmd: i32) -> i32;
    fn fstat(fd: i32, buf: *mut Stat) -> i32;
    fn fchmod(fd: i32, mode: u32) -> i32;
    fn execve(
        path: *const std::ffi::c_char,
        argv: *const *const std::ffi::c_char,
        envp: *const *const std::ffi::c_char,
    ) -> i32;
    fn recvmsg(fd: i32, msg: *mut Msghdr, flags: i32) -> isize;
    fn syscall(nr: i64, ...) -> i64;
    fn prctl(option: i32, ...) -> i32;
    #[link_name = "write"]
    fn c_write(fd: i32, buf: *const u8, count: usize) -> isize;
}

#[repr(C)]
struct Stat {
    st_dev: u64,
    st_ino: u64,
    st_nlink: u64,
    st_mode: u32,
    _rest: [u8; 128],
}

#[repr(C)]
struct Iovec {
    iov_base: *mut u8,
    iov_len: usize,
}

#[repr(C)]
struct Msghdr {
    msg_name: *mut u8,
    msg_namelen: u32,
    msg_iov: *mut Iovec,
    msg_iovlen: usize,
    msg_control: *mut u8,
    msg_controllen: usize,
    msg_flags: i32,
}

#[repr(C)]
struct Cmsghdr {
    cmsg_len: usize,
    cmsg_level: i32,
    cmsg_type: i32,
}

const SIGKILL: i32 = 9;
const S_IFMT: u32 = 0o170000;
const S_IFSOCK: u32 = 0o140000;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSTI: u64 = 0x5412;
const O_RDONLY: i32 = 0;
const O_NOCTTY: i32 = 0o400;
const F_GETFD: i32 = 1;
const AT_EMPTY_PATH: i64 = 0x1000;
const MFD_CLOEXEC: u32 = 1;
const MFD_EXEC: u32 = 0x0010;
const PR_SET_DUMPABLE: i32 = 4;
#[cfg(target_arch = "x86_64")]
const SYS_MEMFD_CREATE: i64 = 319;
#[cfg(target_arch = "x86_64")]
const SYS_EXECVEAT: i64 = 322;
#[cfg(target_arch = "aarch64")]
const SYS_MEMFD_CREATE: i64 = 279;
#[cfg(target_arch = "aarch64")]
const SYS_EXECVEAT: i64 = 281;
// Common numbers on x86_64 and aarch64.
const SYS_PIDFD_SEND_SIGNAL: i64 = 424;
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_PIDFD_GETFD: i64 = 438;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        usage();
    }
    let provider = &args[1];
    let storage = Path::new(&args[2]);
    let outside_file = Path::new(&args[3]);
    let outside_dir = Path::new(&args[4]);
    let extra = parse_extra(&args[5..]);
    if extra.memfd_child {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "memfd_exec ran");
        let _ = out.flush();
        std::process::exit(0);
    }
    if extra.reexec_child {
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "after_reexec");
        let _ = out.flush();
        std::process::exit(0);
    }

    let marker = fs::write(storage.join("probe-ran"), provider);
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "fds={}", list_fds());
    let _ = writeln!(out, "stdin_tty={}", i32::from(unsafe { isatty(0) } != 0));
    let _ = writeln!(out, "stdin_sock={}", i32::from(fd_is_sock(0)));
    report(&mut out, "stdin_ioctl", ioctl_on_fd(0));
    report(&mut out, "stdin_tiocsti", ioctl_tiocsti(0));
    try_set_dumpable(&mut out);
    try_pidfd_parent(&mut out);
    if extra.memfd_exec {
        try_memfd_exec(&mut out, &args[0]);
    }
    if extra.memfd_procfd {
        try_memfd_procfd(&mut out, &args[0]);
    }
    if extra.reexec {
        try_reexec(&mut out, &args[0]);
    }
    if extra.scm_recv {
        try_scm_recv(&mut out);
    }
    let _ = writeln!(out, "probe-ran provider={provider}");
    report(&mut out, "marker", marker);
    report(
        &mut out,
        "socket_inet",
        TcpListener::bind("127.0.0.1:0").map(drop),
    );
    report(&mut out, "socket_unix", UnixDatagram::unbound().map(drop));
    report(&mut out, "read_outside", fs::read(outside_file).map(drop));
    report(
        &mut out,
        "write_outside",
        fs::write(outside_dir.join("written-by-probe"), b"x"),
    );
    report(&mut out, "read_etc_passwd", fs::read("/etc/passwd").map(drop));
    report(
        &mut out,
        "storage_write",
        fs::write(storage.join("probe.txt"), b"inside"),
    );
    report(
        &mut out,
        "storage_read",
        fs::read(storage.join("probe.txt")).and_then(|bytes| {
            if bytes == b"inside" {
                Ok(())
            } else {
                Err(io::Error::other("storage read returned other bytes"))
            }
        }),
    );
    report(
        &mut out,
        "truncate_storage",
        truncate_path(&storage.join("probe.txt")),
    );
    report(&mut out, "truncate_outside", truncate_path(outside_file));
    report(
        &mut out,
        "o_trunc_outside",
        OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(outside_file)
            .map(drop),
    );
    if let Some(path) = extra.tty_path.as_deref() {
        report(&mut out, "ioctl_dev", ioctl_tty(path));
    }
    for fd in &extra.inherited_fds {
        report(&mut out, &format!("inherit_ioctl_{fd}"), ioctl_on_fd(*fd));
    }
    let _ = writeln!(out, "nspid={}", nspid());
    if let Some(host_pid) = extra.kill_host {
        report_kill(&mut out, host_pid);
    }
    if extra.orphan_exit {
        orphan_exiting_grandchild(&mut out);
    }
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    drop(out);

    if extra.daemonize {
        let child = unsafe { fork() };
        if child < 0 {
            std::process::exit(2);
        }
        if child > 0 {
            unsafe { _exit(0) };
        }
    }

    if let Some(code) = extra.exit_code {
        std::process::exit(code);
    }
    let mut rest = Vec::new();
    let _ = io::stdin().read_to_end(&mut rest);
}

struct Extra {
    tty_path: Option<String>,
    inherited_fds: Vec<i32>,
    kill_host: Option<i32>,
    exit_code: Option<i32>,
    daemonize: bool,
    orphan_exit: bool,
    memfd_exec: bool,
    memfd_child: bool,
    memfd_procfd: bool,
    reexec: bool,
    reexec_child: bool,
    scm_recv: bool,
}

fn parse_extra(args: &[String]) -> Extra {
    let mut extra = Extra {
        tty_path: None,
        inherited_fds: Vec::new(),
        kill_host: None,
        exit_code: None,
        daemonize: false,
        orphan_exit: false,
        memfd_exec: false,
        memfd_child: false,
        memfd_procfd: false,
        reexec: false,
        reexec_child: false,
        scm_recv: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tty-path" => {
                extra.tty_path = Some(args.get(i + 1).cloned().unwrap_or_else(|| usage()));
                i += 2;
            }
            "--inherited-fd" => {
                extra.inherited_fds.push(parse_i32(args.get(i + 1)));
                i += 2;
            }
            "--kill-host" => {
                extra.kill_host = Some(parse_i32(args.get(i + 1)));
                i += 2;
            }
            "--exit" => {
                extra.exit_code = Some(parse_i32(args.get(i + 1)));
                i += 2;
            }
            "--daemonize" => {
                extra.daemonize = true;
                i += 1;
            }
            "--orphan-exit" => {
                extra.orphan_exit = true;
                i += 1;
            }
            "--memfd-exec" => {
                extra.memfd_exec = true;
                i += 1;
            }
            "--memfd-child" => {
                extra.memfd_child = true;
                i += 1;
            }
            "--memfd-procfd" => {
                extra.memfd_procfd = true;
                i += 1;
            }
            "--reexec" => {
                extra.reexec = true;
                i += 1;
            }
            "--reexec-child" => {
                extra.reexec_child = true;
                i += 1;
            }
            "--scm-recv" => {
                extra.scm_recv = true;
                i += 1;
            }
            _ => usage(),
        }
    }
    extra
}

fn parse_i32(arg: Option<&String>) -> i32 {
    match arg.and_then(|text| text.parse().ok()) {
        Some(value) => value,
        None => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR [--tty-path PATH] [--inherited-fd N] [--kill-host PID] [--exit CODE] [--daemonize] [--orphan-exit] [--memfd-exec] [--memfd-child] [--memfd-procfd] [--reexec] [--reexec-child] [--scm-recv]"
    );
    std::process::exit(2);
}

fn nspid() -> i32 {
    // Inside a new PID namespace this is 1 (init) or 2 (the provider).
    // SAFETY: getpid cannot fail.
    unsafe { getpid() }
}

fn report_kill(out: &mut impl Write, host_pid: i32) {
    let host = unsafe { kill(host_pid, 0) };
    if host == 0 {
        let _ = writeln!(out, "kill_host ok");
    } else {
        let _ = writeln!(
            out,
            "kill_host errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    }

    let child = unsafe { fork() };
    if child < 0 {
        let _ = writeln!(
            out,
            "kill_child errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        return;
    }
    if child == 0 {
        unsafe {
            pause();
            _exit(0);
        }
    }
    let sent = unsafe { kill(child, 0) };
    if sent == 0 {
        let _ = writeln!(out, "kill_child ok");
    } else {
        let _ = writeln!(
            out,
            "kill_child errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    }
    unsafe {
        kill(child, SIGKILL);
        let mut status = 0;
        waitpid(child, &mut status, 0);
    }
}

fn orphan_exiting_grandchild(out: &mut impl Write) {
    let mid = unsafe { fork() };
    if mid < 0 {
        let _ = writeln!(
            out,
            "orphan errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        return;
    }
    if mid == 0 {
        let gc = unsafe { fork() };
        if gc == 0 {
            unsafe { _exit(0) };
        }
        unsafe { _exit(0) };
    }
    unsafe {
        let mut status = 0;
        waitpid(mid, &mut status, 0);
    }
    let _ = writeln!(out, "orphan-forked");
}

fn truncate_path(path: &Path) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let ret = unsafe { truncate(c_path.as_ptr(), 0) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[repr(C)]
struct Winsize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

fn ioctl_tty(path: &str) -> io::Result<()> {
    let c_path = CString::new(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let fd = unsafe { open(c_path.as_ptr(), O_RDONLY | O_NOCTTY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let result = ioctl_on_fd(fd);
    unsafe { close(fd) };
    result
}

fn ioctl_on_fd(fd: i32) -> io::Result<()> {
    let mut winsize = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let ret = unsafe { ioctl(fd, TIOCGWINSZ, &mut winsize as *mut Winsize) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn report(out: &mut impl Write, check: &str, result: io::Result<()>) {
    let _ = match result {
        Ok(()) => writeln!(out, "{check} ok"),
        Err(err) => writeln!(out, "{check} errno={}", err.raw_os_error().unwrap_or(-1)),
    };
}

fn list_fds() -> String {
    let mut open = Vec::new();
    for fd in 0..64 {
        if unsafe { fcntl(fd, F_GETFD) } >= 0 {
            open.push(fd.to_string());
        }
    }
    open.join(",")
}

fn ioctl_tiocsti(fd: i32) -> io::Result<()> {
    let ch: u8 = b'x';
    let ret = unsafe { ioctl(fd, TIOCSTI, &ch as *const u8) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn try_memfd_exec(out: &mut impl Write, self_path: &str) {
    // The granted binary is execute-only after confine. A dummy image is
    // enough: seccomp must return EPERM before the kernel reads the bytes.
    let src = b"fcl-memfd-dummy";
    let flags = MFD_CLOEXEC | MFD_EXEC;
    let mem = unsafe { syscall(SYS_MEMFD_CREATE, b"fcl\0".as_ptr(), flags) };
    let mem = if mem < 0 {
        let first = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        let _ = writeln!(out, "memfd_create_exec errno={first}");
        unsafe { syscall(SYS_MEMFD_CREATE, b"fcl\0".as_ptr(), MFD_CLOEXEC) }
    } else {
        mem
    };
    if mem < 0 {
        let _ = writeln!(
            out,
            "memfd_create errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        return;
    }
    let fd = mem as i32;
    let wrote = unsafe { c_write(fd, src.as_ptr(), src.len()) };
    if wrote < 0 || wrote as usize != src.len() {
        let _ = writeln!(
            out,
            "memfd_write errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        unsafe { close(fd) };
        return;
    }
    let arg0 = std::ffi::CString::new(self_path).unwrap_or_else(|_| std::ffi::CString::new("p").unwrap());
    let arg1 = std::ffi::CString::new("--memfd-child").unwrap();
    let argv = [arg0.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<i8>()];
    let ret = unsafe {
        syscall(
            SYS_EXECVEAT,
            i64::from(fd),
            b"\0".as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            AT_EMPTY_PATH,
        )
    };
    let _ = writeln!(
        out,
        "memfd_exec errno={}",
        if ret == 0 {
            0
        } else {
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    );
    unsafe { close(fd) };
}

fn fd_is_sock(fd: i32) -> bool {
    let mut st = Stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        _rest: [0; 128],
    };
    unsafe { fstat(fd, &mut st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK }
}

fn try_memfd_procfd(out: &mut impl Write, _self_path: &str) {
    let src = b"fcl-memfd-dummy";
    let mem = unsafe { syscall(SYS_MEMFD_CREATE, b"fcl\0".as_ptr(), MFD_CLOEXEC) };
    if mem < 0 {
        let _ = writeln!(
            out,
            "memfd_procfd_create errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        return;
    }
    let fd = mem as i32;
    let wrote = unsafe { c_write(fd, src.as_ptr(), src.len()) };
    if wrote < 0 || wrote as usize != src.len() {
        let _ = writeln!(
            out,
            "memfd_procfd_write errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        unsafe { close(fd) };
        return;
    }
    if unsafe { fchmod(fd, 0o755) } != 0 {
        let _ = writeln!(
            out,
            "memfd_procfd_fchmod errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        unsafe { close(fd) };
        return;
    }
    let path = format!("/proc/self/fd/{fd}");
    let c_path = std::ffi::CString::new(path).unwrap();
    let arg1 = std::ffi::CString::new("--memfd-child").unwrap();
    let argv = [c_path.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<std::ffi::c_char>()];
    let ret = unsafe { execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    let _ = writeln!(
        out,
        "memfd_procfd errno={}",
        if ret == 0 {
            0
        } else {
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    );
    unsafe { close(fd) };
}

fn try_reexec(out: &mut impl Write, self_path: &str) {
    let c_path = match std::ffi::CString::new(self_path) {
        Ok(path) => path,
        Err(_) => {
            let _ = writeln!(out, "reexec errno=-1");
            return;
        }
    };
    let arg1 = std::ffi::CString::new("--reexec-child").unwrap();
    let argv = [c_path.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<std::ffi::c_char>()];
    let ret = unsafe { execve(c_path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    let _ = writeln!(
        out,
        "reexec errno={}",
        if ret == 0 {
            0
        } else {
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        }
    );
}

fn try_set_dumpable(out: &mut impl Write) {
    let ret = unsafe { prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) };
    if ret == 0 {
        let _ = writeln!(out, "set_dumpable ok");
    } else {
        let _ = writeln!(
            out,
            "set_dumpable errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
    }
}

fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn report_syscall(out: &mut impl Write, name: &str, ret: i64) {
    if ret >= 0 {
        let _ = writeln!(out, "{name} ok");
    } else {
        let _ = writeln!(out, "{name} errno={}", last_errno());
    }
}

/// Exercise pidfd_open of init, then pidfd_getfd and pidfd_send_signal.
/// When open is denied the other two still run against a dummy fd so
/// seccomp, not the kernel fd check, is what the test sees.
fn try_pidfd_parent(out: &mut impl Write) {
    let open = unsafe { syscall(SYS_PIDFD_OPEN, 1i32, 0i32) };
    report_syscall(out, "pidfd_open_parent", open);
    let pidfd = if open >= 0 { open as i32 } else { 0 };
    let getfd = unsafe { syscall(SYS_PIDFD_GETFD, pidfd, 1i32, 0i32) };
    report_syscall(out, "pidfd_getfd_parent", getfd);
    if getfd >= 0 {
        unsafe { close(getfd as i32) };
    }
    let sent = unsafe { syscall(SYS_PIDFD_SEND_SIGNAL, pidfd, 0i32, 0i64, 0u32) };
    report_syscall(out, "pidfd_send_signal_parent", sent);
    if open >= 0 {
        unsafe { close(open as i32) };
    }
}

fn try_scm_recv(out: &mut impl Write) {
    let mut data = [0u8; 8];
    let mut iov = Iovec {
        iov_base: data.as_mut_ptr(),
        iov_len: data.len(),
    };
    let mut control = [0u8; 256];
    let mut msg = Msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: control.as_mut_ptr(),
        msg_controllen: control.len(),
        msg_flags: 0,
    };
    let n = unsafe { recvmsg(0, &mut msg, 0) };
    if n < 0 {
        let _ = writeln!(
            out,
            "scm_recv errno={}",
            io::Error::last_os_error().raw_os_error().unwrap_or(-1)
        );
        return;
    }
    if msg.msg_controllen < std::mem::size_of::<Cmsghdr>() {
        let _ = writeln!(out, "scm_recv empty");
        return;
    }
    let hdr = unsafe { &*control.as_ptr().cast::<Cmsghdr>() };
    if hdr.cmsg_level == SOL_SOCKET && hdr.cmsg_type == SCM_RIGHTS {
        let _ = writeln!(out, "scm_rights ok");
        return;
    }
    let _ = writeln!(out, "scm_recv other");
}
