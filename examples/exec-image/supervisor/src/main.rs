//! The exec image supervisor. Init runs it as root, once per boot.
//!
//! `run` holds the exit port, runs one command as an unprivileged user, and
//! reports the command's exit code on the exit port. The command can write
//! the console; it can never reach the exit port:
//!
//! 1. Bind vsock port 1022 (below 1024: only `CAP_NET_BIND_SERVICE` may bind
//!    it). Nothing else can bind it while this process holds it. A second
//!    bind is checked to fail with `EADDRINUSE`.
//! 2. Fork the command. In the child: stdout and stderr to the console (opened
//!    here, before privileges drop), no supplementary groups, uid and gid
//!    65534, `no_new_privs`, every capability dropped including the bounding
//!    and ambient sets. Each step is checked; any miss stops the child.
//! 3. Wait for the command. A command killed by a signal reports 128 + the
//!    signal number. Then kill every process left running as 65534.
//! 4. Only now listen on the port, accept the host's connection (peer CID 2),
//!    write `<code>\n`, and wait for the host to close.
//!
//! No line is ever written to the console that the host reads as a result.
//!
//! `probe` holds the in-image falsifiers. They run as the command, so they
//! run unprivileged: `probe bind` must get `EACCES` on the exit port, and
//! `probe report` tries to write a forged report and leaves a process behind
//! that keeps trying.

use std::ffi::CString;
use std::io::Error;
use std::time::{Duration, Instant};

const EXIT_PORT: u32 = 1022;
const NOBODY: u32 = 65534;
const VMADDR_CID_HOST: u32 = 2;
const VMADDR_CID_LOCAL: u32 = 1;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("run") => run(&args[1..]),
        Some("probe") => probe(&args[1..]),
        _ => {
            eprintln!("usage: exec-supervisor run [--port N] [--console PATH] [--host-cid N] -- PROGRAM [ARGS...]");
            eprintln!("       exec-supervisor probe bind|report [--port N]");
            2
        }
    };
    std::process::exit(code);
}

/// Options for `run`. `report_unix` is for host tests only: the report is
/// served on a Unix socket open to everyone (like vsock, which has no file
/// permissions) instead of listening on the vsock port.
struct RunOptions {
    port: u32,
    console: String,
    host_cid: u32,
    report_unix: Option<String>,
    program: Vec<String>,
}

fn parse_run(args: &[String]) -> Result<RunOptions, String> {
    let mut options = RunOptions {
        port: EXIT_PORT,
        console: "/dev/hvc0".to_string(),
        host_cid: VMADDR_CID_HOST,
        report_unix: None,
        program: Vec::new(),
    };
    let mut index = 0;
    while index < args.len() {
        let value = || args.get(index + 1).cloned().ok_or("missing value");
        match args[index].as_str() {
            "--port" => options.port = value()?.parse().map_err(|_| "bad port")?,
            "--console" => options.console = value()?,
            "--host-cid" => options.host_cid = value()?.parse().map_err(|_| "bad cid")?,
            "--report-unix" => options.report_unix = Some(value()?),
            "--" => {
                options.program = args[index + 1..].to_vec();
                break;
            }
            other => return Err(format!("unknown option {other}")),
        }
        index += 2;
    }
    if options.program.is_empty() {
        return Err("no program".to_string());
    }
    Ok(options)
}

/// A line on the console, for people. The host never reads a result from it.
fn say(fd: i32, line: &str) {
    let text = format!("exec-supervisor: {line}\n");
    unsafe {
        libc::write(fd, text.as_ptr().cast(), text.len());
    }
}

fn run(args: &[String]) -> i32 {
    let options = match parse_run(args) {
        Ok(options) => options,
        Err(err) => {
            eprintln!("exec-supervisor: {err}");
            return 2;
        }
    };
    let console = match open_fd(&options.console, libc::O_WRONLY | libc::O_APPEND) {
        Ok(fd) => fd,
        Err(err) => {
            eprintln!(
                "exec-supervisor: cannot open the console {}: {err}",
                options.console
            );
            return 1;
        }
    };

    // Orphans of the command come back here, so they can be reaped.
    unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };

    // 1. Hold the exit port before anything else runs.
    let port = match vsock_socket().and_then(|fd| vsock_bind(fd, options.port).map(|()| fd)) {
        Ok(fd) => fd,
        Err(err) => {
            say(
                console,
                &format!("cannot hold exit port {}: {err}", options.port),
            );
            return 1;
        }
    };
    match vsock_socket().map(|fd| (fd, vsock_bind(fd, options.port))) {
        Ok((fd, Err(err))) if err.raw_os_error() == Some(libc::EADDRINUSE) => {
            unsafe { libc::close(fd) };
            say(
                console,
                &format!(
                    "exit port {} held (a second bind gets EADDRINUSE)",
                    options.port
                ),
            );
        }
        _ => {
            say(
                console,
                &format!("exit port {} is not held; refusing to run", options.port),
            );
            return 1;
        }
    }

    // 2. Run the command unprivileged.
    let devnull = match open_fd("/dev/null", libc::O_RDONLY) {
        Ok(fd) => fd,
        Err(err) => {
            say(console, &format!("cannot open /dev/null: {err}"));
            return 1;
        }
    };
    let program: Vec<CString> = match options
        .program
        .iter()
        .map(|arg| CString::new(arg.as_bytes()))
        .collect()
    {
        Ok(program) => program,
        Err(_) => {
            say(console, "a program argument has a NUL byte");
            return 1;
        }
    };
    let last_cap = last_capability();
    let child = unsafe { libc::fork() };
    if child < 0 {
        say(console, &format!("fork failed: {}", Error::last_os_error()));
        return 1;
    }
    if child == 0 {
        exec_unprivileged(&program, console, devnull, last_cap);
    }
    unsafe { libc::close(devnull) };

    // 3. Wait for it, then leave nothing of it running.
    let code = match wait_for(child) {
        Ok(code) => code,
        Err(err) => {
            say(console, &format!("wait failed: {err}"));
            return 1;
        }
    };
    say(
        console,
        "command finished; its code goes to the exit port only",
    );
    kill_everything_unprivileged(console);

    // 4. Only now accept a report connection.
    let served = match options.report_unix.as_deref() {
        Some(path) => serve_unix(path, code),
        None => serve_vsock(port, options.host_cid, code, console),
    };
    match served {
        Ok(()) => 0,
        Err(err) => {
            say(console, &format!("report failed: {err}"));
            1
        }
    }
}

fn open_fd(path: &str, flags: i32) -> Result<i32, Error> {
    let path = CString::new(path).map_err(|_| Error::from_raw_os_error(libc::EINVAL))?;
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn vsock_socket() -> Result<i32, Error> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(fd)
    }
}

fn vsock_address(cid: u32, port: u32) -> libc::sockaddr_vm {
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = cid;
    address.svm_port = port;
    address
}

fn vsock_bind(fd: i32, port: u32) -> Result<(), Error> {
    let address = vsock_address(libc::VMADDR_CID_ANY, port);
    let done = unsafe {
        libc::bind(
            fd,
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if done < 0 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

fn vsock_connect(cid: u32, port: u32) -> Result<i32, Error> {
    let fd = vsock_socket()?;
    let address = vsock_address(cid, port);
    let done = unsafe {
        libc::connect(
            fd,
            std::ptr::addr_of!(address).cast(),
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if done < 0 {
        let err = Error::last_os_error();
        unsafe { libc::close(fd) };
        Err(err)
    } else {
        Ok(fd)
    }
}

fn last_capability() -> u32 {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(63)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// The child: drop to 65534 with no capabilities and run the program. Any
/// step that fails, or any check that does not hold, stops the child with
/// 126 before the program runs. Never returns.
fn exec_unprivileged(program: &[CString], console: i32, devnull: i32, last_cap: u32) -> ! {
    let stop = |what: &str| -> ! {
        let text = format!(
            "exec-supervisor: cannot drop privileges ({what}): {}\n",
            Error::last_os_error()
        );
        unsafe {
            libc::write(console, text.as_ptr().cast(), text.len());
            libc::_exit(126)
        }
    };
    unsafe {
        if libc::setsid() < 0 {
            stop("setsid");
        }
        if libc::dup2(devnull, 0) < 0 || libc::dup2(console, 1) < 0 || libc::dup2(console, 2) < 0 {
            stop("dup2");
        }
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) < 0
        {
            stop("clear ambient");
        }
        for cap in 0..=last_cap {
            if libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0) < 0 {
                stop("bounding set");
            }
        }
        if libc::setgroups(0, std::ptr::null()) < 0 {
            stop("setgroups");
        }
        if libc::setresgid(NOBODY, NOBODY, NOBODY) < 0 {
            stop("setresgid");
        }
        if libc::setresuid(NOBODY, NOBODY, NOBODY) < 0 {
            stop("setresuid");
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 {
            stop("no_new_privs");
        }
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capset, &mut header, data.as_mut_ptr()) < 0 {
            stop("capset");
        }
        // Check, do not assume.
        let mut uid = (0, 0, 0);
        let mut gid = (0, 0, 0);
        libc::getresuid(&mut uid.0, &mut uid.1, &mut uid.2);
        libc::getresgid(&mut gid.0, &mut gid.1, &mut gid.2);
        if uid != (NOBODY, NOBODY, NOBODY) || gid != (NOBODY, NOBODY, NOBODY) {
            stop("ids");
        }
        if libc::getgroups(0, std::ptr::null_mut()) != 0 {
            stop("groups");
        }
        if libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 {
            stop("no_new_privs check");
        }
        let mut header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData::default(); 2];
        if libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) < 0
            || data
                .iter()
                .any(|set| set.effective != 0 || set.permitted != 0 || set.inheritable != 0)
        {
            stop("capability check");
        }
        for cap in 0..=last_cap {
            if libc::prctl(libc::PR_CAPBSET_READ, cap as libc::c_ulong, 0, 0, 0) != 0
                || libc::prctl(
                    libc::PR_CAP_AMBIENT,
                    libc::PR_CAP_AMBIENT_IS_SET,
                    cap as libc::c_ulong,
                    0,
                    0,
                ) != 0
            {
                stop("bounding or ambient check");
            }
        }
        if libc::chdir(c"/".as_ptr()) < 0 {
            stop("chdir");
        }
        let mut argv: Vec<*const libc::c_char> = program.iter().map(|arg| arg.as_ptr()).collect();
        argv.push(std::ptr::null());
        libc::execv(program[0].as_ptr(), argv.as_ptr());
        let text = format!(
            "exec-supervisor: cannot run {:?}: {}\n",
            program[0],
            Error::last_os_error()
        );
        libc::write(console, text.as_ptr().cast(), text.len());
        libc::_exit(127)
    }
}

/// The command's code: its exit status, or 128 + the signal that killed it.
fn wait_for(child: i32) -> Result<i32, Error> {
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(child, &mut status, 0) } >= 0 {
            break;
        }
        let err = Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Ok(128 + libc::WTERMSIG(status))
    } else {
        Ok(255)
    }
}

/// Kill every process still running as 65534, from a helper that is itself
/// 65534: `kill(-1)` then reaches exactly the processes it may signal, never
/// root's. Orphans of the command come back to this process (it is a child
/// subreaper), so they are reaped here. Then `/proc` is checked: no live
/// process of 65534 may be left.
fn kill_everything_unprivileged(console: i32) {
    for _ in 0..5 {
        let helper = unsafe { libc::fork() };
        if helper == 0 {
            unsafe {
                if libc::setresgid(NOBODY, NOBODY, NOBODY) < 0
                    || libc::setresuid(NOBODY, NOBODY, NOBODY) < 0
                {
                    libc::_exit(1);
                }
                for _ in 0..20 {
                    libc::kill(-1, libc::SIGKILL);
                    libc::usleep(5_000);
                }
                libc::_exit(0);
            }
        }
        if helper > 0 {
            let _ = wait_for(helper);
        }
        // Reap orphans that came back to this subreaper.
        let mut status = 0;
        while unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) } > 0 {}
        if live_unprivileged_processes() == 0 {
            return;
        }
    }
    say(console, "a process of the command is still running");
}

/// Processes running as 65534 that are not zombies.
fn live_unprivileged_processes() -> usize {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return usize::MAX;
    };
    entries
        .flatten()
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .bytes()
                .all(|byte| byte.is_ascii_digit())
        })
        .filter_map(|entry| std::fs::read_to_string(entry.path().join("status")).ok())
        .filter(|status| {
            let field = |name: &str| {
                status
                    .lines()
                    .find_map(|line| line.strip_prefix(name))
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_string()
            };
            field("Uid:").split_whitespace().next() == Some("65534")
                && !field("State:").starts_with('Z')
        })
        .count()
}

fn serve_vsock(port: i32, host_cid: u32, code: i32, console: i32) -> Result<(), Error> {
    if unsafe { libc::listen(port, 1) } < 0 {
        return Err(Error::last_os_error());
    }
    loop {
        let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
        let fd = unsafe {
            libc::accept4(
                port,
                std::ptr::addr_of_mut!(peer).cast(),
                &mut length,
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let err = Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err);
        }
        if peer.svm_cid != host_cid {
            say(
                console,
                &format!("refused a report connection from cid {}", peer.svm_cid),
            );
            unsafe { libc::close(fd) };
            continue;
        }
        return report(fd, code);
    }
}

fn serve_unix(path: &str, code: i32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::IntoRawFd;
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    let (stream, _) = listener.accept()?;
    report(stream.into_raw_fd(), code)
}

/// Write `<code>\n`, then wait (up to 10 s) for the host to close, so the
/// bytes are delivered before the machine stops.
fn report(fd: i32, code: i32) -> Result<(), Error> {
    let text = format!("{code}\n");
    let written = unsafe { libc::write(fd, text.as_ptr().cast(), text.len()) };
    if written != text.len() as isize {
        unsafe { libc::close(fd) };
        return Err(Error::last_os_error());
    }
    unsafe { libc::shutdown(fd, libc::SHUT_WR) };
    let deadline = Instant::now() + Duration::from_secs(10);
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(timeout).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    let mut buffer = [0_u8; 64];
    while Instant::now() < deadline {
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if read == 0 {
            break;
        }
    }
    unsafe { libc::close(fd) };
    Ok(())
}

/// In-image falsifiers. They run as the command, so unprivileged.
fn probe(args: &[String]) -> i32 {
    let port = args
        .iter()
        .position(|arg| arg == "--port")
        .and_then(|at| args.get(at + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(EXIT_PORT);
    let report_unix = args
        .iter()
        .position(|arg| arg == "--report-unix")
        .and_then(|at| args.get(at + 1))
        .cloned();
    match args.first().map(String::as_str) {
        Some("bind") => probe_bind(port),
        Some("report") => probe_report(port, report_unix.as_deref()),
        _ => 2,
    }
}

/// Exit 0 only when binding the exit port is refused with EACCES.
fn probe_bind(port: u32) -> i32 {
    let outcome = vsock_socket().and_then(|fd| vsock_bind(fd, port));
    match outcome {
        Err(err) if err.raw_os_error() == Some(libc::EACCES) => {
            println!("probe-bind: port {port}: EACCES");
            0
        }
        Err(err) => {
            println!("probe-bind: port {port}: {err}");
            1
        }
        Ok(()) => {
            println!("probe-bind: port {port}: BOUND");
            1
        }
    }
}

/// Try to deliver a forged `0\n` on the report channel, now and from a
/// process left behind for 10 s; then exit 3. The host must see 3.
fn probe_report(port: u32, report_unix: Option<&str>) -> i32 {
    let attempt = |label: &str| {
        for cid in [VMADDR_CID_LOCAL, VMADDR_CID_HOST, libc::VMADDR_CID_ANY] {
            if let Ok(fd) = vsock_connect(cid, port) {
                unsafe { libc::write(fd, b"0\n".as_ptr().cast(), 2) };
                println!("probe-report: {label}: wrote a forged report to cid {cid}");
                unsafe { libc::close(fd) };
            }
        }
        if let Some(path) = report_unix {
            if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(path) {
                use std::io::Write;
                let _ = stream.write_all(b"0\n");
                println!("probe-report: {label}: wrote a forged report to {path}");
            }
        }
    };
    attempt("now");
    let behind = unsafe { libc::fork() };
    if behind == 0 {
        unsafe { libc::setsid() };
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            attempt("left behind");
            std::thread::sleep(Duration::from_millis(50));
        }
        unsafe { libc::_exit(0) };
    }
    println!("probe-report: leaving a process behind and exiting 3");
    3
}
