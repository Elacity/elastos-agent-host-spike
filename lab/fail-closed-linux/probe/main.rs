//! Stand-in provider for the real-kernel tests.
//!
//! usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR
//!        [--tty-path PATH] [--inherited-fd N] [--kill-host PID] [--exit CODE]
//!        [--daemonize] [--orphan-exit]
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
    fn truncate(path: *const i8, length: i64) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn open(path: *const i8, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
}

const SIGKILL: i32 = 9;
const TIOCGWINSZ: u64 = 0x5413;
const O_RDONLY: i32 = 0;
const O_NOCTTY: i32 = 0o400;

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

    let marker = fs::write(storage.join("probe-ran"), provider);
    let mut out = io::stdout().lock();
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
    if let Some(fd) = extra.inherited_fd {
        report(&mut out, "inherit_ioctl", ioctl_on_fd(fd));
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
    inherited_fd: Option<i32>,
    kill_host: Option<i32>,
    exit_code: Option<i32>,
    daemonize: bool,
    orphan_exit: bool,
}

fn parse_extra(args: &[String]) -> Extra {
    let mut extra = Extra {
        tty_path: None,
        inherited_fd: None,
        kill_host: None,
        exit_code: None,
        daemonize: false,
        orphan_exit: false,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--tty-path" => {
                extra.tty_path = Some(args.get(i + 1).cloned().unwrap_or_else(|| usage()));
                i += 2;
            }
            "--inherited-fd" => {
                extra.inherited_fd = Some(parse_i32(args.get(i + 1)));
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
        "usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR [--tty-path PATH] [--inherited-fd N] [--kill-host PID] [--exit CODE] [--daemonize] [--orphan-exit]"
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
