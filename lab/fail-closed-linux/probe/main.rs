//! Stand-in provider for the real-kernel tests.
//!
//! usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR [--kill-host PID] [--exit CODE]
//!
//! It writes STORAGE_ROOT/probe-ran first, prints one line per check, prints
//! `nspid=` from `/proc/self/status`, prints `ready`, then waits until stdin
//! closes so the test can read the running process. `--kill-host` tries
//! `kill(PID, 0)` and a kill of its own child. `--exit` ends with that code
//! instead of waiting.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn fork() -> i32;
    fn pause() -> i32;
    fn getpid() -> i32;
    fn waitpid(pid: i32, wstatus: *mut i32, options: i32) -> i32;
    fn _exit(status: i32) -> !;
}

const SIGKILL: i32 = 9;

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
    let _ = writeln!(out, "nspid={}", nspid());
    if let Some(host_pid) = extra.kill_host {
        report_kill(&mut out, host_pid);
    }
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    drop(out);

    if let Some(code) = extra.exit_code {
        std::process::exit(code);
    }
    let mut rest = Vec::new();
    let _ = io::stdin().read_to_end(&mut rest);
}

struct Extra {
    kill_host: Option<i32>,
    exit_code: Option<i32>,
}

fn parse_extra(args: &[String]) -> Extra {
    let mut extra = Extra {
        kill_host: None,
        exit_code: None,
    };
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kill-host" => {
                extra.kill_host = Some(parse_i32(args.get(i + 1)));
                i += 2;
            }
            "--exit" => {
                extra.exit_code = Some(parse_i32(args.get(i + 1)));
                i += 2;
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
        "usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR [--kill-host PID] [--exit CODE]"
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

fn report(out: &mut impl Write, check: &str, result: io::Result<()>) {
    let _ = match result {
        Ok(()) => writeln!(out, "{check} ok"),
        Err(err) => writeln!(out, "{check} errno={}", err.raw_os_error().unwrap_or(-1)),
    };
}
