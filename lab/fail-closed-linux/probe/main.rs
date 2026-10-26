//! Stand-in provider for the real-kernel tests.
//!
//! usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR
//!
//! It writes STORAGE_ROOT/probe-ran first, prints one line per check, prints
//! `ready`, then waits until stdin closes so the test can read its
//! /proc/<pid>/status while it still runs.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: fcl-probe PROVIDER STORAGE_ROOT OUTSIDE_FILE OUTSIDE_DIR");
        std::process::exit(2);
    }
    let provider = &args[1];
    let storage = Path::new(&args[2]);
    let outside_file = Path::new(&args[3]);
    let outside_dir = Path::new(&args[4]);

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
    let _ = writeln!(out, "ready");
    let _ = out.flush();
    drop(out);

    let mut rest = Vec::new();
    let _ = io::stdin().read_to_end(&mut rest);
}

fn report(out: &mut impl Write, check: &str, result: io::Result<()>) {
    let _ = match result {
        Ok(()) => writeln!(out, "{check} ok"),
        Err(err) => writeln!(out, "{check} errno={}", err.raw_os_error().unwrap_or(-1)),
    };
}
