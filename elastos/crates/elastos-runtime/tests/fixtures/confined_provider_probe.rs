//! Protocol-speaking provider used by the slice 10 rows.
//!
//! The test substitutes `@@PID_FILE@@` (a path inside its storage root, or
//! empty), `@@MODE@@` (`ok` or `reject_init`), and `@@STDERR_REPORT@@` (a path
//! inside the storage root, or empty) before compiling this file.

use std::io::{BufRead, Read, Write};

const PID_FILE: &str = "@@PID_FILE@@";
const MODE: &str = "@@MODE@@";
const STDERR_REPORT: &str = "@@STDERR_REPORT@@";

fn main() {
    if !STDERR_REPORT.is_empty() {
        use std::os::fd::FromRawFd;
        let mut stderr = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(2) });
        let mut buf = [0u8; 64];
        let n = Read::read(&mut *stderr, &mut buf).unwrap_or(0);
        let _ = Write::write_all(&mut *stderr, b"PROBE-STDERR");
        let mut record = n.to_string().into_bytes();
        record.push(b'\n');
        record.extend_from_slice(&buf[..n]);
        let _ = std::fs::write(STDERR_REPORT, record);
    }
    if !PID_FILE.is_empty() {
        let _ = std::fs::write(PID_FILE, std::process::id().to_string());
    }
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut lines = stdin.lock().lines();
    while let Some(Ok(line)) = lines.next() {
        if line.contains("\"op\":\"init\"") {
            if MODE == "reject_init" {
                writeln!(
                    out,
                    "{{\"status\":\"error\",\"code\":\"invalid\",\"message\":\"refused\"}}"
                )
                .unwrap();
                out.flush().unwrap();
            } else {
                writeln!(out, "{{\"status\":\"ok\"}}").unwrap();
                out.flush().unwrap();
            }
        } else if line.contains("\"op\":\"shutdown\"") {
            writeln!(out, "{{\"status\":\"ok\"}}").unwrap();
            out.flush().unwrap();
            return;
        }
    }
}
