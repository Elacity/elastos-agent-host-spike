//! Protocol-speaking provider used by the slice 10 rows.
//!
//! The test substitutes `@@PID_FILE@@` (a path inside its storage root, or
//! empty) and `@@MODE@@` (`ok` or `reject_init`) before compiling this file.

use std::io::{BufRead, Write};

const PID_FILE: &str = "@@PID_FILE@@";
const MODE: &str = "@@MODE@@";

fn main() {
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
