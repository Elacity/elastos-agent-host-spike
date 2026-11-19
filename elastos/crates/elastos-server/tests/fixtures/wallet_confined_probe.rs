use std::io::{BufRead, Write};

const ROOT: &str = "@@ROOT@@";
const BASE: &str = "@@BASE@@";
const MARKER: &str = "@@MARKER@@";
const PROTOCOL: &str = "@@PROTOCOL@@";

/// Minimal wallet-provider stdio stand-in for the start-path rows. It writes the
/// marker outside STORAGE_ROOT: the sandbox refuses that write, so the file only
/// appears when a plain start runs this binary unbounded.
fn main() {
    let _ = std::fs::write(MARKER, b"started");
    let _ = std::fs::create_dir_all(ROOT);
    std::fs::write(format!("{ROOT}/child.pid"), std::process::id().to_string()).unwrap();
    let mut output = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.contains("\"op\":\"init\"") {
            if !line.contains(&format!("\"base_path\":\"{}\"", BASE)) {
                writeln!(
                    output,
                    "{{\"status\":\"error\",\"message\":\"wrong base\"}}"
                )
                .unwrap();
            } else {
                writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            }
        } else if line.contains("\"op\":\"status\"") {
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"provider\":\"wallet-provider\",\"protocol_version\":\"{}\"}}}}",
                PROTOCOL
            )
            .unwrap();
        } else if line.contains("\"op\":\"create_wallet\"") {
            std::fs::write(format!("{ROOT}/wallet-state.json"), b"{\"accounts\":[\"a1\"]}").unwrap();
            writeln!(output, "{{\"status\":\"ok\",\"data\":{{\"created\":\"a1\"}}}}").unwrap();
        } else if line.contains("\"op\":\"list_wallets\"") {
            let state = std::fs::read_to_string(format!("{ROOT}/wallet-state.json"))
                .unwrap_or_default();
            let accounts = if state.contains("a1") { 1 } else { 0 };
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"accounts\":{accounts}}}}}"
            )
            .unwrap();
        } else if line.contains("\"op\":\"probe_outside_write\"") {
            let refused = std::fs::write(format!("{BASE}/outside"), b"outside").is_err();
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"outside_write_refused\":{refused}}}}}"
            )
            .unwrap();
        } else if line.contains("\"op\":\"shutdown\"") {
            std::fs::write(format!("{ROOT}/shutdown"), b"yes").unwrap();
            writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            output.flush().unwrap();
            return;
        }
        output.flush().unwrap();
    }
}
