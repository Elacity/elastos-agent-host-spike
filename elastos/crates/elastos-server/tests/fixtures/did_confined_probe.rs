use std::io::{BufRead, Write};

const ROOT: &str = "@@ROOT@@";

fn main() {
    std::fs::write(format!("{ROOT}/child.pid"), std::process::id().to_string()).unwrap();
    let mut output = std::io::stdout();
    for line in std::io::stdin().lock().lines() {
        let line = line.unwrap();
        if line.contains("\"op\":\"init\"") {
            if !line.contains(&format!(
                "\"base_path\":\"{}\"",
                ROOT.trim_end_matches("/did")
            )) {
                writeln!(
                    output,
                    "{{\"status\":\"error\",\"code\":\"path\",\"message\":\"wrong base\"}}"
                )
                .unwrap();
            } else {
                writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            }
        } else if line.contains("\"op\":\"get_did\"") {
            writeln!(
                output,
                "{{\"status\":\"ok\",\"data\":{{\"did\":\"did:key:zFixture\"}}}}"
            )
            .unwrap();
        } else if line.contains("\"op\":\"set_nickname\"") {
            std::fs::write(format!("{ROOT}/nickname"), b"Ada").unwrap();
            writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
        } else if line.contains("\"op\":\"shutdown\"") {
            std::fs::write(format!("{ROOT}/shutdown"), b"yes").unwrap();
            writeln!(output, "{{\"status\":\"ok\"}}").unwrap();
            output.flush().unwrap();
            return;
        }
        output.flush().unwrap();
    }
}
