use std::{env, fs, process};

fn main() {
    let args: Vec<_> = env::args_os().collect();
    let report = (|| {
        if args.len() != 4 {
            return None;
        }
        let listed = fs::read_to_string(&args[1]).ok()?;
        let output = fs::read_to_string(&args[2]).ok()?;
        Some(agent_conformance::report::table(
            &listed,
            &output,
            args[3] == "0",
        ))
    })();
    let (text, passed) = report.unwrap_or_else(|| {
        (
            "test | PASS/FAIL/BLOCKED (id)\ncargo | FAIL\n".into(),
            false,
        )
    });
    print!("{text}");
    if !passed {
        process::exit(1);
    }
}
